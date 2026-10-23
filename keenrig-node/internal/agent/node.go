package agent

// node.go — phía agent của node API (`contracts/openapi/node.yaml`).
//
// Agent nói chuyện với box QUA ĐÂY và chỉ qua đây: nó không mở platform.db
// (Luật 5, ND-05) và không đọc file trong node/logs/ (Luật 6).
//
// Transport là chi tiết bị giấu sau client này: nấc 0 là unix socket, nấc cao
// hơn là TCP + mTLS khác host. Chỗ gọi chỉ thấy một địa chỉ chuỗi, nên đổi nấc
// không phải sửa executor.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// NodeClient gọi node API của box trên cùng máy.
type NodeClient struct {
	base string
	http *http.Client
}

// NewNodeClient dựng client theo địa chỉ box đang nghe.
//
// addr nhận ba dạng, theo đúng thứ tự Listen có thể trả về:
//
//	/var/lib/keenrig/node/run/box.sock  unix socket (nấc 0, mặc định)
//	127.0.0.1:39217                     TCP loopback (đường dev-only trên Windows)
//	http://host:port                    URL đầy đủ
//
// Đoán theo hình dạng chuỗi thay vì bắt chỗ gọi khai thêm một cờ "kiểu": chỗ
// gọi chỉ có một thứ trong tay — cái mà `nodeapi.Listener.Addr` in ra.
func NewNodeClient(addr string, timeout time.Duration) *NodeClient {
	if timeout <= 0 {
		// 10 giây: box cùng máy: chậm hơn thế là box đang có vấn đề, và giữ
		// agent lại lâu hơn chỉ làm nó trễ nhịp sync kế.
		timeout = 10 * time.Second
	}
	c := &NodeClient{http: &http.Client{Timeout: timeout}}
	switch {
	case strings.HasPrefix(addr, "http://"), strings.HasPrefix(addr, "https://"):
		c.base = strings.TrimSuffix(addr, "/")
	case strings.Contains(addr, "/") || strings.Contains(addr, `\`):
		// Unix socket: host trong URL không có nghĩa gì, nhưng http.Client vẫn
		// đòi một cái để dựng Host header. "box" là một tên chết, cố ý.
		sock := addr
		c.base = "http://box"
		c.http.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}
	default:
		c.base = "http://" + addr
	}
	return c
}

// AppStatuses trả NGUYÊN VĂN phản hồi `/node/v1/apps` (ND-01).
func (c *NodeClient) AppStatuses(ctx context.Context) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/node/v1/apps", nil)
	if err != nil {
		return nil, err
	}
	res, raw, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: the box returned %d for the app list: %s", res.StatusCode, snippet(raw))
	}
	return json.RawMessage(raw), nil
}

// InstallLicense giao NGUYÊN VĂN phong bì license cho box (`PUT /node/v1/license`).
//
// Agent không mở phong bì: box verify chữ ký trước khi ghi, và lý do từ chối
// của box đi nguyên văn vào lỗi trả về — đó là dòng log duy nhất người vận hành
// có khi license không vào.
func (c *NodeClient) InstallLicense(ctx context.Context, raw []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.base+"/node/v1/license", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, out, err := c.do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("agent: the box refused the license (%d): %s",
			res.StatusCode, snippet(out))
	}
	return nil
}

// SetParentDomain giao tên miền gốc cloud đã chọn cho box (`PUT /node/v1/parent-domain`).
//
// Agent là người đưa thư, không phải người quyết định: giá trị đi nguyên văn từ
// phản hồi sync, box chuẩn hoá và từ chối nếu hỏng. Lý do từ chối đi nguyên văn
// vào lỗi trả về — đó là dòng log duy nhất người vận hành có khi tên miền không
// vào.
func (c *NodeClient) SetParentDomain(ctx context.Context, parent, mode string) error {
	raw, err := json.Marshal(map[string]string{"parent_domain": parent, "mode": mode})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.base+"/node/v1/parent-domain", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, out, err := c.do(req)
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("agent: the box refused the parent domain (%d): %s",
			res.StatusCode, snippet(out))
	}
	return nil
}

// SetCloudLink báo trạng thái pair cho box (`PUT /node/v1/cloud-link`).
//
// Ba trường đúng tên hợp đồng node.yaml; mốc đi RFC3339 UTC. Lý do từ chối
// của box đi nguyên văn vào lỗi trả về — dòng log duy nhất người vận hành có
// khi Admin UI vẫn nói "chưa pair" trên một máy đang sync.
func (c *NodeClient) SetCloudLink(ctx context.Context, cloudURL, envID string, lastSync time.Time) error {
	raw, err := json.Marshal(map[string]string{
		"cloud_url":    cloudURL,
		"env_id":       envID,
		"last_sync_at": lastSync.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.base+"/node/v1/cloud-link", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, out, err := c.do(req)
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("agent: the box refused the cloud link state (%d): %s",
			res.StatusCode, snippet(out))
	}
	return nil
}

// AcceptAdminTicket giao HASH của một vé "Mở Admin ↗" cho box (CON-13).
//
// KHÔNG có vé trần ở đây: agent không bao giờ thấy nó. Thứ đi qua đường này là
// hash cloud đã đặt trong payload lệnh, cộng hạn của chính lệnh đó.
func (c *NodeClient) AcceptAdminTicket(ctx context.Context, hash string, expiresAt time.Time) error {
	body := map[string]string{"token_hash": hash}
	if !expiresAt.IsZero() {
		body["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/node/v1/admin-tickets", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, out, err := c.do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusOK {
		// Lý do NGUYÊN VĂN của box: nó đi tiếp lên Console qua kết quả lệnh
		// (CON-14). "501 login is not enabled" và "400 hash sai" là hai việc
		// phải sửa khác nhau, và người dùng chỉ thấy được câu ta chuyển tiếp.
		return fmt.Errorf("agent: the box refused the admin ticket (%d): %s",
			res.StatusCode, snippet(out))
	}
	return nil
}

// InstallApp giao lệnh "cài app từ catalog" cho box (`POST /node/v1/apps/install`).
//
// 200 (app cùng slug đã có — lệnh giao lại) và 201 (vừa tạo) đều là thành
// công. Lý do từ chối của box (quota, license, domain trùng) đi NGUYÊN VĂN vào
// lỗi: nó là dòng chữ duy nhất người dùng đọc được trên Console (CON-14).
func (c *NodeClient) InstallApp(ctx context.Context, catalogID, slug string, domains []string) error {
	raw, err := json.Marshal(map[string]any{
		"catalog_id": catalogID, "slug": slug, "domains": domains,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/node/v1/apps/install", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, out, err := c.do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return fmt.Errorf("agent: the box refused to install %s (%d): %s",
			catalogID, res.StatusCode, snippet(out))
	}
	return nil
}

func (c *NodeClient) do(req *http.Request) (*http.Response, []byte, error) {
	res, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: could not reach the box node API: %w", err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, nil, err
	}
	return res, out, nil
}
