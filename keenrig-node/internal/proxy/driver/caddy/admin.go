package caddy

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

// Client mỏng cho admin API của Caddy.
//
// Tách khỏi Driver để test trỏ được vào httptest thay vì phải có Caddy thật.
// Nói thẳng phạm vi: test như vậy kiểm HỢP ĐỒNG request/response giữa ta và
// admin API (đường dẫn, method, hình dạng JSON), KHÔNG kiểm rằng Caddy hiểu
// config ta gửi. Phần sau chỉ e2e với Caddy thật mới trả lời được (T12).
type adminClient struct {
	base string
	http *http.Client
}

// adminTimeout — admin API là lời gọi cục bộ; quá 10 giây nghĩa là Caddy treo,
// và treo thì phải trả lỗi để reconciler backoff, không phải chờ mãi.
const adminTimeout = 10 * time.Second

// adminHost — Host gửi qua unix socket; khớp `admin.origins` của caddy-bootstrap.sh.
const adminHost = "localhost"

// newAdminClient dựng client theo scheme của endpoint.
//
// unix socket cần transport riêng: net/http không tự hiểu "unix/<path>", nên ta
// giữ nguyên hình dạng URL của Caddy ở tầng cấu hình rồi dịch sang DialContext
// ở đây. Nhờ vậy người vận hành viết đúng cú pháp trong tài liệu Caddy.
func newAdminClient(addr string) *adminClient {
	if path, ok := strings.CutPrefix(addr, schemeUnix); ok {
		return &adminClient{
			// Host giả: unix socket không có host, nhưng net/http vẫn cần một URL
			// hợp lệ để dựng request.
			//
			// PHẢI là `localhost`, không phải một tên tuỳ ý: Caddy kiểm Host của
			// MỌI request admin với `admin.origins`, và caddy-bootstrap.sh ghi
			// `"origins": ["localhost"]`. Tên cũ `caddy-admin` nhận 403 "host not
			// allowed" ở từng lần Apply — đo được trên VPS thật 2026-10-02: Caddy
			// chạy, :443 mở, mà không route nào được đẩy vào.
			base: "http://" + adminHost,
			http: &http.Client{
				Timeout: adminTimeout,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "unix", path)
					},
				},
			},
		}
	}
	return &adminClient{base: strings.TrimSuffix(addr, "/"), http: &http.Client{Timeout: adminTimeout}}
}

// do gọi admin API và trả body. Status ≥ 400 → lỗi kèm nguyên văn body: Caddy
// mô tả rất cụ thể chỗ config sai, nuốt đi là vứt bỏ manh mối duy nhất.
func (c *adminClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("caddy: %s %s → %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (c *adminClient) getJSON(ctx context.Context, path string, out any) error {
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil // chưa có gì ở nhánh này — out giữ zero value
	}
	return json.Unmarshal(raw, out)
}
