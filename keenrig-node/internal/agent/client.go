package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Client — phía instance của `/agent/v1`.
//
// # Nó KHÔNG mở platform.db, và đó là ràng buộc kiến trúc chứ không phải phong cách
//
// SQLite không chịu được nhiều tiến trình cùng ghi (Luật 5, ND-05). Agent lấy
// mọi dữ liệu qua node API của box và đẩy lên cloud; nó không biết file DB nằm
// ở đâu. Có một test chạy binary thật rồi nhìn đĩa để canh điều này.

var (
	// ErrRateLimited — cloud trả 429. Kèm Retry-After ở Outcome.
	ErrRateLimited = errors.New("agent: rate limited by the control plane")
	// ErrUnauthorized — khoá sai hoặc đã bị thu hồi.
	//
	// Tách riêng vì nó là lỗi KHÔNG tự khỏi: thử lại mãi cũng vô ích, và agent
	// phải nói ra thay vì lặng lẽ backoff tới 5 phút rồi lặp lại vĩnh viễn.
	ErrUnauthorized = errors.New("agent: the instance token was rejected")
	// ErrNoLicenseSigner — cloud này không phát license (503 từ
	// `/agent/v1/license`, bản self-hosted). KHÔNG phải lỗi vận hành: agent giữ
	// nguyên hiện trạng và không log gì — đây là trạng thái thiết kế.
	ErrNoLicenseSigner = errors.New("agent: this control plane does not issue licenses")
)

// Client gọi lên control plane.
type Client struct {
	base   string
	apiKey string
	http   *http.Client
}

// NewClient dựng client. base là URL gốc của cloud, ví dụ https://api.keenrig.com.
func NewClient(base, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		// 30 giây: đủ cho một đường truyền tệ, đủ ngắn để một cloud treo không
		// giữ agent lại quá một chu kỳ poll.
		timeout = 30 * time.Second
	}
	return &Client{
		base:   base,
		apiKey: apiKey,
		http:   &http.Client{Timeout: timeout},
	}
}

// PairResult — thứ nhận được sau khi đổi join token.
type PairResult struct {
	EnvID      string `json:"env_id"`
	APIKey     string `json:"api_key"`
	NextPollMS int    `json:"next_poll_ms"`
}

// Pair đổi join token lấy khoá API.
func (c *Client) Pair(ctx context.Context, token, hostID, version string) (*PairResult, error) {
	body := map[string]string{"token": token, "host_id": hostID, "version": version}
	res, raw, err := c.post(ctx, "/agent/v1/pair", body, false)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: pairing failed with %d: %s", res.StatusCode, snippet(raw))
	}
	var out PairResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("agent: pairing response is not valid JSON: %w", err)
	}
	if out.APIKey == "" || out.EnvID == "" {
		return nil, errors.New("agent: pairing response is missing the key or the environment id")
	}
	return &out, nil
}

// SyncRequest — khớp `sync.schema.json#/$defs/SyncRequest`.
type SyncRequest struct {
	EnvID          string          `json:"env_id"`
	HostRole       string          `json:"host_role,omitempty"`
	Version        string          `json:"version"`
	Heartbeat      Heartbeat       `json:"heartbeat"`
	AppStatuses    json.RawMessage `json:"app_statuses,omitempty"`
	MetricsSummary json.RawMessage `json:"metrics_summary,omitempty"`
	CommandResults []CommandResult `json:"command_results,omitempty"`
}

type Heartbeat struct {
	TS      string `json:"ts"`
	UptimeS int    `json:"uptime_s,omitempty"`
}

// CommandResult — kết quả một lệnh, báo lên ở lần sync SAU.
type CommandResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Command — lệnh nhận từ cloud.
type Command struct {
	ID             string          `json:"id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	ExpiresAt      string          `json:"expires_at,omitempty"`
}

// SyncResponse — khớp `sync.schema.json#/$defs/SyncResponse`.
type SyncResponse struct {
	Commands   []Command `json:"commands"`
	NextPollMS int       `json:"next_poll_ms,omitempty"`
	// ParentDomain/DomainMode — tên miền gốc cloud đã chọn cho môi trường này.
	// Rỗng = cloud chưa chọn; agent KHÔNG suy ra "hãy xoá" từ đó.
	ParentDomain string `json:"parent_domain,omitempty"`
	DomainMode   string `json:"domain_mode,omitempty"`
}

// Sync gửi trạng thái và nhận lệnh.
//
// Trả về Outcome KÈM lỗi: chính sách poll cần biết 429 khác lỗi mạng khác thành
// công, và gộp cả ba vào một `error` sẽ buộc chỗ gọi đi dò chuỗi.
func (c *Client) Sync(ctx context.Context, req SyncRequest) (*SyncResponse, Outcome) {
	res, raw, err := c.post(ctx, "/agent/v1/sync", req, true)
	if err != nil {
		return nil, Outcome{Err: err}
	}

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		// Retry-After là con số agent PHẢI tôn trọng (AG-04). Thiếu header thì
		// rơi về backoff thường chứ không đoán một con số.
		return nil, Outcome{Err: ErrRateLimited, RetryAfter: retryAfter(res)}
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, Outcome{Err: fmt.Errorf("%w (%d): %s", ErrUnauthorized, res.StatusCode, snippet(raw))}
	default:
		return nil, Outcome{Err: fmt.Errorf("agent: sync failed with %d: %s", res.StatusCode, snippet(raw))}
	}

	var out SyncResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, Outcome{Err: fmt.Errorf("agent: sync response is not valid JSON: %w", err)}
	}
	return &out, Outcome{OK: true, NextPollMS: out.NextPollMS}
}

// retryAfter đọc header Retry-After.
//
// Chỉ nhận dạng SỐ GIÂY. Chuẩn cho phép cả dạng ngày HTTP, nhưng dạng đó cần
// đồng hồ hai bên khớp nhau — mà đồng hồ lệch chính là thứ hay xảy ra trên máy
// tự lưu trữ. Không đọc được thì trả 0 và để backoff thường lo.
// License kéo license MỚI NHẤT của instance từ cloud (`GET /agent/v1/license`).
//
// Trả về NGUYÊN VĂN các byte của phản hồi — không parse: chữ ký Ed25519 ký trên
// byte và bên duy nhất được mở phong bì là verifier của box. Agent chỉ là người
// đưa thư.
func (c *Client) License(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/v1/license", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		return raw, nil
	case http.StatusServiceUnavailable:
		return nil, ErrNoLicenseSigner
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrUnauthorized
	case http.StatusTooManyRequests:
		return nil, ErrRateLimited
	default:
		return nil, fmt.Errorf("agent: the license endpoint returned %d: %s",
			res.StatusCode, snippet(raw))
	}
}

func retryAfter(res *http.Response) time.Duration {
	v := res.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func (c *Client) post(ctx context.Context, path string, body any, auth bool) (*http.Response, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	// Trần đọc: một cloud hỏng trả về vài trăm MB sẽ làm agent hết bộ nhớ, và
	// agent chết là mất luôn đường quan sát instance đó.
	out, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, nil, err
	}
	return res, out, nil
}

func snippet(b []byte) string {
	const n = 200
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
