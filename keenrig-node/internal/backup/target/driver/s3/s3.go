// Package s3 — target trên S3 và mọi thứ nói giao thức S3 (MinIO, Ceph RGW,
// Backblaze B2, Wasabi, R2).
//
//	KEENRIG_BACKUP_TARGET=s3
//	KEENRIG_BACKUP_CONFIG=s3://bucket/tien-to?region=us-east-1&endpoint=https://s3.eu.example&insecure=false
//	KEENRIG_BACKUP_S3_KEY_ID=...
//	KEENRIG_BACKUP_S3_SECRET=...
//
// # Vì sao credential KHÔNG nằm trong DSN
//
// DSN xuất hiện trong thông báo lỗi ("cấu hình driver không hợp lệ: s3://…"), và
// thông báo lỗi đi vào log, vào event, vào ảnh chụp màn hình người dùng gửi khi
// cần hỗ trợ. Một secret trong DSN là một secret trong log. Hai biến riêng thì
// không bao giờ bị in ra cùng DSN.
//
// # Path-style, không phải virtual-host-style
//
// `https://endpoint/bucket/key` chứ không phải `https://bucket.endpoint/key`.
// Virtual-host cần DNS wildcard cho endpoint, mà MinIO/Ceph tự dựng thường không
// có. AWS S3 vẫn nhận path-style. Chọn một kiểu và chỉ một: hỗ trợ cả hai nghĩa là
// có hai đường ký chữ ký, tức là hai chỗ để sai.
package s3

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target"
)

// Name — tên driver.
const Name = "s3"

func init() { target.Register(Name, openFromEnv) }

// Options — thứ New cần. Tách khỏi env để test không đụng môi trường tiến trình.
type Options struct {
	Bucket   string
	Prefix   string // có thể rỗng
	Region   string
	Endpoint string // gồm scheme; rỗng = AWS S3 công cộng
	KeyID    string
	Secret   string
	// Insecure cho phép endpoint http://. Xem godoc sigv4.go: với
	// UNSIGNED-PAYLOAD thì toàn vẹn nội dung do TLS bảo đảm, nên http:// nghĩa là
	// một người đứng giữa sửa được nội dung bản sao lưu mà chữ ký vẫn hợp lệ.
	Insecure bool
	// HTTP để test thay transport. nil = http.DefaultClient với timeout.
	HTTP *http.Client
	// Now để test cố định thời gian ký. nil = time.Now.
	Now func() time.Time
	// MaxKeys giới hạn số key mỗi trang LIST. 0 = mặc định của server (1000).
	//
	// Chỉ có để TEST được phân trang: buộc phân trang bằng cách ghi 1001 object
	// mất vài phút, nên bug phân trang sẽ không bao giờ được canh. Với MaxKeys=2
	// thì 5 object đã đủ ba trang.
	MaxKeys int
}

type Driver struct {
	opt  Options
	base *url.URL // scheme://endpoint/bucket
	cl   *http.Client
	cr   creds
	now  func() time.Time
}

func openFromEnv(ctx context.Context, cfg target.Config) (target.Target, error) {
	opt, err := parseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	opt.KeyID = strings.TrimSpace(os.Getenv(EnvKeyID))
	opt.Secret = strings.TrimSpace(os.Getenv(EnvSecret))
	return New(ctx, opt)
}

// New dựng driver và BẮT TAY với server ngay.
//
// Bắt tay lúc mở, không đợi Put: một credential sai hoặc bucket không tồn tại chỉ
// lộ ra lúc snapshot đầu tiên chạy theo lịch, và đó là lúc không ai xem log. Cùng
// lý lẽ với `driver/dir` ghi file thăm dò.
func New(ctx context.Context, opt Options) (*Driver, error) {
	if opt.Bucket == "" {
		return nil, fmt.Errorf("%w: %s needs a bucket", target.ErrBadConfig, Name)
	}
	if opt.KeyID == "" || opt.Secret == "" {
		return nil, fmt.Errorf("%w: %s needs %s and %s (do NOT put them in the DSN — the DSN ends up in logs)",
			target.ErrBadConfig, Name, EnvKeyID, EnvSecret)
	}
	if opt.Region == "" {
		// us-east-1 là region mà mọi impl S3-compatible chấp nhận trong chữ ký kể
		// cả khi nó không có khái niệm region (MinIO). Đoán một region khác sẽ làm
		// AWS trả AuthorizationHeaderMalformed.
		opt.Region = "us-east-1"
	}
	endpoint := opt.Endpoint
	if endpoint == "" {
		endpoint = "https://s3." + opt.Region + ".amazonaws.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: %s endpoint %q cannot be parsed", target.ErrBadConfig, Name, endpoint)
	}
	if u.Scheme != "https" && !opt.Insecure {
		return nil, fmt.Errorf("%w: %s endpoint %q is not https. Signing uses UNSIGNED-PAYLOAD, so over "+
			"plain HTTP a man in the middle can alter the backup contents. Add "+
			"insecure=true to the DSN if this is a trusted private network",
			target.ErrBadConfig, Name, endpoint)
	}
	u.Path = "/" + opt.Bucket

	cl := opt.HTTP
	if cl == nil {
		// Timeout ở transport, KHÔNG ở Client.Timeout: Client.Timeout phủ cả thời
		// gian đọc body, nên nó sẽ cắt ngang một lần tải 10 GB đang chạy đúng.
		cl = &http.Client{Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}}
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}

	d := &Driver{
		opt: opt, base: u, cl: cl, now: now,
		cr: creds{keyID: opt.KeyID, secret: opt.Secret, region: opt.Region},
	}
	if err := d.ping(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// ping — ListObjectsV2 giới hạn 1 key. Kiểm đủ ba thứ: endpoint tới được,
// credential đúng, bucket tồn tại.
//
// `max-keys=1`, KHÔNG phải 0. Bản đầu dùng 0 với lý lẽ "rẻ nhất" và nó rẻ đúng
// vì nó không kiểm gì: MinIO thấy max-keys=0, trả 200 với danh sách rỗng NGAY,
// trước cả khi tra bucket có tồn tại. Đo được: max-keys=0 → 200 OK, max-keys=1 →
// 404 NoSuchBucket, trên cùng một bucket không tồn tại.
//
// Bài học tổng quát hơn một dòng code: một phép kiểm sức khoẻ được tối ưu cho
// "rẻ" rất dễ trở thành một phép kiểm không kiểm gì.
func (d *Driver) ping(ctx context.Context) error {
	q := url.Values{"list-type": {"2"}, "max-keys": {"1"}}
	resp, err := d.do(ctx, http.MethodGet, "", q, nil, 0, emptySHA256)
	if err != nil {
		return fmt.Errorf("%w: %s: %s", target.ErrBadConfig, Name, err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s: bucket %q returned %s — %s",
			target.ErrBadConfig, Name, d.opt.Bucket, resp.Status, errBody(resp))
	}
	return nil
}

func (d *Driver) Name() string { return Name }

// full ghép prefix cấu hình vào key. Prefix là chuyện của DRIVER, không của
// caller: caller dùng cùng một không gian key trên mọi target.
func (d *Driver) full(key string) string {
	if d.opt.Prefix == "" {
		return key
	}
	return d.opt.Prefix + "/" + key
}

func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := target.ValidateKey(key); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("target: %s: negative size (%d)", Name, size)
	}
	// LimitReader + kiểm số byte đã gửi: size là hợp đồng. Gửi ít hơn đã hứa thì
	// server nhận một object cụt mang đúng tên bản đầy đủ — nên ta phải phát hiện
	// và xoá lại.
	cr := &countingReader{r: io.LimitReader(r, size)}
	resp, err := d.do(ctx, http.MethodPut, key, nil, cr, size, unsignedPayload)
	if err != nil {
		// Ngay cả khi request lỗi giữa đường, server có thể đã nhận một phần.
		// S3 chỉ công bố object khi nhận đủ Content-Length, nhưng ta không được
		// TIN điều đó với mọi impl — nên dọn cho chắc.
		d.cleanup(ctx, key)
		return fmt.Errorf("target: %s: PUT %s: %w", Name, key, err)
	}
	defer drain(resp)
	if resp.StatusCode/100 != 2 {
		d.cleanup(ctx, key)
		return fmt.Errorf("target: %s: PUT %s returned %s — %s", Name, key, resp.Status, errBody(resp))
	}
	if cr.n != size {
		d.cleanup(ctx, key)
		return fmt.Errorf("target: %s: %s declared %d bytes but %d were read", Name, key, size, cr.n)
	}
	return nil
}

// cleanup xoá một object vừa ghi dở. Lỗi ở đây bị bỏ qua CÓ CHỦ ĐÍCH: ta đang
// trên đường xử lý một lỗi khác, và lỗi dọn dẹp không được che lỗi gốc.
func (d *Driver) cleanup(ctx context.Context, key string) {
	if ctx.Err() != nil {
		// ctx đã hết — dùng ctx mới, ngắn, nếu không thì request xoá cũng chết ngay.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
	}
	_ = d.Delete(ctx, key)
}

func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := target.ValidateKey(key); err != nil {
		return nil, err
	}
	resp, err := d.do(ctx, http.MethodGet, key, nil, nil, 0, emptySHA256)
	if err != nil {
		return nil, fmt.Errorf("target: %s: GET %s: %w", Name, key, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		drain(resp)
		return nil, fmt.Errorf("%w: %s", target.ErrNotFound, key)
	case resp.StatusCode/100 != 2:
		msg := errBody(resp)
		drain(resp)
		return nil, fmt.Errorf("target: %s: GET %s returned %s — %s", Name, key, resp.Status, msg)
	}
	return resp.Body, nil
}

func (d *Driver) Delete(ctx context.Context, key string) error {
	if err := target.ValidateKey(key); err != nil {
		return err
	}
	resp, err := d.do(ctx, http.MethodDelete, key, nil, nil, 0, emptySHA256)
	if err != nil {
		return fmt.Errorf("target: %s: DELETE %s: %w", Name, key, err)
	}
	defer drain(resp)
	// S3 trả 204 cho cả object có và không có — DELETE đã idempotent ở tầng giao
	// thức, nên ở đây không cần xử lý gì thêm. 404 vẫn nhận vì một số impl trả nó.
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("target: %s: DELETE %s returned %s — %s", Name, key, resp.Status, errBody(resp))
	}
	return nil
}

// listResult — phần ListObjectsV2 ta dùng.
type listResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// List phân trang cho tới hết.
//
// Phân trang là BẮT BUỘC, không phải tối ưu: S3 trả tối đa 1000 key mỗi lần. Bỏ
// phân trang thì retention trên một bucket có 1500 bản sao lưu chỉ thấy 1000 bản
// đầu — và "1000 bản, giữ 30" nghĩa là nó xoá đúng những bản nó thấy rồi để lại
// 500 bản cũ hơn mãi mãi.
func (d *Driver) List(ctx context.Context, prefix string) ([]target.Object, error) {
	if err := target.ValidatePrefix(prefix); err != nil {
		return nil, err
	}
	var out []target.Object
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {d.full(prefix)}}
		if d.opt.MaxKeys > 0 {
			q.Set("max-keys", strconv.Itoa(d.opt.MaxKeys))
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := d.do(ctx, http.MethodGet, "", q, nil, 0, emptySHA256)
		if err != nil {
			return nil, fmt.Errorf("target: %s: LIST %q: %w", Name, prefix, err)
		}
		if resp.StatusCode/100 != 2 {
			msg := errBody(resp)
			drain(resp)
			return nil, fmt.Errorf("target: %s: LIST %q returned %s — %s", Name, prefix, resp.Status, msg)
		}
		var res listResult
		derr := xml.NewDecoder(resp.Body).Decode(&res)
		drain(resp)
		if derr != nil {
			return nil, fmt.Errorf("target: %s: decoding the LIST response: %w", Name, derr)
		}
		for _, c := range res.Contents {
			key := strings.TrimPrefix(c.Key, d.opt.Prefix+"/")
			if d.opt.Prefix == "" {
				key = c.Key
			}
			out = append(out, target.Object{Key: key, Size: c.Size, ModTime: c.LastModified})
		}
		if !res.IsTruncated || res.NextContinuationToken == "" {
			break
		}
		token = res.NextContinuationToken
	}
	// S3 trả theo thứ tự UTF-8 của key ĐẦY ĐỦ; sau khi cắt prefix thì thứ tự vẫn
	// giữ, nhưng sắp lại để hợp đồng "đã sắp xếp" không phụ thuộc chi tiết đó.
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// do dựng, ký và gửi một request.
func (d *Driver) do(ctx context.Context, method, key string, q url.Values,
	body io.Reader, size int64, payloadHash string) (*http.Response, error) {

	u := *d.base
	if key != "" {
		u.Path = d.base.Path + "/" + d.full(key)
	}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		// ContentLength tường minh: không đặt thì Go dùng chunked
		// transfer-encoding, và S3 THẬT từ chối PUT chunked
		// (MissingContentLength). Đây là lý do `Put` bắt buộc phải nhận size.
		req.ContentLength = size
		if size == 0 {
			// KHÔNG bỏ được nhánh này. Với net/http, `ContentLength = 0` cùng một
			// Body khác nil nghĩa là "ĐỘ DÀI CHƯA BIẾT", không phải "dài 0" — nên
			// Go bỏ header Content-Length và chuyển sang chunked. S3 trả
			// 411 MissingContentLength.
			//
			// Đo được trên MinIO: object 0 byte thất bại còn mọi size khác thành
			// công. Và object 0 byte có thật — một app không có volume nào cho ra
			// archive rỗng. `http.NoBody` là cách tường minh nói "dài đúng 0".
			req.Body = http.NoBody
		}
	}
	// Go tự sinh URL từ u.String(), nhưng chữ ký phải dùng ĐÚNG đường dẫn đã mã
	// hoá mà server thấy. u.Path (chưa mã hoá) là thứ ta ký, và canonicalURI mã
	// hoá lại theo luật SigV4 — nên hai bên khớp.
	req.URL.RawPath = ""
	sign(req, d.cr, payloadHash, d.now())
	return d.cl.Do(req)
}

// countingReader đếm số byte thật đã đọc, để phát hiện size nói sai.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// errBody đọc phần đầu body lỗi. S3 trả XML có <Message> — in nguyên XML thì log
// không đọc được, nên rút ra Code và Message.
func errBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(b, &e) == nil && e.Code != "" {
		return e.Code + ": " + e.Message
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "(no error body)"
	}
	return s
}

// drain đọc hết rồi đóng body.
//
// Không đọc hết thì kết nối không quay lại pool và mỗi request tốn một TCP
// handshake mới — với retention xoá vài trăm object thì đó là vài trăm handshake.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}
