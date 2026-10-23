package s3

// AWS Signature Version 4, tự ký.
//
// # Vì sao không dùng SDK
//
// Driver này cần ĐÚNG BỐN request: PUT object, GET object, DELETE object,
// ListObjectsV2. `minio-go` hay `aws-sdk-go-v2` mang theo một cây phụ thuộc lớn
// cho bốn lời gọi HTTP, và cả hai đều là mã ta không đọc trong khi phần ta cần là
// một thuật toán được đặc tả công khai.
//
// Cái phải trả giá, nói thẳng: ký sai là chỗ dễ sai nhất trong cả package, và một
// chữ ký sai chỉ lộ ra khi nói chuyện với server thật. Nên bộ test của driver này
// chạy trên MinIO THẬT — server tự kiểm chữ ký và trả 403 SignatureDoesNotMatch
// nếu ta ký sai. Đó là oracle mạnh hơn bất kỳ test vector chép tay nào, vì nó
// kiểm cả những phần ta không nghĩ tới.
//
// # UNSIGNED-PAYLOAD, và vì sao
//
// SigV4 muốn SHA256 của toàn bộ payload trong chữ ký. Với một snapshot vài
// gigabyte, điều đó nghĩa là đọc dữ liệu HAI LẦN (một lần để băm, một lần để
// gửi) — mà `Put` nhận `io.Reader`, không seek lại được. Phương án còn lại là
// chunked signing (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), phức tạp gấp nhiều lần.
//
// `UNSIGNED-PAYLOAD` là lựa chọn được S3 hỗ trợ chính thức: chữ ký vẫn phủ
// method, đường dẫn, query và header, chỉ không phủ nội dung. Trên HTTPS thì TLS
// đã bảo đảm toàn vẹn nội dung. Trên HTTP thì KHÔNG — nên driver từ chối endpoint
// `http://` trừ khi người vận hành tự đặt `insecure=true` (xem dsn.go).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	algorithm = "AWS4-HMAC-SHA256"
	// unsignedPayload — xem godoc đầu file.
	unsignedPayload = "UNSIGNED-PAYLOAD"
	// emptySHA256 — sha256 của chuỗi rỗng, dùng cho GET/DELETE/LIST (không body).
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type creds struct {
	keyID  string
	secret string
	region string
}

// sign gắn header Authorization vào req.
//
// payloadHash là `UNSIGNED-PAYLOAD` hoặc hex sha256. now truyền vào để test cố
// định được thời gian.
func sign(req *http.Request, c creds, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateOnly := now.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	// Host KHÔNG nằm trong req.Header của Go (nó ở req.Host/req.URL), nhưng nó
	// PHẢI có trong canonical headers. Bỏ nó là 403, và thông báo của S3 không
	// nói header nào thiếu.
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	signed, canonicalHeaders := canonicalHeaders(req, host)
	canonicalReq := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders,
		signed,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateOnly, c.region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalReq)),
	}, "\n")

	key := signingKey(c.secret, dateOnly, c.region, "s3")
	sig := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))

	req.Header.Set("Authorization", algorithm+
		" Credential="+c.keyID+"/"+scope+
		", SignedHeaders="+signed+
		", Signature="+sig)
}

// canonicalURI mã hoá từng SEGMENT của đường dẫn, giữ nguyên dấu '/'.
//
// Đây là một trong hai chỗ hay sai nhất. Ba luật cụ thể:
//
//   - KHÔNG mã hoá lại '/': nó là phân cách, không phải dữ liệu.
//   - Mã hoá theo RFC 3986, tức là '~' KHÔNG được mã hoá (url.QueryEscape mã hoá
//     nó, nên không dùng được) và khoảng trắng thành %20 (không phải '+').
//   - Đường dẫn rỗng thành "/".
func canonicalURI(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s)
	}
	return strings.Join(segs, "/")
}

// canonicalQuery — tham số sắp xếp theo tên, mã hoá RFC 3986, nối bằng '&'.
//
// Tham số cùng tên phải sắp xếp theo GIÁ TRỊ sau khi mã hoá. Không làm thế thì
// chữ ký đổi theo thứ tự map của Go, và lỗi chỉ xuất hiện ngẫu nhiên.
func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// canonicalHeaders trả (SignedHeaders, CanonicalHeaders).
//
// Chỉ ký host + mọi header x-amz-*. Ký thêm header khác không sai nhưng mỗi header
// được ký là một header mà proxy trên đường đi không được sửa — và Content-Length
// thì proxy CÓ sửa.
func canonicalHeaders(req *http.Request, host string) (string, string) {
	names := []string{"host"}
	vals := map[string]string{"host": host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") {
			names = append(names, lk)
			vals[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(vals[n])
		b.WriteByte('\n')
	}
	return strings.Join(names, ";"), b.String()
}

// uriEncode — RFC 3986 unreserved giữ nguyên, còn lại %XX CHỮ HOA.
//
// Tự viết thay vì dùng net/url vì cả `url.QueryEscape` (biến ' ' thành '+', mã
// hoá '~') và `url.PathEscape` (giữ nguyên nhiều ký tự reserved như ':' và '@')
// đều KHÔNG khớp luật của SigV4.
func uriEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hexSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
