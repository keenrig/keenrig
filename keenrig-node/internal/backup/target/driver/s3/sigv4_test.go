package s3

// Test cho phần THUẦN TÍNH TOÁN của SigV4.
//
// Chữ ký hoàn chỉnh được kiểm bởi MinIO thật (s3_test.go) — server tự bác chữ ký
// sai. Ở đây kiểm những mảnh mà một chữ ký sai KHÔNG chỉ ra được là sai ở đâu:
// nếu MinIO trả 403 thì ta biết có lỗi, nhưng không biết ở uriEncode hay ở
// canonicalQuery. Hai tầng test trả lời hai câu hỏi khác nhau.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// uriEncode theo RFC 3986: chỉ A-Z a-z 0-9 - _ . ~ giữ nguyên.
//
// Ba bẫy cụ thể, và cả ba là lý do không dùng net/url:
//   - `url.QueryEscape` biến ' ' thành '+' (SigV4 cần %20) và mã hoá '~' (SigV4
//     không được mã hoá).
//   - `url.PathEscape` giữ nguyên ':' '@' '$' '&' '+' — SigV4 phải mã hoá chúng.
//   - %XX phải CHỮ HOA.
func TestURIEncode(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"abcXYZ019":           "abcXYZ019",
		"-_.~":                "-_.~", // unreserved, KHÔNG mã hoá
		" ":                   "%20",  // không phải '+'
		"+":                   "%2B",
		"/":                   "%2F", // canonicalURI gọi từng segment nên '/' tới đây là dữ liệu
		"=":                   "%3D",
		"&":                   "%26",
		":":                   "%3A",
		"@":                   "%40",
		"(":                   "%28",
		"%":                   "%25",
		"a b":                 "a%20b",
		"\n":                  "%0A",
		"\u00e1":              "%C3%A1", // UTF-8 theo từng byte
		"phan tram %20 trong": "phan%20tram%20%2520%20trong",
	}
	for in, want := range cases {
		if got := uriEncode(in); got != want {
			t.Errorf("uriEncode(%q) = %q, muốn %q", in, got, want)
		}
	}
	// %XX phải chữ HOA: chữ thường vẫn là URI hợp lệ nhưng chữ ký KHÔNG khớp, và
	// lỗi lộ ra thành 403 không giải thích được.
	if got := uriEncode("\xff"); got != "%FF" {
		t.Errorf("uriEncode(0xff) = %q — %%XX phải chữ hoa", got)
	}
}

// canonicalURI mã hoá từng segment, GIỮ NGUYÊN dấu '/'.
func TestCanonicalURI(t *testing.T) {
	cases := map[string]string{
		"":                       "/",
		"/":                      "/",
		"/bucket/key":            "/bucket/key",
		"/bucket/co khoang":      "/bucket/co%20khoang",
		"/bucket/a/b/c.tgz":      "/bucket/a/b/c.tgz",
		"/bucket/dau~nga":        "/bucket/dau~nga",
		"/bucket/co+cong":        "/bucket/co%2Bcong",
		"/bucket/tieng-viet-á":   "/bucket/tieng-viet-%C3%A1",
		"/bucket/hai//lien-tiep": "/bucket/hai//lien-tiep",
	}
	for in, want := range cases {
		if got := canonicalURI(in); got != want {
			t.Errorf("canonicalURI(%q) = %q, muốn %q", in, got, want)
		}
	}
}

// canonicalQuery sắp xếp theo tên, rồi theo giá trị.
//
// Không sắp xếp thì chữ ký đổi theo thứ tự lặp map của Go — và lỗi chỉ xuất hiện
// ngẫu nhiên, ở một phần các lần chạy, không tái hiện được.
func TestCanonicalQuery(t *testing.T) {
	q := url.Values{
		"list-type":          {"2"},
		"continuation-token": {"abc/def+ghi"},
		"prefix":             {"snap/"},
	}
	want := "continuation-token=abc%2Fdef%2Bghi&list-type=2&prefix=snap%2F"
	if got := canonicalQuery(q); got != want {
		t.Errorf("= %q\nmuốn %q", got, want)
	}

	// Tham số cùng tên, nhiều giá trị: sắp xếp theo giá trị đã mã hoá.
	multi := url.Values{"x": {"b", "a"}}
	if got := canonicalQuery(multi); got != "x=a&x=b" {
		t.Errorf("nhiều giá trị = %q, muốn x=a&x=b", got)
	}

	// Ổn định: gọi nhiều lần cho cùng kết quả.
	for i := 0; i < 20; i++ {
		if canonicalQuery(q) != want {
			t.Fatal("canonicalQuery không ổn định giữa các lần gọi")
		}
	}
}

// Host PHẢI nằm trong signed headers, và mọi x-amz-* cũng vậy.
//
// Thiếu host là 403, và thông báo của S3 không nói header nào thiếu.
func TestCanonicalHeadersIncludesHostAndAmz(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, "http://example.tld/b/k", nil)
	req.Header.Set("X-Amz-Date", "20260810T000000Z")
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	req.Header.Set("Content-Type", "application/octet-stream")

	signed, canon := canonicalHeaders(req, "example.tld")
	if signed != "host;x-amz-content-sha256;x-amz-date" {
		t.Errorf("SignedHeaders = %q", signed)
	}
	if !strings.HasPrefix(canon, "host:example.tld\n") {
		t.Errorf("CanonicalHeaders không mở đầu bằng host: %q", canon)
	}
	// Content-Type KHÔNG được ký: mỗi header được ký là một header mà proxy trên
	// đường đi không được sửa, và các header không phải x-amz-* thì proxy CÓ sửa.
	if strings.Contains(canon, "content-type") {
		t.Error("ký cả Content-Type — proxy sửa nó là chữ ký hỏng")
	}
}

// Khoá ký phụ thuộc NGÀY, region và service — đổi bất kỳ cái nào phải ra khoá khác.
//
// Đây là chỗ một lỗi copy-paste (dùng amzDate đầy đủ thay vì chỉ ngày) sẽ làm chữ
// ký chỉ hợp lệ đúng một giây.
func TestSigningKeyVariesByScope(t *testing.T) {
	base := signingKey("secret", "20260810", "us-east-1", "s3")
	same := signingKey("secret", "20260810", "us-east-1", "s3")
	if string(base) != string(same) {
		t.Fatal("cùng đầu vào ra hai khoá khác nhau")
	}
	for _, other := range [][]byte{
		signingKey("secret2", "20260810", "us-east-1", "s3"),
		signingKey("secret", "20260811", "us-east-1", "s3"),
		signingKey("secret", "20260810", "eu-west-1", "s3"),
		signingKey("secret", "20260810", "us-east-1", "s3x"),
	} {
		if string(base) == string(other) {
			t.Error("đổi một thành phần của scope mà khoá không đổi")
		}
	}
	if len(base) != 32 {
		t.Errorf("khoá dài %d byte, muốn 32", len(base))
	}
}

// Authorization phải có đủ ba phần và scope theo đúng ngày UTC.
func TestSignSetsAuthorizationHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.tld/b/k", nil)
	// Cố tình chọn một mốc mà giờ địa phương và UTC khác NGÀY: nếu ta dùng giờ
	// địa phương ở bất kỳ đâu thì scope sẽ lệch một ngày và mọi request 403.
	at := time.Date(2026, 8, 10, 23, 30, 0, 0, time.FixedZone("ICT", 7*3600))
	sign(req, creds{keyID: "AKID", secret: "secret", region: "ap-southeast-1"}, emptySHA256, at)

	auth := req.Header.Get("Authorization")
	for _, want := range []string{
		algorithm + " ",
		"Credential=AKID/20260810/ap-southeast-1/s3/aws4_request",
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization thiếu %q:\n%s", want, auth)
		}
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20260810T163000Z" {
		t.Errorf("X-Amz-Date = %q — phải là UTC", got)
	}
}
