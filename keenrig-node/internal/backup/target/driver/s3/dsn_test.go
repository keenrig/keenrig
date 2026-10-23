package s3

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
)

func TestParseDSN(t *testing.T) {
	ok := []struct {
		dsn  string
		want Options
	}{
		{"s3://bucket", Options{Bucket: "bucket"}},
		{"s3://bucket/tien/to", Options{Bucket: "bucket", Prefix: "tien/to"}},
		{"s3://bucket/tien/to/", Options{Bucket: "bucket", Prefix: "tien/to"}},
		{"s3://b?region=eu-west-1", Options{Bucket: "b", Region: "eu-west-1"}},
		{"s3://b?endpoint=https://s3.example.tld", Options{Bucket: "b", Endpoint: "https://s3.example.tld"}},
		{"s3://b?insecure=true", Options{Bucket: "b", Insecure: true}},
		{"s3://b?insecure=false", Options{Bucket: "b"}},
	}
	for _, c := range ok {
		t.Run(c.dsn, func(t *testing.T) {
			got, err := parseDSN(c.dsn)
			if err != nil {
				t.Fatalf("muốn hợp lệ, nhận %v", err)
			}
			// So từng trường: Options có trường func nên không so trực tiếp được.
			if got.Bucket != c.want.Bucket || got.Prefix != c.want.Prefix ||
				got.Region != c.want.Region || got.Endpoint != c.want.Endpoint ||
				got.Insecure != c.want.Insecure {
				t.Errorf("= %+v, muốn %+v", got, c.want)
			}
		})
	}

	bad := map[string]string{
		"rỗng":                    "",
		"scheme sai":              "https://bucket",
		"không scheme":            "bucket/tien-to",
		"thiếu bucket":            "s3:///chi-co-duong-dan",
		"credential trong DSN":    "s3://KEY:SECRET@bucket",
		"tham số gõ sai":          "s3://b?endpoints=https://x",
		"tham số lạ":              "s3://b?token=abc",
		"insecure không boolean":  "s3://b?insecure=co",
		"tiền tố thoát ra":        "s3://b/../thoat",
		"tiền tố có segment rỗng": "s3://b/a//b",
	}
	for name, dsn := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDSN(dsn); !errors.Is(err, target.ErrBadConfig) {
				t.Errorf("parseDSN(%q) = %v, muốn ErrBadConfig", dsn, err)
			}
		})
	}
}

// Credential trong DSN bị TỪ CHỐI, và thông báo phải chỉ ra hai biến đúng.
//
// Bỏ qua im lặng nghĩa là người vận hành tưởng đã cấu hình xong rồi nhận một lỗi
// "thiếu credential" không liên quan gì tới thứ họ vừa gõ.
func TestCredentialsInDSNRejectedWithGuidance(t *testing.T) {
	_, err := parseDSN("s3://AKIA123:secret@bucket/prefix")
	if err == nil {
		t.Fatal("credential trong DSN được nhận")
	}
	for _, want := range []string{EnvKeyID, EnvSecret} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("thông báo không chỉ ra %s: %v", want, err)
		}
	}
	// Và KHÔNG được in lại secret trong thông báo — đó đúng là thứ ta đang bảo vệ.
	if strings.Contains(err.Error(), "secret") && strings.Contains(err.Error(), "AKIA123") {
		t.Errorf("thông báo lỗi in lại credential: %v", err)
	}
}

// Endpoint http:// bị từ chối nếu không có insecure=true.
//
// Chữ ký dùng UNSIGNED-PAYLOAD, nên trên HTTP một người đứng giữa sửa được nội
// dung bản sao lưu mà chữ ký vẫn hợp lệ. Đây là quyết định an ninh, không phải sở
// thích — nên nó phải có test.
func TestPlainHTTPRefusedUnlessInsecure(t *testing.T) {
	base := Options{Bucket: "b", KeyID: "k", Secret: "s", Endpoint: "http://127.0.0.1:9000"}
	_, err := New(context.Background(), base)
	if !errors.Is(err, target.ErrBadConfig) {
		t.Fatalf("= %v, muốn ErrBadConfig", err)
	}
	if !strings.Contains(err.Error(), "insecure=true") {
		t.Errorf("thông báo không nói cách bật có chủ đích: %v", err)
	}
}

// Thiếu credential → lỗi lúc mở, và thông báo nói tên biến.
func TestMissingCredentialsNamesTheEnvVars(t *testing.T) {
	_, err := New(context.Background(), Options{Bucket: "b", Endpoint: "https://s3.example.tld"})
	if !errors.Is(err, target.ErrBadConfig) {
		t.Fatalf("= %v, muốn ErrBadConfig", err)
	}
	if !strings.Contains(err.Error(), EnvKeyID) {
		t.Errorf("thông báo không nói %s: %v", EnvKeyID, err)
	}
}
