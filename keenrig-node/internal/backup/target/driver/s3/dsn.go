package s3

// Phân tích DSN. Tách file riêng vì đây là phần DUY NHẤT người vận hành gõ tay,
// nên mọi thông báo lỗi ở đây phải kèm ví dụ đúng.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
)

// Hai biến cho credential, KHÔNG đặt trong DSN — xem godoc s3.go.
const (
	EnvKeyID  = "KEENRIG_BACKUP_S3_KEY_ID"
	EnvSecret = "KEENRIG_BACKUP_S3_SECRET"
)

const dsnUsage = `syntax: s3://<bucket>[/<prefix>][?region=<r>&endpoint=<url>&insecure=true]`

// parseDSN đọc `s3://bucket/prefix?...`.
func parseDSN(dsn string) (Options, error) {
	var opt Options
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return opt, fmt.Errorf("%w: %s needs a DSN. %s", target.ErrBadConfig, Name, dsnUsage)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return opt, fmt.Errorf("%w: %s: %s. %s", target.ErrBadConfig, Name, err, dsnUsage)
	}
	if u.Scheme != "s3" {
		return opt, fmt.Errorf("%w: %s: scheme is %q, want s3://. %s",
			target.ErrBadConfig, Name, u.Scheme, dsnUsage)
	}
	// Credential trong DSN bị TỪ CHỐI, không phải bỏ qua: bỏ qua im lặng nghĩa là
	// người vận hành tưởng đã cấu hình xong rồi nhận một lỗi "thiếu credential"
	// không liên quan gì tới thứ họ vừa gõ.
	if u.User != nil {
		return opt, fmt.Errorf("%w: %s: do NOT put credentials in the DSN (the DSN ends up in logs) — "+
			"use %s and %s", target.ErrBadConfig, Name, EnvKeyID, EnvSecret)
	}
	opt.Bucket = u.Host
	if opt.Bucket == "" {
		return opt, fmt.Errorf("%w: %s: missing bucket. %s", target.ErrBadConfig, Name, dsnUsage)
	}

	opt.Prefix = strings.Trim(u.Path, "/")
	if opt.Prefix != "" {
		// Tiền tố phải theo đúng luật key, nếu không nó là một đường vòng qua
		// ValidateKey: mọi key sạch nối sau một tiền tố `../` vẫn ra ngoài.
		if err := target.ValidateKey(opt.Prefix); err != nil {
			return opt, fmt.Errorf("%w: %s: prefix %q: %s", target.ErrBadConfig, Name, opt.Prefix, err)
		}
	}

	q := u.Query()
	for k := range q {
		switch k {
		case "region", "endpoint", "insecure":
		default:
			// Tham số lạ bị TỪ CHỐI thay vì bỏ qua: gõ `endpoints=` thay vì
			// `endpoint=` sẽ im lặng trỏ về AWS S3 công cộng, và bản sao lưu đi
			// tới một nơi người vận hành không hề chọn.
			return opt, fmt.Errorf("%w: %s: unknown parameter %q. %s", target.ErrBadConfig, Name, k, dsnUsage)
		}
	}
	opt.Region = strings.TrimSpace(q.Get("region"))
	opt.Endpoint = strings.TrimSpace(q.Get("endpoint"))
	if s := strings.TrimSpace(q.Get("insecure")); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return opt, fmt.Errorf("%w: %s: insecure=%q is not true/false",
				target.ErrBadConfig, Name, s)
		}
		opt.Insecure = b
	}
	return opt, nil
}
