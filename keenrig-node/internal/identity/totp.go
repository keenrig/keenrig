package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 quy định HMAC-SHA1; đổi là không tương thích app xác thực
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP theo RFC 6238. Tự viết vì nó là ~40 dòng và mọi tham số đều cố định bởi
// chuẩn — một thư viện ở đây chỉ thêm một phụ thuộc phải theo dõi.
//
// SHA-1 KHÔNG phải lựa chọn: RFC 6238 quy định vậy và mọi app xác thực (Google
// Authenticator, 1Password, Aegis) đều giả định SHA-1 + 6 chữ số + chu kỳ 30s.
// Đổi sang SHA-256 sẽ sinh mã mà không app nào khớp. Điểm yếu va chạm của SHA-1
// cũng không áp dụng ở đây: TOTP dùng HMAC, và HMAC-SHA1 vẫn an toàn.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew — chấp nhận lệch ±1 bước (±30 giây).
	//
	// Không phải 0: đồng hồ điện thoại lệch vài giây là chuyện thường, và một
	// người gõ mã đúng vào giây thứ 29 sẽ bị từ chối. Cũng không phải ±2 hay
	// hơn: mỗi bước nới rộng là nhân đôi số mã hợp lệ cùng lúc.
	totpSkew = 1
	// secretLen — 20 byte = 160 bit, đúng khuyến nghị RFC 4226 §4.
	totpSecretLen = 20
)

// NewTOTPSecret sinh secret mới, trả chuỗi base32 (dạng app xác thực nhận).
func NewTOTPSecret() (string, error) {
	b := make([]byte, totpSecretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Không padding: app xác thực hiển thị và nhận tay chuỗi này, dấu "=" chỉ
	// làm người dùng gõ nhầm.
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPURI dựng otpauth:// để hiện QR.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCode sinh mã cho một mốc thời gian.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return codeAtCounter(key, uint64(t.Unix())/uint64(totpPeriod.Seconds())), nil
}

// VerifyTOTP kiểm mã, chấp nhận lệch ±totpSkew bước.
//
// So sánh bằng thời gian hằng số: mã chỉ có 6 chữ số, nên rò rỉ thời gian ở
// đây thu hẹp không gian tìm kiếm nhanh hơn nhiều so với ở một chuỗi dài.
func VerifyTOTP(secret, code string, now time.Time) bool {
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	counter := uint64(now.Unix()) / uint64(totpPeriod.Seconds())
	ok := false
	for d := -totpSkew; d <= totpSkew; d++ {
		c := counter
		switch {
		case d < 0:
			if c < uint64(-d) {
				continue
			}
			c -= uint64(-d)
		case d > 0:
			c += uint64(d)
		}
		// KHÔNG thoát sớm khi khớp: thoát sớm làm thời gian phản hồi tiết lộ
		// mã rơi vào bước nào, tức là tiết lộ độ lệch đồng hồ của server.
		if subtle.ConstantTimeCompare([]byte(codeAtCounter(key, c)), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// codeAtCounter — HOTP (RFC 4226): HMAC-SHA1 rồi truncate động.
func codeAtCounter(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}
