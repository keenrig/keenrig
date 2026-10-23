package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// JWT ký bằng stdlib, không thêm thư viện.
//
// # Vì sao tự viết thay vì kéo một thư viện JWT
//
// Phần ta CẦN của JWT là ba dòng: base64url(header).base64url(payload), ký
// RS256, ghép chữ ký. Phần nguy hiểm của mọi thư viện JWT là phần XÁC MINH —
// và ở đây ta là bên PHÁT HÀNH, không phải bên xác minh. Ta không bao giờ phải
// đọc một token do người khác ký, nên cả lớp lỗ hổng nổi tiếng nhất của JWT
// (`alg: none`, nhầm HMAC với RSA, tin `alg` trong header) không tồn tại trên
// đường của ta.
//
// Có MỘT chỗ ta tự xác minh: access token của chính mình ở `/userinfo`. Chỗ đó
// KHÔNG đọc `alg` từ header — nó áp thuật toán từ bên ngoài. Xem verify().
//
// # Vì sao RS256 chứ không ES256
//
// ES256 nhỏ hơn và nhanh hơn. Nhưng bên tiêu thụ là app tự lưu trữ của người
// khác — Grafana, Nextcloud, một dashboard nội bộ — và RS256 là thuật toán duy
// nhất mà `id_token_signing_alg_values_supported` nào cũng chấp nhận. Chọn cái
// đẹp hơn ở đây nghĩa là một số app không đăng nhập được, và người vận hành
// không có cách nào sửa từ phía họ.

const (
	// SigningAlg — thuật toán ký ID token và access token.
	SigningAlg = "RS256"
	// keyBits — độ dài khoá RSA.
	//
	// 2048 chứ không 4096: khoá này ký MỌI lần đăng nhập của mọi app, và 4096
	// tốn khoảng 6–7 lần thời gian ký cho một mức an toàn không ai đang cần.
	keyBits = 2048
)

// signingKey — khoá ký kèm định danh của nó.
type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

// newSigningKey sinh khoá mới. kid dẫn xuất TỪ khoá công khai, không phải ngẫu
// nhiên: hai tiến trình đọc cùng một khoá phải ra cùng một kid, nếu không thì
// JWKS công bố một kid khác với kid trong token và RP từ chối mọi thứ.
func newSigningKey() (*signingKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	return &signingKey{kid: thumbprint(&k.PublicKey), key: k}, nil
}

// thumbprint — RFC 7638 JWK thumbprint, rút gọn cho đúng RSA.
//
// Thứ tự khoá trong JSON là BẮT BUỘC theo chuẩn ("e" trước "kty" trước "n") và
// không có khoảng trắng. Viết tay chuỗi thay vì json.Marshal một map: map trong
// Go không có thứ tự, và một thumbprint sai thứ tự vẫn "chạy" cho tới khi có
// bên thứ hai tự tính lại nó.
func thumbprint(pub *rsa.PublicKey) string {
	j := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, encodeExp(pub.E), b64(pub.N.Bytes()))
	sum := sha256.Sum256([]byte(j))
	return b64(sum[:])
}

func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

// encodeExp mã hoá số mũ công khai theo big-endian KHÔNG có byte 0 ở đầu.
func encodeExp(e int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(e))
	i := 0
	for i < len(buf)-1 && buf[i] == 0 {
		i++
	}
	return b64(buf[i:])
}

// marshalKey / parseKey — dạng lưu trong bảng secrets (PKCS#8 trong PEM).
//
// PEM chứ không phải DER trần: khoá này có thể phải được người vận hành nhìn
// thấy, sao chép, hoặc khôi phục bằng tay từ một bản sao lưu, và một khối
// base64 có nhãn `BEGIN PRIVATE KEY` thì mọi công cụ đều đọc được.
func marshalKey(k *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseKey(raw []byte) (*signingKey, error) {
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("oidc: the stored signing key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oidc: parsing the signing key: %w", err)
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("oidc: the signing key is %T, want RSA", parsed)
	}
	return &signingKey{kid: thumbprint(&k.PublicKey), key: k}, nil
}

// --- ký ------------------------------------------------------------------------------

// sign tạo một JWS compact từ claims.
func (s *signingKey) sign(claims map[string]any) (string, error) {
	head, err := json.Marshal(map[string]string{"alg": SigningAlg, "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// verify kiểm chữ ký + hạn của một token do CHÍNH ta phát hành.
//
// # Nó KHÔNG đọc `alg` từ header, và đó là điểm quan trọng nhất của hàm này
//
// Cách hỏng kinh điển của JWT là tin vào `alg` trong header rồi chọn thuật toán
// theo nó: kẻ tấn công đặt `alg: none` (bỏ luôn chữ ký) hoặc đổi RS256 thành
// HS256 rồi ký bằng chính khoá CÔNG KHAI của ta — mà khoá công khai thì nằm ở
// /jwks.json cho ai cũng tải được.
//
// Ở đây thuật toán là hằng số của chương trình. Header chỉ được dùng để tra
// `kid` trong tập khoá của ta; một `alg` lạ bị TỪ CHỐI chứ không được chiều.
func (p *Provider) verify(token string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(raw, &head) != nil {
		return nil, ErrInvalidToken
	}
	if head.Alg != SigningAlg {
		return nil, ErrInvalidToken
	}
	key := p.keyByID(head.Kid)
	if key == nil {
		return nil, ErrInvalidToken
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&key.key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return nil, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	exp, ok := claims["exp"].(float64)
	if !ok || now.Unix() >= int64(exp) {
		return nil, ErrTokenExpired
	}
	if iss, _ := claims["iss"].(string); iss != p.opts.Issuer {
		// Token do một issuer khác ký bằng một khoá trùng kid là chuyện không
		// xảy ra được, nhưng kiểm iss là một dòng và nó khoá lại giả định đó.
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// --- JWKS ------------------------------------------------------------------------------

// jwk — một khoá công khai ở dạng JSON Web Key.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwks — tập khoá công khai công bố tại /oidc/jwks.json.
//
// Trả về NHIỀU khoá kể cả khi chỉ có một: xoay khoá là việc phải làm được mà
// không làm gãy token đang lưu hành, và cách duy nhất là công bố cả khoá cũ lẫn
// khoá mới trong một khoảng chuyển tiếp. Một endpoint trả đúng một khoá sẽ ép
// người viết RP giả định điều đó.
func (p *Provider) jwks() map[string]any {
	p.mu.RLock()
	defer p.mu.RUnlock()

	keys := make([]jwk, 0, len(p.keys))
	for _, k := range p.keys {
		pub := &k.key.PublicKey
		keys = append(keys, jwk{
			Kty: "RSA", Use: "sig", Alg: SigningAlg, Kid: k.kid,
			N: b64(pub.N.Bytes()), E: encodeExp(pub.E),
		})
	}
	// Thứ tự ổn định: JWKS được cache theo ETag ở nhiều RP, và một thứ tự đổi
	// mỗi lần gọi làm mọi cache đó vô dụng.
	sort.Slice(keys, func(i, j int) bool { return keys[i].Kid < keys[j].Kid })
	return map[string]any{"keys": keys}
}

func (p *Provider) keyByID(kid string) *signingKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, k := range p.keys {
		if k.kid == kid {
			return k
		}
	}
	return nil
}
