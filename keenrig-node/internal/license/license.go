// Package license — verify license Ed25519 và mở/khoá tính năng theo `features`.
//
// Bên VERIFY (đối xứng với bên ký ở Keenrig Cloud (`license`)). Instance
// kiểm chữ ký bằng khoá công nhúng trong binary và KHÔNG HỎI AI CẢ — đó là toàn
// bộ lý do license tồn tại tách khỏi billing: một subscription không kiểm được
// khi máy đã ngắt cloud, còn một chữ ký thì có.
//
// # Ba luật của package này, xếp theo thứ tự quan trọng
//
//  1. KHÔNG CÓ LICENSE LÀ MỘT TRẠNG THÁI HỢP LỆ — nó nghĩa là bậc miễn phí
//     (starter: docker · 1 node · 3 app · 3 domain), không phải một lỗi. Bản
//     self-hosted không có tài khoản cloud sống trọn đời ở trạng thái này.
//  2. HẠ BẬC CHỈ CHẶN THAO TÁC MỚI. License hết hạn (quá cả grace) đưa máy về
//     giới hạn starter, nghĩa là app THỨ TƯ không cài thêm được — nhưng mười
//     hai app đang chạy vẫn chạy. Một cái thẻ hết hạn không được phép làm sập
//     cửa hàng của ai.
//  3. Docker LUÔN được phép. Không tồn tại trạng thái nào — license hỏng, hết
//     hạn, giả mạo — mà bậc miễn phí bị khoá.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// Keys — khoá công theo key_id. Giữ HAI khoá (active + next) để xoay khoá mà
// binary cũ vẫn verify được — cùng cơ chế manifest catalog và bản OTA.
type Keys map[string]ed25519.PublicKey

// ParseKeys đọc "id1=base64,id2=base64" (RawURLEncoding hoặc Std đều nhận).
//
// Nguồn chuỗi: nhúng lúc build qua -ldflags, hoặc env cho môi trường dev/test.
// Nửa vời (id không khoá, khoá sai cỡ) → LỖI, không bỏ qua im lặng: một khoá
// đọc sai nghĩa là mọi license đều "giả mạo" và không ai hiểu vì sao.
func ParseKeys(raw string) (Keys, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := Keys{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64, ok := strings.Cut(part, "=")
		if !ok || id == "" || b64 == "" {
			return nil, fmt.Errorf("license: key entry %q is not in id=base64 form", part)
		}
		key, err := decodeB64(b64)
		if err != nil {
			return nil, fmt.Errorf("license: key %q could not be decoded: %w", id, err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("license: key %q is %d bytes, Ed25519 needs %d",
				id, len(key), ed25519.PublicKeySize)
		}
		out[id] = ed25519.PublicKey(key)
	}
	return out, nil
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Status — license đang ở pha nào của vòng đời.
type Status string

const (
	// StatusNone — không có license: bậc miễn phí. KHÔNG phải lỗi.
	StatusNone  Status = "none"
	StatusValid Status = "valid"
	// StatusGrace — quá expires_at nhưng còn trong grace_days: ĐỦ QUYỀN, kèm
	// một lời nhắc. Grace tồn tại vì gia hạn thẻ trượt là chuyện hằng ngày.
	StatusGrace Status = "grace"
	// StatusExpired — quá cả grace: quyền về sàn starter. Thứ đang chạy vẫn chạy.
	StatusExpired Status = "expired"
)

// State — kết quả sau verify: quyền HIỆU LỰC tại thời điểm hỏi.
type State struct {
	Status   Status
	Plan     string
	Features contracts.Features // quyền ĐANG áp dụng (đã tính grace/hết hạn)
	// Payload — nội dung license gốc, nil khi StatusNone. Giữ để UI hiện "hết
	// hạn ngày…" — con số thật, không phải suy đoán.
	Payload *contracts.LicensePayload
}

// StarterFeatures — SÀN quyền: không license, license hỏng, hay hết hạn đều về
// đây. Docker 1 node · 3 app · 3 domain — cùng hằng `contracts.Starter*` mà
// TierLimits(starter) phía cloud đọc, nên hai bên không thể lệch nhau.
func StarterFeatures() contracts.Features {
	return contracts.Features{
		Plan: "starter", Runtime: "docker",
		MaxNodes:   contracts.StarterMaxNodes,
		MaxApps:    contracts.StarterMaxApps,
		MaxDomains: contracts.StarterMaxDomains,
	}
}

// Các lỗi phân loại được.
var (
	ErrBadSignature = errors.New("license: invalid signature")
	ErrUnknownKey   = errors.New("license: signed with a key this binary does not know")
	ErrMalformed    = errors.New("license: malformed license file")
)

// Verify kiểm một file license và trả về quyền hiệu lực tại `now`.
//
// Thứ tự là nội dung: CHỮ KÝ TRƯỚC, unmarshal payload SAU. Parse một payload
// chưa xác thực là trao cho kẻ nắm file một parser JSON làm bề mặt tấn công.
func Verify(raw []byte, keys Keys, now time.Time) (*State, error) {
	var env contracts.LicenseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if env.V != contracts.LicenseEnvelopeV {
		return nil, fmt.Errorf("%w: envelope v%d, this binary understands v%d",
			ErrMalformed, env.V, contracts.LicenseEnvelopeV)
	}
	pub, ok := keys[env.KeyID]
	if !ok {
		return nil, fmt.Errorf("%w: key_id %q", ErrUnknownKey, env.KeyID)
	}
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: the payload is not base64url: %v", ErrMalformed, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: the signature is not base64url: %v", ErrMalformed, err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, ErrBadSignature
	}

	var p contracts.LicensePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: the payload is signed but could not be parsed: %v", ErrMalformed, err)
	}
	switch p.Features.Runtime {
	case "docker", "swarm", "k8s":
	default:
		return nil, fmt.Errorf("%w: runtime %q does not exist", ErrMalformed, p.Features.Runtime)
	}
	if p.ExpiresAt.IsZero() || p.InstanceID == "" || p.LicenseID == "" {
		return nil, fmt.Errorf("%w: a required field is missing", ErrMalformed)
	}

	st := &State{Plan: p.Features.Plan, Payload: &p}
	graceEnd := p.ExpiresAt.Add(time.Duration(p.GraceDays) * 24 * time.Hour)
	switch {
	case !now.After(p.ExpiresAt):
		st.Status, st.Features = StatusValid, p.Features
	case !now.After(graceEnd):
		// Trong grace: ĐỦ quyền. Grace mà bị giảm quyền thì nó không phải grace,
		// nó chỉ là một cách hết hạn có trì hoãn thông báo.
		st.Status, st.Features = StatusGrace, p.Features
	default:
		st.Status, st.Features = StatusExpired, StarterFeatures()
		st.Features.Plan = p.Features.Plan // tên bậc giữ để UI nói "gói X đã hết hạn"
	}
	return st, nil
}

// Load đọc license từ đường dẫn. FILE KHÔNG TỒN TẠI → bậc miễn phí, không lỗi
// (luật 1 của package). File CÓ mà hỏng/giả → lỗi: một file hỏng là thứ người
// vận hành phải biết, không phải thứ âm thầm rơi về miễn phí — khách đã trả
// tiền cho một license mà máy đang không nhận thì phải có một dòng đỏ nói vậy.
func Load(path string, keys Keys, now time.Time) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{Status: StatusNone, Plan: "starter", Features: StarterFeatures()}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("license: reading %s: %w", path, err)
	}
	return Verify(raw, keys, now)
}

// --- gates: các phép hỏi mà phần còn lại của box dùng --------------------------

// RuntimeAllowed — driver này có được phép ở quyền hiện tại không.
//
// Chữ ký khớp `runtime.LicenseGate` để cắm thẳng vào `runtime.Open`. Docker
// luôn qua (luật 3). Không có "bậc cao bao hàm bậc thấp" ngoài docker: license
// swarm KHÔNG mở k8s — hai bậc giá khác nhau.
func (s *State) RuntimeAllowed(driver string) error {
	if driver == "docker" || driver == s.Features.Runtime {
		return nil
	}
	return fmt.Errorf("license: tier %s (%s) does not include runtime %q - upgrade the tier or set KEENRIG_RUNTIME=%s",
		s.planLabel(), s.Status, driver, s.Features.Runtime)
}

// CanAddApp — được cài thêm một app khi ĐANG có `current` app không.
// Chặn ở admission, tức trước khi có gì được ghi — app đang chạy không bị đụng.
func (s *State) CanAddApp(current int) error {
	return s.canAdd("app", current, s.Features.MaxApps)
}

// CanAddDomain — được thêm một domain khi đang có `current` domain không.
func (s *State) CanAddDomain(current int) error {
	return s.canAdd("domain", current, s.Features.MaxDomains)
}

// CanJoinNode — được ghép thêm một node khi cluster đang có `current` node không.
func (s *State) CanJoinNode(current int) error {
	return s.canAdd("node", current, s.Features.MaxNodes)
}

func (s *State) canAdd(what string, current, max int) error {
	if max == 0 || current < max { // 0 = không giới hạn (schema v2)
		return nil
	}
	return fmt.Errorf("license: tier %s allows at most %d %s, and %d are in use - NEW operations are blocked, "+
		"nothing already running is touched", s.planLabel(), max, what, current)
}

func (s *State) planLabel() string {
	if s.Plan == "" {
		return "starter"
	}
	return s.Plan
}

// Install verify RỒI mới ghi license xuống đường dẫn — một license không verify
// được KHÔNG BAO GIỜ chạm đĩa: file trên đĩa mà hỏng thì mọi lần Load về sau
// đều đỏ (luật 2), nên chặn từ cổng rẻ hơn nhiều so với dọn hậu quả.
//
// Ghi NGUYÊN TỬ (tmp cùng thư mục + rename): box đọc lại file này ở mọi lần
// admission, và một lần đọc trúng file ghi dở là một lần admission chạy trên
// license cụt — rename trên cùng filesystem thì hoặc thấy bản cũ hoặc bản mới,
// không có bản thứ ba.
func Install(path string, raw []byte, keys Keys, now time.Time) (*State, error) {
	st, err := Verify(raw, keys, now)
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return nil, fmt.Errorf("license: ghi %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("license: thay %s: %w", path, err)
	}
	return st, nil
}
