package contracts

// license.go — payload và phong bì của license Ed25519.
//
// Khớp `jsonschema/license.schema.json` v2. Đặt ở contracts vì nó là hợp đồng
// giữa HAI module không được import nhau: keenrig-cloud KÝ, keenrig-node VERIFY.
//
// # Vì sao phong bì giữ payload dưới dạng BYTES đã mã hoá base64
//
// Chữ ký Ed25519 ký trên BYTE, còn JSON thì không có một cách serialize duy
// nhất (thứ tự khoá, khoảng trắng, escape). Nếu bên verify unmarshal rồi
// marshal lại để kiểm chữ ký, nó phải tái tạo đúng từng byte bên ký đã tạo —
// một lời hứa mà mỗi lần nâng cấp thư viện JSON đều có thể phá. Nên phong bì
// mang NGUYÊN VĂN các byte đã ký: verify chữ ký trên các byte đó trước, rồi mới
// unmarshal. Không có bước canonicalize nào để mà sai.

// LicenseEnvelope — file license trên đĩa.
type LicenseEnvelope struct {
	V int `json:"v"` // phiên bản phong bì; hiện là 1
	// KeyID — khoá nào đã ký. Instance giữ HAI khoá công (active + next) để
	// xoay khoá mà binary cũ không chết — cùng cơ chế với manifest catalog.
	KeyID string `json:"key_id"`
	// Payload — base64 RawURLEncoding của các byte JSON LicensePayload, NGUYÊN
	// VĂN như lúc ký. Verify trên byte này; unmarshal SAU khi chữ ký đã đúng.
	Payload string `json:"payload"`
	// Signature — base64 RawURLEncoding của chữ ký Ed25519 trên các byte payload.
	Signature string `json:"signature"`
}

// LicenseEnvelopeV — phiên bản phong bì hiện hành.
const LicenseEnvelopeV = 1

// Hạn mức của bậc miễn phí. Ở đây vì HAI bên cùng cần đúng các số này mà không
// import nhau: cloud dùng cho `TierLimits(starter)`, node dùng làm SÀN quyền khi
// không có license / license hết hạn. Hai bản chép tay là hai bản sẽ lệch.
//
// Nâng 1 → 3 ngày 2026-10-07:
// bậc miễn phí chạy trên máy khách nên thêm app không tốn gì phía ta, và
// 1 app là quá ít để người dùng thử được một bộ công cụ thật.
const (
	StarterMaxNodes   = 1
	StarterMaxApps    = 3
	StarterMaxDomains = 3
)
