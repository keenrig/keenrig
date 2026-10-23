package authz

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// SecretBootstrapToken — ref của token quản trị khởi tạo trong bảng secrets.
//
// Nằm trong SECRETS (mã hoá bằng master.key) chứ không phải settings: settings
// bị đọc bởi mọi đường liệt kê cấu hình, còn đây là thứ mở toàn quyền instance.
const SecretBootstrapToken = "auth/bootstrap-token"

// BootstrapAuth — xác thực bằng một bearer token duy nhất, scope admin.
//
// Đây là cầu tạm cho tới T10 (login + session + TOTP), KHÔNG phải mô hình cuối:
// một token bất biến không thu hồi được từng phần và không gắn với người dùng
// nào. Nó tồn tại vì lựa chọn còn lại tệ hơn nhiều — để /api/v1 mở toang trong
// suốt quãng T7→T10.
//
// So sánh bằng subtle.ConstantTimeCompare: so sánh chuỗi thường thoát sớm ở byte
// đầu khác nhau, đủ để dò dần từng byte token qua thời gian phản hồi.
type BootstrapAuth struct {
	token []byte
}

var _ Authenticator = (*BootstrapAuth)(nil)

// LoadOrCreateBootstrap đọc token trong store, chưa có thì sinh mới.
//
// Trả thêm `created` để main biết đây là lần đầu và IN token ra log — token
// sinh ra mà không ai đọc được thì instance tự khoá chính nó.
func LoadOrCreateBootstrap(ctx context.Context, st store.Store) (*BootstrapAuth, string, bool, error) {
	raw, err := st.GetSecret(ctx, SecretBootstrapToken)
	if err == nil && len(raw) > 0 {
		return &BootstrapAuth{token: raw}, string(raw), false, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, "", false, err
	}

	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", false, err
	}
	tok := []byte(base64.RawURLEncoding.EncodeToString(b[:]))
	if err := st.PutSecret(ctx, SecretBootstrapToken, tok); err != nil {
		return nil, "", false, err
	}
	return &BootstrapAuth{token: tok}, string(tok), true, nil
}

func (a *BootstrapAuth) Authenticate(r *http.Request) (Principal, error) {
	got := BearerToken(r)
	if got == "" {
		return Principal{}, ErrUnauthenticated
	}
	// So sánh độ dài TRƯỚC bằng một phép không rẽ nhánh theo nội dung: khác độ
	// dài thì ConstantTimeCompare trả 0 ngay, nên vẫn cần chặn ở đây để không
	// vô tình so sánh slice lệch kích thước.
	if subtle.ConstantTimeCompare([]byte(got), a.token) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Subject: "bootstrap", Scopes: []Scope{ScopeAdmin}}, nil
}
