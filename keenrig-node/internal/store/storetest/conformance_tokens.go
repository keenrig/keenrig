package storetest

// Conformance cho api_tokens (ID-04). Ở đây chỉ kiểm HỢP ĐỒNG TẦNG LƯU TRỮ —
// hạn lọc trong SQL, thu hồi xoá thật, không đọc chéo giữa hai user. Luật
// nghiệp vụ (scope là tập con, so khớp CIDR) thuộc internal/identity và được
// kiểm ở đó.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

func mustUser(t *testing.T, st store.Store, id, name string) *store.User {
	t.Helper()
	u := &store.User{ID: id, Username: name, PasswordHash: "x", Scopes: []string{"apps:read"}}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser(%s): %v", id, err)
	}
	return u
}

func mustToken(t *testing.T, st store.Store, hash, id, userID string, ttl time.Duration) *store.APIToken {
	t.Helper()
	tok := &store.APIToken{
		TokenHash: hash, ID: id, UserID: userID, Name: "ci",
		Scopes: []string{"apps:read"}, ExpiresAt: time.Now().Add(ttl),
	}
	if err := st.CreateAPIToken(context.Background(), tok); err != nil {
		t.Fatalf("CreateAPIToken(%s): %v", id, err)
	}
	return tok
}

func testAPITokenLifecycle(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustUser(t, st, "u1", "alice")
	mustToken(t, st, "hash-1", "tok-1", "u1", time.Hour)

	got, err := st.GetAPIToken(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetAPIToken: %v", err)
	}
	if got.ID != "tok-1" || got.UserID != "u1" || got.Name != "ci" {
		t.Errorf("token = %+v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "apps:read" {
		t.Errorf("scopes = %v", got.Scopes)
	}
	// Chưa dùng lần nào: LastUsedAt phải là nil, không phải zero-time đội lốt.
	// Phân biệt được "chưa dùng" với "dùng lúc năm 0001" là điều kiện để trả
	// lời "token này còn ai xài không" trước khi thu hồi.
	if got.LastUsedAt != nil {
		t.Errorf("LastUsedAt = %v, muốn nil khi chưa dùng", got.LastUsedAt)
	}

	if err := st.TouchAPIToken(ctx, "hash-1", "203.0.113.9"); err != nil {
		t.Fatalf("TouchAPIToken: %v", err)
	}
	got, _ = st.GetAPIToken(ctx, "hash-1")
	if got.LastUsedAt == nil || got.LastUsedIP != "203.0.113.9" {
		t.Errorf("sau Touch: LastUsedAt=%v IP=%q", got.LastUsedAt, got.LastUsedIP)
	}

	// Thu hồi xoá THẬT.
	if err := st.DeleteAPIToken(ctx, "u1", "tok-1"); err != nil {
		t.Fatalf("DeleteAPIToken: %v", err)
	}
	if _, err := st.GetAPIToken(ctx, "hash-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("sau thu hồi: err = %v, muốn ErrNotFound", err)
	}
	if err := st.DeleteAPIToken(ctx, "u1", "tok-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("thu hồi lần hai: err = %v, muốn ErrNotFound", err)
	}
}

// Hạn phải lọc TRONG SQL. Lọc ở Go nghĩa là mỗi đường đọc phải tự nhớ so sánh,
// và chỗ nào quên là một token chết vẫn gọi được API.
func testAPITokenExpiryFilteredInSQL(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustUser(t, st, "u1", "alice")
	mustToken(t, st, "hash-live", "tok-live", "u1", time.Hour)
	mustToken(t, st, "hash-dead", "tok-dead", "u1", -time.Hour) // đã hết hạn

	if _, err := st.GetAPIToken(ctx, "hash-live"); err != nil {
		t.Errorf("token còn hạn: %v", err)
	}
	if _, err := st.GetAPIToken(ctx, "hash-dead"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token hết hạn: err = %v, muốn ErrNotFound", err)
	}

	// Nhưng LIST vẫn phải thấy nó — người vận hành cần dọn được thứ đã chết,
	// và cần thấy nó đã chết chứ không phải thấy nó biến mất.
	list, err := st.ListAPITokens(ctx, "u1")
	if err != nil {
		t.Fatalf("ListAPITokens: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List trả %d token, muốn 2 (kể cả đã hết hạn)", len(list))
	}

	n, err := st.PurgeExpiredAPITokens(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PurgeExpiredAPITokens = %d, %v; muốn 1, nil", n, err)
	}
	if list, _ = st.ListAPITokens(ctx, "u1"); len(list) != 1 {
		t.Errorf("sau purge còn %d token, muốn 1", len(list))
	}
}

// Một user KHÔNG thu hồi được token của người khác chỉ vì đoán trúng id.
// Ràng buộc này phải nằm trong CÂU TRUY VẤN, vì tầng service có thể quên.
func testAPITokenIsolationBetweenUsers(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustUser(t, st, "u1", "alice")
	mustUser(t, st, "u2", "mallory")
	mustToken(t, st, "hash-1", "tok-1", "u1", time.Hour)

	if err := st.DeleteAPIToken(ctx, "u2", "tok-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("u2 thu hồi được token của u1: err = %v", err)
	}
	if _, err := st.GetAPIToken(ctx, "hash-1"); err != nil {
		t.Errorf("token của u1 bị ảnh hưởng: %v", err)
	}

	list, _ := st.ListAPITokens(ctx, "u2")
	if len(list) != 0 {
		t.Errorf("u2 thấy %d token của người khác", len(list))
	}
}

// Xoá user phải kéo theo token (ON DELETE CASCADE), và token của user không
// tồn tại phải bị từ chối ngay lúc tạo — không có token mồ côi.
func testAPITokenForeignKey(t *testing.T, st store.Store) {
	ctx := context.Background()
	tok := &store.APIToken{
		TokenHash: "h", ID: "t", UserID: "không-có-user",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := st.CreateAPIToken(ctx, tok); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("tạo token cho user không tồn tại: err = %v, muốn ErrNotFound", err)
	}
}
