package storetest

// Conformance ID-01 — hai bảng OIDC.
//
// Ba khẳng định ở đây là khẳng định về TẦNG LƯU TRỮ, không phải về giao thức, và
// vì thế chúng thuộc suite dùng chung: một implementation Store thứ hai (Postgres
// cho HA ở M6) phải giữ đúng cả ba, nếu không thì đăng nhập SSO hỏng theo cách
// chỉ lộ ra dưới tải.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// mustOIDCUser tạo một user để mã uỷ quyền có chỗ trỏ tới (FK).
func mustOIDCUser(t *testing.T, st store.Store, id string) *store.User {
	t.Helper()
	u := &store.User{ID: id, Username: id, PasswordHash: "x", Scopes: []string{"apps:read"}}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func mustOIDCClient(t *testing.T, st store.Store, id string) *store.OIDCClient {
	t.Helper()
	c := &store.OIDCClient{
		ClientID: id, Name: id, SecretRef: "oidc/client/" + id,
		RedirectURIs: []string{"https://" + id + ".example.com/cb"},
	}
	if err := st.PutOIDCClient(context.Background(), c); err != nil {
		t.Fatalf("PutOIDCClient: %v", err)
	}
	return c
}

func testOIDCClientCRUD(t *testing.T, st store.Store) {
	ctx := context.Background()
	c := mustOIDCClient(t, st, "app-one")

	got, err := st.GetOIDCClient(ctx, "app-one")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if got.SecretRef != c.SecretRef || len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != c.RedirectURIs[0] {
		t.Errorf("đọc lại KHÁC lúc ghi: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("thiếu mốc thời gian")
	}

	// Upsert: đổi danh sách redirect_uri phải THAY nguyên khối, không phải nối
	// thêm. Nối thêm nghĩa là một URI đã bị gỡ vẫn nhận được mã uỷ quyền.
	c.RedirectURIs = []string{"https://app-one.example.com/new"}
	if err := st.PutOIDCClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetOIDCClient(ctx, "app-one")
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app-one.example.com/new" {
		t.Errorf("upsert nối thêm thay vì thay: %v", got.RedirectURIs)
	}

	mustOIDCClient(t, st, "app-two")
	list, err := st.ListOIDCClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) < 2 || list[0].ClientID > list[1].ClientID {
		t.Errorf("ListOIDCClients không sắp thứ tự hoặc thiếu: %d", len(list))
	}

	if err := st.DeleteOIDCClient(ctx, "app-two"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetOIDCClient(ctx, "app-two"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("sau khi xoá vẫn đọc được: %v", err)
	}
	if err := st.DeleteOIDCClient(ctx, "app-two"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("xoá lần hai = %v, muốn ErrNotFound", err)
	}
}

// Mã uỷ quyền dùng ĐÚNG MỘT LẦN, kể cả khi N tiến trình đổi cùng lúc.
//
// # Đây là khẳng định quan trọng nhất của cả file
//
// Nếu ConsumeOIDCCode được hiện thực bằng SELECT rồi DELETE, test này XANH khi
// chạy tuần tự và ĐỎ dưới tải — nghĩa là nó chỉ hỏng trên máy thật, vào lúc có
// người dùng thật. Ở đây 16 goroutine cùng đổi một mã, và đúng MỘT được phép
// thắng.
func testOIDCCodeSingleUseUnderConcurrency(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustOIDCUser(t, st, "user-sso")
	mustOIDCClient(t, st, "app-race")

	const hash = "hash-cua-ma-uy-quyen"
	if err := st.CreateOIDCCode(ctx, &store.OIDCCode{
		CodeHash: hash, ClientID: "app-race", UserID: "user-sso",
		RedirectURI: "https://app-race.example.com/cb", Scope: "openid",
		CodeChallenge: "challenge", AuthTime: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateOIDCCode: %v", err)
	}

	const n = 16
	wins := make(chan *store.OIDCCode, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // cùng vạch xuất phát, để cửa sổ tranh chấp rộng nhất
			rec, err := st.ConsumeOIDCCode(ctx, hash)
			if err == nil {
				wins <- rec
			}
		}()
	}
	close(start)
	wg.Wait()
	close(wins)

	got := 0
	for rec := range wins {
		got++
		if rec.UserID != "user-sso" || rec.CodeChallenge != "challenge" {
			t.Errorf("bản ghi trả về thiếu dữ liệu: %+v", rec)
		}
	}
	if got != 1 {
		t.Fatalf("%d trong %d lần đổi cùng lúc THÀNH CÔNG, phải đúng 1.\n"+
			"Một mã uỷ quyền dùng được nhiều lần là nhiều phiên đăng nhập mạo danh.", got, n)
	}
}

// Mã HẾT HẠN không được trả về, và cũng KHÔNG được nằm lại làm rác.
func testOIDCCodeExpiry(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustOIDCUser(t, st, "user-exp")
	mustOIDCClient(t, st, "app-exp")

	dead := &store.OIDCCode{
		CodeHash: "ma-da-chet", ClientID: "app-exp", UserID: "user-exp",
		RedirectURI: "https://app-exp.example.com/cb", CodeChallenge: "c",
		AuthTime:  time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := st.CreateOIDCCode(ctx, dead); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeOIDCCode(ctx, "ma-da-chet"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("mã hết hạn vẫn đổi được: %v", err)
	}
	// Và nó đã bị XOÁ trong cùng lần gọi đó: lần Purge sau không còn gì để dọn.
	if _, err := st.ConsumeOIDCCode(ctx, "ma-da-chet"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("lần hai = %v", err)
	}

	alive := &store.OIDCCode{
		CodeHash: "ma-con-song", ClientID: "app-exp", UserID: "user-exp",
		RedirectURI: "https://app-exp.example.com/cb", CodeChallenge: "c",
		AuthTime:  time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := st.CreateOIDCCode(ctx, alive); err != nil {
		t.Fatal(err)
	}
	// Purge KHÔNG được đụng vào mã còn sống — dọn rác mà xoá luôn mã đang dùng
	// nghĩa là mọi lần đăng nhập trùng thời điểm dọn đều thất bại.
	if _, err := st.PurgeExpiredOIDCCodes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeOIDCCode(ctx, "ma-con-song"); err != nil {
		t.Errorf("Purge xoá mất mã CÒN SỐNG: %v", err)
	}
}

// Mã trỏ tới client hoặc user không tồn tại phải bị TỪ CHỐI ở tầng DB.
//
// Không có FK thì một mã mồ côi vẫn đổi được token — mang danh tính một user đã
// bị xoá, cho một app đã bị gỡ.
func testOIDCCodeForeignKeys(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustOIDCUser(t, st, "user-fk")
	mustOIDCClient(t, st, "app-fk")
	base := store.OIDCCode{
		RedirectURI: "https://app-fk.example.com/cb", CodeChallenge: "c",
		AuthTime: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}

	noClient := base
	noClient.CodeHash, noClient.ClientID, noClient.UserID = "h1", "app-khong-co", "user-fk"
	if err := st.CreateOIDCCode(ctx, &noClient); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("mã cho client không tồn tại = %v, muốn ErrNotFound", err)
	}

	noUser := base
	noUser.CodeHash, noUser.ClientID, noUser.UserID = "h2", "app-fk", "user-khong-co"
	if err := st.CreateOIDCCode(ctx, &noUser); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("mã cho user không tồn tại = %v, muốn ErrNotFound", err)
	}

	// Xoá client phải CASCADE xuống mã của nó: một mã mồ côi là một phiên đăng
	// nhập cho một app không còn tồn tại.
	ok := base
	ok.CodeHash, ok.ClientID, ok.UserID = "h3", "app-fk", "user-fk"
	if err := st.CreateOIDCCode(ctx, &ok); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteOIDCClient(ctx, "app-fk"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeOIDCCode(ctx, "h3"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("gỡ client mà mã của nó còn dùng được: %v", err)
	}
}
