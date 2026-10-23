package reconciler

// Test tầng NỐI addon vào vòng hội tụ. Không cần Docker: driver thật đã có
// conformance riêng trên PostgreSQL/Redis thật. Ở đây kiểm những điều chỉ tầng
// nối hỏng được — thứ tự, ai thắng khi trùng biến, và ai được đánh dấu lỗi.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

type fakeProv struct {
	mu       sync.Mutex
	setups   []string // "<kind>/<app>"
	teardown []string
	env      map[addons.Kind]map[string]string
	setupErr error
}

func (f *fakeProv) Setup(_ context.Context, k addons.Kind, appID string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setups = append(f.setups, string(k)+"/"+appID)
	if f.setupErr != nil {
		return nil, f.setupErr
	}
	if e, ok := f.env[k]; ok {
		return e, nil
	}
	return map[string]string{"KEENRIG_" + upper(string(k)) + "_URL": "x://" + appID}, nil
}

func (f *fakeProv) Teardown(_ context.Context, k addons.Kind, appID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.teardown = append(f.teardown, string(k)+"/"+appID)
	return nil
}

func (f *fakeProv) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.setups...)
}

func (f *fakeProv) tornDown() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.teardown...)
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func sha64() string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}

func desiredWith(on ...addons.Kind) contracts.DesiredApp {
	d := contracts.DesiredApp{Image: "nginx@sha256:" + sha64(), Addons: &contracts.Addons{}}
	for _, k := range on {
		switch k {
		case addons.KindPostgres:
			d.Addons.Postgres = &contracts.AddonSpec{Enabled: true}
		case addons.KindRedis:
			d.Addons.Redis = &contracts.AddonSpec{Enabled: true}
		}
	}
	return d
}

// Biến của NGƯỜI DÙNG thắng biến của addon.
//
// Ngược lại nghe an toàn hơn nhưng sai: người vận hành trỏ app sang một
// PostgreSQL bên ngoài bằng KEENRIG_POSTGRES_URL của họ phải làm được, và nếu
// addon ghi đè thì họ không có cách nào — kể cả tắt addon, vì lúc đó biến biến
// mất hoàn toàn thay vì mang giá trị họ đặt.
func TestUserEnvBeatsAddonEnv(t *testing.T) {
	d := contracts.DesiredApp{Env: map[string]string{"KEENRIG_POSTGRES_URL": "cua-toi"}}
	got := injectAddonEnv(d, map[string]string{
		"KEENRIG_POSTGRES_URL":  "cua-addon",
		"KEENRIG_POSTGRES_HOST": "postgres",
	})
	if got.Env["KEENRIG_POSTGRES_URL"] != "cua-toi" {
		t.Errorf("URL = %q, muốn giá trị người dùng đặt", got.Env["KEENRIG_POSTGRES_URL"])
	}
	if got.Env["KEENRIG_POSTGRES_HOST"] != "postgres" {
		t.Errorf("biến addon không bị ghi đè lại bị mất: %v", got.Env)
	}
}

// injectAddonEnv trả BẢN SAO. Sửa tại chỗ nghĩa là bộ biến addon lọt vào thứ ta
// so sánh để biết "desired có đổi không", và mọi tick sẽ thấy một desired khác.
func TestInjectDoesNotMutateInput(t *testing.T) {
	d := contracts.DesiredApp{Env: map[string]string{"A": "1"}}
	injectAddonEnv(d, map[string]string{"KEENRIG_REDIS_URL": "x"})
	if len(d.Env) != 1 {
		t.Errorf("desired gốc bị sửa: %v", d.Env)
	}
}

func TestWantedAddonsIsStable(t *testing.T) {
	d := desiredWith(addons.KindRedis, addons.KindPostgres)
	first := wantedAddons(d)
	for i := 0; i < 10; i++ {
		got := wantedAddons(d)
		if len(got) != len(first) {
			t.Fatalf("độ dài đổi giữa các lần gọi")
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("thứ tự đổi: %v vs %v", got, first)
			}
		}
	}
	if len(first) != 2 {
		t.Fatalf("= %v, muốn 2 addon", first)
	}
	// Không khai addon nào → nil, không phải slice rỗng có cấp phát.
	if got := wantedAddons(contracts.DesiredApp{}); got != nil {
		t.Errorf("desired không có addon → %v, muốn nil", got)
	}
}

// ErrInfraNotReady là CHƯA XONG, không phải HỎNG: app phải BACKOFF, KHÔNG bị
// đánh dấu error.
//
// postgres mất tới một phút để initdb lần đầu, nên đánh dấu lỗi ở đây làm mọi
// app đầu tiên trên máy mới vào trạng thái error rồi tự khỏi — một cảnh báo giả
// mà người vận hành sẽ học cách phớt lờ.
func TestInfraNotReadyBackoffsInsteadOfFailing(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	prov := &fakeProv{setupErr: addons.ErrInfraNotReady}

	raw, _ := json.Marshal(desiredWith(addons.KindPostgres))
	app := &store.App{ID: "app-addon", Slug: "app-addon", Desired: raw}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}

	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-addon"}).
		WithAddons(prov)
	_, stop := runReconciler(t, r)
	defer stop()

	deadline := time.Now().Add(3 * time.Second)
	for len(prov.list()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(prov.list()) == 0 {
		t.Fatal("không có lần Setup nào")
	}

	got, err := st.GetApp(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	var status contracts.AppStatus
	if len(got.Status) > 0 {
		_ = json.Unmarshal(got.Status, &status)
	}
	if status.State == contracts.AppStateError {
		t.Errorf("ErrInfraNotReady làm app vào trạng thái error — nó là chưa xong, "+
			"không phải hỏng: %+v", status)
	}
}

// Lỗi THẬT của addon thì app PHẢI để lại dấu vết — nếu không thì một cấu hình
// addon sai im lặng và app chạy thiếu DB.
func TestRealAddonErrorLeavesTrace(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	prov := &fakeProv{setupErr: errors.New("mat khau superuser sai")}

	raw, _ := json.Marshal(desiredWith(addons.KindPostgres))
	app := &store.App{ID: "app-loi", Slug: "app-loi", Desired: raw}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}

	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-addon"}).
		WithAddons(prov)
	_, stop := runReconciler(t, r)
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := st.GetApp(ctx, app.ID)
		if err == nil && len(got.Status) > 0 {
			var status contracts.AppStatus
			_ = json.Unmarshal(got.Status, &status)
			if status.State == contracts.AppStateError {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := st.GetApp(ctx, app.ID)
	t.Errorf("lỗi addon thật không đưa app vào trạng thái error; status = %s", got.Status)
}

// Tầng addon TẮT (nil) không được làm app không deploy được — nhưng phải KÊU TO.
func TestNilProvisionerIsLoudNotFatal(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	raw, _ := json.Marshal(desiredWith(addons.KindRedis))
	app := &store.App{ID: "app-khong-prov", Slug: "app-khong-prov", Desired: raw}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}

	// KHÔNG gọi WithAddons.
	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-addon"})
	_, stop := runReconciler(t, r)
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasEvent(t, st, "app.addons_unavailable", app.ID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("không có event app.addons_unavailable — app deploy thiếu biến kết " +
		"nối một cách IM LẶNG, và người dùng sẽ đi tìm lỗi trong app của họ")
}

// Teardown dọn theo BẢNG app_addons, không theo desired.
//
// desired có thể đã bị sửa để tắt addon TRƯỚC khi app bị xoá — lúc đó DB vẫn còn
// nhưng không ai biết. Bảng là nguồn sự thật về đã cấp phát cái gì.
func TestTeardownFollowsTableNotDesired(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	prov := &fakeProv{}

	// desired KHÔNG khai addon nào...
	raw, _ := json.Marshal(contracts.DesiredApp{Image: "nginx@sha256:" + sha64()})
	app := &store.App{ID: "app-tat-addon", Slug: "app-tat-addon", Desired: raw}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}
	// ...nhưng bảng app_addons NÓI đã cấp phát postgres.
	if err := st.PutAppAddon(ctx, &store.AppAddon{
		AppID: app.ID, Addon: string(addons.KindPostgres), State: store.AddonReady,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteApp(ctx, app.ID); err != nil {
		t.Fatal(err)
	}

	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-addon"}).
		WithAddons(prov)
	_, stop := runReconciler(t, r)
	defer stop()

	waitPurged(t, st, 5*time.Second)
	got := prov.tornDown()
	if len(got) != 1 || got[0] != "postgres/"+app.ID {
		t.Errorf("Teardown gọi với %v, muốn [postgres/%s] — dọn theo desired thay "+
			"vì theo bảng nghĩa là DB sót lại mà không ai biết", got, app.ID)
	}
}

// Addon được cấp phát TRƯỚC khi container được tạo, và biến ĐI VÀO container.
//
// Đảo thứ tự thì container khởi động thiếu biến kết nối, app chết vì thiếu cấu
// hình, và triệu chứng nằm trong log của APP chứ không của ta.
func TestAddonEnvReachesRuntime(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	prov := &fakeProv{env: map[addons.Kind]map[string]string{
		addons.KindPostgres: {"KEENRIG_POSTGRES_URL": "postgres://x"},
	}}
	rt := newFakeRuntime()

	raw, _ := json.Marshal(desiredWith(addons.KindPostgres))
	app := &store.App{ID: "app-env", Slug: "app-env", Desired: raw}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}

	r := New(st, rt, Options{Interval: 20 * time.Millisecond, Holder: "box-addon"}).
		WithAddons(prov)
	_, stop := runReconciler(t, r)
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if spec, ok := rt.lastSpec(app.ID); ok {
			if spec.Desired.Env["KEENRIG_POSTGRES_URL"] != "postgres://x" {
				t.Fatalf("container nhận Env = %v — biến addon KHÔNG tới runtime",
					spec.Desired.Env)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("runtime.Apply chưa được gọi")
}

// AD-03, mệnh đề thứ hai: MẬT KHẨU KHÔNG NẰM TRONG CỘT `desired`.
//
// # Vì sao đây là một test riêng, không phải hệ quả của TestInjectDoesNotMutateInput
//
// Test kia kiểm một hàm: injectAddonEnv trả bản sao. Test này kiểm một TÍNH CHẤT
// CỦA HỆ THỐNG: sau khi hội tụ xong, mật khẩu không có mặt ở bất cứ chỗ nào bền
// vững mà không được mã hoá. Hai điều đó khác nhau vì tính chất kia còn có thể
// hỏng theo những cách không đi qua injectAddonEnv — ai đó thêm một
// `UpdateDesired` vào reconciler để "lưu lại bộ biến đã tính", hoặc ghi desired
// vào payload của một event để dễ debug.
//
// Hiện tại tính chất này đúng vì một lý do cấu trúc: reconciler KHÔNG BAO GIỜ gọi
// UpdateDesired — chỉ API gọi, từ PATCH của người dùng. Lý do cấu trúc là lý do
// tốt, nhưng nó không tự canh mình.
//
// # Vì sao quét cả status và event, không chỉ desired
//
// TESTCASES chỉ nói "cột desired", nhưng cột đó không đặc biệt — nó chỉ là chỗ
// đầu tiên người ta nghĩ tới. `status` cũng là JSON do reconciler ghi mỗi tick,
// và payload event là chỗ thông tin gỡ lỗi hay bị nhét vào. Một mật khẩu trong
// bảng `events` rò rỉ đúng bằng một mật khẩu trong `apps`, và tệ hơn ở một điểm:
// event được thiết kế để đọc và xuất ra ngoài.
func TestAddonPasswordNeverReachesDesiredColumn(t *testing.T) {
	const pw = "mat-khau-khong-duoc-ro-ri-9f3a"

	st := openStore(t)
	ctx := context.Background()
	prov := &fakeProv{env: map[addons.Kind]map[string]string{
		addons.KindPostgres: {
			"KEENRIG_POSTGRES_URL":      "postgres://app_x:" + pw + "@postgres:5432/app_x",
			"KEENRIG_POSTGRES_PASSWORD": pw,
		},
	}}
	rt := newFakeRuntime()

	raw, _ := json.Marshal(desiredWith(addons.KindPostgres))
	app := &store.App{ID: "app-pw", Slug: "app-pw", Desired: raw}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}

	r := New(st, rt, Options{Interval: 20 * time.Millisecond, Holder: "box-pw"}).
		WithAddons(prov)
	_, stop := runReconciler(t, r)
	defer stop()

	// Chờ hội tụ THẬT rồi mới quét: quét trước khi Apply chạy thì test xanh vì
	// chưa có gì xảy ra, chứ không vì hệ thống đúng.
	waitFor(t, 5*time.Second, "container nhận biến addon", func() bool {
		spec, ok := rt.lastSpec(app.ID)
		return ok && spec.Desired.Env["KEENRIG_POSTGRES_PASSWORD"] == pw
	})

	// Điều kiện tiên quyết: mật khẩu THẬT SỰ đã tới container. Không có bước này
	// thì mọi khẳng định "không thấy mật khẩu ở đâu" đều thoả một cách tầm thường.
	if spec, _ := rt.lastSpec(app.ID); spec.Desired.Env["KEENRIG_POSTGRES_PASSWORD"] != pw {
		t.Fatal("mật khẩu chưa tới container — test không kiểm được gì")
	}

	got := getApp(t, st, app.ID)
	if bytes.Contains(got.Desired, []byte(pw)) {
		t.Errorf("cột desired chứa mật khẩu addon:\n%s", got.Desired)
	}
	if bytes.Contains(got.Status, []byte(pw)) {
		t.Errorf("cột status chứa mật khẩu addon:\n%s", got.Status)
	}

	// desired sau hội tụ phải GIỐNG NGUYÊN bản người dùng gửi. Khác đi — kể cả
	// không chứa mật khẩu — nghĩa là reconciler đang ghi lại desired, và mỗi tick
	// sẽ thấy một desired mới: hội tụ không bao giờ dừng.
	if !bytes.Equal(got.Desired, raw) {
		t.Errorf("reconciler đã sửa cột desired\ntrước: %s\nsau:   %s", raw, got.Desired)
	}

	evs, err := st.ListEvents(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if bytes.Contains(e.Data, []byte(pw)) {
			t.Errorf("event %q chứa mật khẩu addon: %s", e.Action, e.Data)
		}
	}

	recs, err := st.ListAppAddons(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("không có bản ghi app_addons — reconciler chưa ghi sổ")
	}
	for _, rec := range recs {
		if rec.ConfigRef == pw || rec.LastError == pw {
			t.Errorf("app_addons chứa mật khẩu: %+v", rec)
		}
	}
}
