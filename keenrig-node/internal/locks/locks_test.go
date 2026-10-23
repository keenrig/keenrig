package locks_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/locks"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

func openStore(t *testing.T) store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// Ma trận: cặp nào ĐƯỢC chạy song song, cặp nào KHÔNG.
//
// Đây là bảng quan trọng nhất của package. Mỗi ô sai là một cặp thao tác chồng
// nhau trong sản xuất, và loại lỗi đó chỉ lộ ra khi khách chạy backup đúng lúc
// hệ thống tự cập nhật — tức là hiếm, và tệ.
func TestCompatibilityMatrix(t *testing.T) {
	cases := []struct {
		first, second string
		canCoRun      bool
		why           string
	}{
		// Update box chặn tất cả.
		{locks.BoxUpdate, locks.FullBackup, false, "backup trong lúc thay bin sẽ chụp trạng thái nửa vời"},
		{locks.BoxUpdate, locks.AppTask("a"), false, "cài app trong lúc thay bin"},
		{locks.BoxUpdate, locks.AppBackup("a"), false, "backup app trong lúc thay bin"},
		{locks.BoxUpdate, locks.BoxUpdate, false, "hai lần update cùng lúc"},
		{locks.BoxUpdate, locks.RuntimeMigrate, false, "đổi runtime trong lúc thay bin"},

		// Full backup chặn thao tác app nhưng KHÔNG chặn backup từng app.
		{locks.FullBackup, locks.AppTask("a"), false, "app đang cài dở sẽ vào bản backup"},
		{locks.FullBackup, locks.FullBackup, false, "hai full backup cùng lúc"},

		// Hai app KHÁC NHAU chạy song song được — đó là lý do khoá mang id app.
		{locks.AppTask("a"), locks.AppTask("b"), true, "hai app độc lập"},
		{locks.AppBackup("a"), locks.AppBackup("b"), true, "backup hai app độc lập"},
		{locks.AppTask("a"), locks.AppBackup("b"), true, "thao tác app A, backup app B"},

		// Cùng một app thì không.
		{locks.AppTask("a"), locks.AppTask("a"), false, "hai thao tác trên cùng app"},
		{locks.AppBackup("a"), locks.AppBackup("a"), false, "hai backup cùng app"},
	}

	for _, c := range cases {
		st := openStore(t)
		ctx := context.Background()
		m1 := locks.New(st, "chu-1", time.Minute)
		m2 := locks.New(st, "chu-2", time.Minute)

		if err := m1.Acquire(ctx, c.first, "test"); err != nil {
			t.Fatalf("giành %q lần đầu: %v", c.first, err)
		}
		err := m2.Acquire(ctx, c.second, "test")
		got := err == nil
		if got != c.canCoRun {
			t.Errorf("%q + %q: chạy song song = %v, muốn %v (%s) — err: %v",
				c.first, c.second, got, c.canCoRun, c.why, err)
		}
		if !c.canCoRun && !errors.Is(err, locks.ErrBusy) {
			t.Errorf("%q + %q: err = %v, muốn ErrBusy", c.first, c.second, err)
		}
	}
}

// Xung khắc phải ĐỐI XỨNG: A chặn B thì B cũng phải chặn A. Bảng bất đối xứng
// nghĩa là thứ tự đến quyết định ai thắng, và đó là một cuộc đua chứ không phải
// một quy tắc.
func TestMatrixIsSymmetric(t *testing.T) {
	names := []string{
		locks.BoxUpdate, locks.FullBackup, locks.RuntimeMigrate,
		locks.AppTask("a"), locks.AppBackup("a"),
	}
	for _, a := range names {
		for _, b := range names {
			st := openStore(t)
			ctx := context.Background()
			ma := locks.New(st, "A", time.Minute)
			mb := locks.New(st, "B", time.Minute)

			if err := ma.Acquire(ctx, a, ""); err != nil {
				t.Fatalf("giành %q: %v", a, err)
			}
			abBlocked := mb.Acquire(ctx, b, "") != nil

			st2 := openStore(t)
			ma2 := locks.New(st2, "A", time.Minute)
			mb2 := locks.New(st2, "B", time.Minute)
			if err := mb2.Acquire(ctx, b, ""); err != nil {
				t.Fatalf("giành %q: %v", b, err)
			}
			baBlocked := ma2.Acquire(ctx, a, "") != nil

			if abBlocked != baBlocked {
				t.Errorf("bất đối xứng: %q trước %q → chặn=%v, nhưng ngược lại → chặn=%v",
					a, b, abBlocked, baBlocked)
			}
		}
	}
}

// Thông báo lỗi phải nói RÕ cái gì đang chặn — "hệ thống bận" là câu vô dụng.
func TestErrorNamesTheBlocker(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m1 := locks.New(st, "box-A", time.Minute)
	m2 := locks.New(st, "box-B", time.Minute)

	if err := m1.Acquire(ctx, locks.BoxUpdate, "cập nhật lên 1.2.3"); err != nil {
		t.Fatal(err)
	}
	err := m2.Acquire(ctx, locks.FullBackup, "backup hằng đêm")
	if err == nil {
		t.Fatal("backup không bị chặn")
	}
	for _, want := range []string{locks.BoxUpdate, "box-A", "cập nhật lên 1.2.3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("thông báo thiếu %q: %v", want, err)
		}
	}
}

// Chủ giành lại khoá của CHÍNH MÌNH = gia hạn, không phải xung khắc.
func TestReacquireOwnLockRenews(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m := locks.New(st, "box-A", time.Minute)

	if err := m.Acquire(ctx, locks.FullBackup, "lần 1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Acquire(ctx, locks.FullBackup, "gia hạn"); err != nil {
		t.Errorf("gia hạn khoá của chính mình bị từ chối: %v", err)
	}
}

func TestReleaseAndOwnership(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m1 := locks.New(st, "box-A", time.Minute)
	m2 := locks.New(st, "box-B", time.Minute)

	if err := m1.Acquire(ctx, locks.FullBackup, ""); err != nil {
		t.Fatal(err)
	}
	// Nhả khoá của người khác phải bị TỪ CHỐI: chủ cũ tỉnh dậy và "dọn dẹp"
	// đúng lúc chủ mới đang làm việc là kịch bản thật.
	if err := m2.Release(ctx, locks.FullBackup); !errors.Is(err, locks.ErrNotHeld) {
		t.Errorf("nhả khoá người khác = %v, muốn ErrNotHeld", err)
	}
	if err := m1.Release(ctx, locks.FullBackup); err != nil {
		t.Fatalf("nhả khoá của mình: %v", err)
	}
	// Nhả hai lần không phải lỗi.
	if err := m1.Release(ctx, locks.FullBackup); err != nil {
		t.Errorf("nhả lần 2: %v", err)
	}
	// Nhả rồi thì người khác vào được.
	if err := m2.Acquire(ctx, locks.FullBackup, ""); err != nil {
		t.Errorf("sau khi nhả vẫn bị chặn: %v", err)
	}
}

// Khoá hết hạn không được chặn ai — đây là hàng rào cho tiến trình chết giữa chừng.
func TestExpiredLockDoesNotBlock(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	// TTL 1 giây: cột expires_at có độ phân giải giây.
	dead := locks.New(st, "box-đã-chết", time.Second)
	if err := dead.Acquire(ctx, locks.FullBackup, ""); err != nil {
		t.Fatal(err)
	}

	live := locks.New(st, "box-B", time.Minute)
	if err := live.Acquire(ctx, locks.FullBackup, ""); !errors.Is(err, locks.ErrBusy) {
		t.Fatalf("trước khi hết hạn = %v, muốn ErrBusy", err)
	}
	time.Sleep(2100 * time.Millisecond)
	if err := live.Acquire(ctx, locks.FullBackup, ""); err != nil {
		t.Errorf("khoá đã hết hạn vẫn chặn: %v", err)
	}
}

// WithLock luôn nhả, kể cả khi fn trả lỗi hoặc PANIC — đó là lý do nó tồn tại.
func TestWithLockAlwaysReleases(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m := locks.New(st, "box-A", time.Minute)
	other := locks.New(st, "box-B", time.Minute)

	wantErr := errors.New("job hỏng")
	if err := m.WithLock(ctx, locks.FullBackup, "", func(context.Context) error {
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Errorf("WithLock nuốt lỗi của fn: %v", err)
	}
	if err := other.Acquire(ctx, locks.FullBackup, ""); err != nil {
		t.Fatalf("khoá không được nhả sau khi fn lỗi: %v", err)
	}
	_ = other.Release(ctx, locks.FullBackup)

	func() {
		defer func() { _ = recover() }()
		_ = m.WithLock(ctx, locks.FullBackup, "", func(context.Context) error {
			panic("nổ giữa chừng")
		})
	}()
	if err := other.Acquire(ctx, locks.FullBackup, ""); err != nil {
		t.Errorf("khoá không được nhả sau panic: %v", err)
	}
}

// ReleaseAll dọn mọi khoá của một chủ — dùng ở cuối job để bắt đường thoát quên nhả.
func TestReleaseAll(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m := locks.New(st, "job-42", time.Minute)

	for _, n := range []string{locks.AppTask("a"), locks.AppBackup("b")} {
		if err := m.Acquire(ctx, n, ""); err != nil {
			t.Fatalf("giành %q: %v", n, err)
		}
	}
	m.ReleaseAll(ctx)

	held, err := st.ListLocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 0 {
		t.Errorf("còn %d khoá sau ReleaseAll", len(held))
	}
}

// Blocking trả đúng thứ đang chặn — cho API "vì sao tôi không backup được".
func TestBlocking(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m1 := locks.New(st, "box-A", time.Minute)
	m2 := locks.New(st, "box-B", time.Minute)

	if err := m1.Acquire(ctx, locks.AppTask("app-1"), "đang cài"); err != nil {
		t.Fatal(err)
	}
	blocking, err := m2.Blocking(ctx, locks.FullBackup)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocking) != 1 || blocking[0].Name != locks.AppTask("app-1") {
		t.Fatalf("Blocking = %+v, muốn khoá app-op/app-1", blocking)
	}

	// Thao tác không xung khắc thì danh sách rỗng.
	empty, err := m2.Blocking(ctx, locks.AppBackup("app-2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("backup app khác lại bị chặn bởi %+v", empty)
	}
}

// Tên khoá lạ mặc định CHẶT (xung khắc với chính nó) — một tên gõ sai không
// được biến thành thao tác chạy song song với mọi thứ.
func TestUnknownLockDefaultsStrict(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	m1 := locks.New(st, "A", time.Minute)
	m2 := locks.New(st, "B", time.Minute)

	if err := m1.Acquire(ctx, "thao_tac_la", ""); err != nil {
		t.Fatal(err)
	}
	if err := m2.Acquire(ctx, "thao_tac_la", ""); !errors.Is(err, locks.ErrBusy) {
		t.Errorf("khoá lạ không tự xung khắc: %v", err)
	}
}
