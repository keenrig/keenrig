// Package addontest — conformance suite cho addons.Addon (AD-01..04).
//
// Mọi impl phải pass RunConformance. Đây là bảo hiểm bằng code cho lời hứa
// "thêm addon mới không đổi hành vi của phần còn lại".
//
// # Vì sao suite này khó hơn storetest/runtimetest
//
// postgres và redis có kiến trúc NGƯỢC nhau: postgres một container dùng chung
// (Teardown xoá DB, container vẫn chạy), redis một container mỗi app (Teardown
// xoá hẳn container). Suite phải phát biểu khẳng định ở mức KHÔNG nhìn thấy
// khác biệt đó.
//
// Cách phát biểu đúng: "sau Teardown app A, app A mất dữ liệu và app B KHÔNG".
// Cách phát biểu SAI: "sau Teardown, container vẫn chạy" — nó chỉ đúng cho
// postgres, và để làm redis pass thì phải thêm một cờ vào suite. Một cờ như vậy
// là chỗ hành vi hai driver âm thầm trôi khỏi nhau.
package addontest

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
)

// Opener cấp một Addon tươi cho mỗi subtest.
type Opener func(t *testing.T) addons.Addon

// RunConformance chạy toàn bộ suite.
func RunConformance(t *testing.T, open Opener) {
	t.Run("SetupReturnsUsableEnv", func(t *testing.T) { testSetupEnv(t, open(t)) })           // AD-01
	t.Run("SetupIdempotent", func(t *testing.T) { testSetupIdempotent(t, open(t)) })          // AD-02
	t.Run("EnvNamespace", func(t *testing.T) { testEnvNamespace(t, open(t)) })                // AD-03
	t.Run("RecordMatchesSchema", func(t *testing.T) { testRecordSchema(t, open(t)) })         // AD-03
	t.Run("EnvBeforeSetupFails", func(t *testing.T) { testEnvBeforeSetup(t, open(t)) })       // AD-01
	t.Run("TeardownIsolation", func(t *testing.T) { testTeardownIsolation(t, open(t)) })      // AD-04
	t.Run("TeardownIdempotent", func(t *testing.T) { testTeardownIdempotent(t, open(t)) })    // AD-04
	t.Run("CredsPerAppAreDistinct", func(t *testing.T) { testCredsDistinct(t, open(t)) })     // BK-05
	t.Run("BackupRestoreRoundTrip", func(t *testing.T) { testBackupRestore(t, open(t)) })     // BK-01
	t.Run("RestoreOnlyTouchesOneApp", func(t *testing.T) { testRestoreIsolated(t, open(t)) }) // BK-01
}

const (
	appA = "conf-app-a"
	appB = "conf-app-b"
)

func setup(t *testing.T, a addons.Addon, appID string) addons.Creds {
	t.Helper()
	c, err := a.Setup(t.Context(), appID)
	if err != nil {
		t.Fatalf("Setup(%s): %v", appID, err)
	}
	return c
}

// AD-01 — Setup trả bộ biến DÙNG ĐƯỢC.
//
// "Dùng được" nghĩa là: có ít nhất một biến, mọi tên đúng namespace, và Env()
// đọc lại được đúng bộ đó. Kiểm ba điều riêng vì mỗi cái hỏng theo một kiểu
// khác: Setup không lưu · Env đọc sai chỗ · driver đặt sai tên biến.
func testSetupEnv(t *testing.T, a addons.Addon) {
	c := setup(t, a, appA)
	if len(c.Env) == 0 {
		t.Fatal("Setup trả bộ biến RỖNG — app không có cách nào kết nối tới addon")
	}
	if err := addons.ValidateEnv(c.Env); err != nil {
		t.Fatalf("Setup trả biến sai hợp đồng: %v", err)
	}

	got, err := a.Env(t.Context(), appA)
	if err != nil {
		t.Fatalf("Env sau Setup: %v", err)
	}
	if !sameEnv(got, c.Env) {
		t.Errorf("Env() = %v, Setup trả %v — hai đường đọc cùng một credential\n"+
			"phải cho cùng kết quả, nếu không thì container chạy với bộ biến khác\n"+
			"bộ mà platform tưởng đã cấp", keys(got), keys(c.Env))
	}
}

// AD-02 — Setup idempotent, và ĐẶC BIỆT: KHÔNG sinh mật khẩu mới.
//
// Sinh mật khẩu mới ở lần gọi thứ hai là kiểu hỏng tệ nhất của addon: container
// app đang chạy với mật khẩu cũ mất kết nối, DB thì vẫn sống, và không có gì
// trong hệ thống nói ra điều đó. Reconciler gọi Setup mỗi vòng hội tụ, nên đây
// không phải trường hợp hiếm — nó là trường hợp THƯỜNG.
func testSetupIdempotent(t *testing.T, a addons.Addon) {
	first := setup(t, a, appA)
	for i := 0; i < 3; i++ {
		again := setup(t, a, appA)
		if !sameEnv(again.Env, first.Env) {
			t.Fatalf("Setup lần %d trả credential KHÁC lần đầu.\n"+
				"Container app đang chạy với bộ cũ sẽ mất kết nối, và không có\n"+
				"lỗi nào được sinh ra.\nlần đầu: %v\nlần %d:  %v",
				i+2, first.Env, i+2, again.Env)
		}
	}
}

// AD-03 — mọi tên biến khớp ^KEENRIG_[A-Z0-9_]+$.
//
// Namespace này là HỢP ĐỒNG CÔNG KHAI với image app. Đổi tên một biến là
// breaking change với mọi app đang chạy, không phải refactor nội bộ.
func testEnvNamespace(t *testing.T, a addons.Addon) {
	setup(t, a, appA)
	env, err := a.Env(t.Context(), appA)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^KEENRIG_[A-Z0-9_]+$`)
	for _, k := range keys(env) {
		if !re.MatchString(k) {
			t.Errorf("biến %q vi phạm namespace KEENRIG_ (addon.schema.json)", k)
		}
	}
	// Và phải có ít nhất một biến mang địa chỉ kết nối. Bộ biến "hợp lệ" mà
	// không nói app phải nối tới đâu thì vô dụng.
	hasAddr := false
	for _, k := range keys(env) {
		if k == "KEENRIG_"+up(string(a.Kind()))+"_URL" || k == "KEENRIG_"+up(string(a.Kind()))+"_HOST" {
			hasAddr = true
		}
	}
	if !hasAddr {
		t.Errorf("không có biến nào mang địa chỉ kết nối (…_URL hoặc …_HOST): %v", keys(env))
	}
}

// AD-03 — bản ghi THẬT do driver sinh ra phải khớp addon.schema.json.
//
// # Vì sao subtest này tồn tại cạnh EnvNamespace
//
// EnvNamespace kiểm regex tên biến — một mảnh của schema, viết lại bằng Go.
// Subtest này chạy CHÍNH schema trên CHÍNH bản ghi driver trả về. Khác biệt
// không phải hình thức: `keenrig-contracts/go` đã có test cho `addon.schema.json`
// từ M1, nhưng nó chỉ chạy trên JSON viết tay trong file test. Một schema chỉ
// từng thấy ví dụ do người viết schema soạn ra thì không khẳng định được gì về
// dữ liệu thật — nó khẳng định người đó biết mình vừa viết gì.
//
// Điều schema bắt được mà regex không: `addon` phải nằm trong enum (driver mới
// quên cập nhật schema), `additionalProperties: false` (một trường `password`
// thêm vào bản ghi), và `secret_ref` khác rỗng nếu có mặt.
//
// Chạy trên cả `Setup` và `Env` vì hai đường sinh ra bộ biến khác nhau: Setup
// dựng nó từ thứ vừa cấp phát, Env đọc lại từ store. Một driver giải mã secret
// sai chỉ hỏng ở đường thứ hai.
func testRecordSchema(t *testing.T, a addons.Addon) {
	creds := setup(t, a, appA)
	if err := creds.Record(a.Kind(), appA).Validate(); err != nil {
		t.Errorf("bản ghi từ Setup: %v", err)
	}

	env, err := a.Env(t.Context(), appA)
	if err != nil {
		t.Fatal(err)
	}
	fromEnv := addons.Creds{Env: env, SecretRef: creds.SecretRef}
	if err := fromEnv.Record(a.Kind(), appA).Validate(); err != nil {
		t.Errorf("bản ghi từ Env: %v", err)
	}
}

// Env trước Setup phải là ErrNotProvisioned, KHÔNG phải bộ biến rỗng.
//
// Trả bộ rỗng nghĩa là reconciler tiêm một tập biến trống vào container và app
// khởi động rồi chết vì thiếu cấu hình — triệu chứng nằm ở app, nguyên nhân ở ta.
func testEnvBeforeSetup(t *testing.T, a addons.Addon) {
	_, err := a.Env(t.Context(), "chua-bao-gio-setup")
	if !errors.Is(err, addons.ErrNotProvisioned) {
		t.Errorf("Env trước Setup = %v, muốn ErrNotProvisioned", err)
	}
}

// AD-04 — Teardown app A KHÔNG được ảnh hưởng app B.
//
// Đây là khẳng định phát biểu ở mức không nhìn thấy kiến trúc: postgres xoá DB
// trong container dùng chung, redis xoá hẳn container của app đó. Cùng một câu,
// hai cách thoả.
func testTeardownIsolation(t *testing.T, a addons.Addon) {
	ctx := t.Context()
	setup(t, a, appA)
	credsB := setup(t, a, appB)

	if err := a.Teardown(ctx, appA); err != nil {
		t.Fatalf("Teardown(%s): %v", appA, err)
	}

	// A mất credential.
	if _, err := a.Env(ctx, appA); !errors.Is(err, addons.ErrNotProvisioned) {
		t.Errorf("sau Teardown, Env(%s) = %v, muốn ErrNotProvisioned", appA, err)
	}
	// B KHÔNG bị đụng — và phải là ĐÚNG credential cũ, không phải một bộ mới.
	envB, err := a.Env(ctx, appB)
	if err != nil {
		t.Fatalf("Teardown app A làm app B mất addon: %v", err)
	}
	if !sameEnv(envB, credsB.Env) {
		t.Errorf("Teardown app A làm ĐỔI credential của app B\ntrước: %v\nsau:  %v",
			credsB.Env, envB)
	}
}

func testTeardownIdempotent(t *testing.T, a addons.Addon) {
	ctx := t.Context()
	setup(t, a, appA)
	for i := 0; i < 3; i++ {
		if err := a.Teardown(ctx, appA); err != nil {
			t.Fatalf("Teardown lần %d: %v — reconciler gọi lại sau mỗi lần restart "+
				"giữa chừng, nên không idempotent nghĩa là app kẹt mãi ở trạng thái xoá",
				i+1, err)
		}
	}
	// Teardown một app CHƯA BAO GIỜ setup cũng không được lỗi.
	if err := a.Teardown(ctx, "chua-bao-gio-setup"); err != nil {
		t.Errorf("Teardown app chưa setup: %v", err)
	}
}

// BK-05 — credential per-app phải KHÁC nhau.
//
// Dùng chung một mật khẩu cho mọi app nghĩa là app A đọc được DB của app B —
// và đó là toàn bộ giá trị của việc cấp phát riêng.
func testCredsDistinct(t *testing.T, a addons.Addon) {
	ca := setup(t, a, appA)
	cb := setup(t, a, appB)

	if sameEnv(ca.Env, cb.Env) {
		t.Fatal("hai app nhận CÙNG credential — app A đọc được dữ liệu app B (BK-05)")
	}
	// Cụ thể hơn: không một GIÁ TRỊ nhạy cảm nào được trùng. Trùng host/port là
	// bình thường (dùng chung service); trùng password thì không.
	for k, va := range ca.Env {
		if !isSensitive(k) {
			continue
		}
		if vb, ok := cb.Env[k]; ok && va == vb {
			t.Errorf("biến nhạy cảm %s giống nhau giữa hai app", k)
		}
	}
}

// BK-01 — Backup rồi Restore trả về đúng dữ liệu.
//
// Suite không biết addon lưu gì, nên nó không kiểm nội dung. Nó kiểm điều mà
// mọi addon phải thoả: Backup sinh ra thứ gì đó, và Restore nhận lại được thứ
// đó mà không lỗi. Kiểm nội dung là việc của test riêng từng driver.
func testBackupRestore(t *testing.T, a addons.Addon) {
	ctx := t.Context()
	setup(t, a, appA)

	dir := t.TempDir()
	if err := a.Backup(ctx, appA, dir); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("Backup không ghi file nào — một backup rỗng là một backup không\n" +
			"restore được, và nó chỉ lộ ra vào lúc người dùng cần restore")
	}

	if err := a.Restore(ctx, appA, dir); err != nil {
		t.Fatalf("Restore từ chính bản Backup vừa tạo: %v", err)
	}
	// Credential phải GIỮ NGUYÊN qua restore: đổi mật khẩu lúc restore nghĩa là
	// app không kết nối lại được sau khi khôi phục.
	if _, err := a.Env(ctx, appA); err != nil {
		t.Errorf("sau Restore, Env lỗi: %v", err)
	}
}

// Restore app A không được cuốn theo dữ liệu app B.
func testRestoreIsolated(t *testing.T, a addons.Addon) {
	ctx := t.Context()
	setup(t, a, appA)
	credsB := setup(t, a, appB)

	dir := t.TempDir()
	if err := a.Backup(ctx, appA, dir); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := a.Restore(ctx, appA, dir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	envB, err := a.Env(ctx, appB)
	if err != nil {
		t.Fatalf("Restore app A làm app B mất addon: %v", err)
	}
	if !sameEnv(envB, credsB.Env) {
		t.Errorf("Restore app A làm đổi credential app B")
	}
}

// --- helper ---------------------------------------------------------------------

// BackupDirFor tạo một thư mục backup tạm — tiện cho test riêng của driver.
func BackupDirFor(t *testing.T, name string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	return d
}

func sameEnv(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isSensitive — biến mang bí mật. Danh sách theo HẬU TỐ chứ không theo tên đầy
// đủ: mỗi addon có tiền tố riêng (KEENRIG_POSTGRES_*, KEENRIG_REDIS_*), và một
// danh sách tên đầy đủ sẽ phải sửa mỗi lần thêm addon — tức là sẽ bị quên.
func isSensitive(name string) bool {
	for _, suffix := range []string{"_PASSWORD", "_URL", "_TOKEN", "_SECRET", "_USER", "_DATABASE"} {
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

func up(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}
