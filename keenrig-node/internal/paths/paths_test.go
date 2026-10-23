package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLayoutNeoVaoBase(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"bin", l.Bin(), filepath.Join("srv", "keenrig", "bin")},
		{"db", l.DB(), filepath.Join("srv", "keenrig", "instance", "platform.db")},
		{"masterkey", l.MasterKey(), filepath.Join("srv", "keenrig", "instance", "master.key")},
		{"proxy sites", l.ProxySites(), filepath.Join("srv", "keenrig", "node", "proxy", "sites")},
		{"acme", l.ACMEChallenges(), filepath.Join("srv", "keenrig", "node", "acme")},
		{"infra version", l.InfraVersionFile(), filepath.Join("srv", "keenrig", "node", "INFRA_VERSION")},
		{"apps", l.AppsDir(), filepath.Join("srv", "keenrig", "apps")},
		{"box socket", l.BoxSocket(), filepath.Join("srv", "keenrig", "node", "run", "box.sock")},
		{"agent data", l.AgentData(), filepath.Join("srv", "keenrig", "node", "agent")},
		{"update state", l.UpdateState(), filepath.Join("srv", "keenrig", "node", "update", "state.json")},
		{"bin previous", l.BinPrevious(), filepath.Join("srv", "keenrig", "node", "update", "bin-previous")},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, muốn %q", c.name, c.got, c.want)
		}
	}
}

func TestBaseRongDungMacDinh(t *testing.T) {
	if got := New("").Base(); got != filepath.Clean(DefaultBase) {
		t.Errorf("New(\"\").Base() = %q, muốn %q", got, DefaultBase)
	}
}

// Bất biến quan trọng nhất: state KHÔNG được nằm trong thư mục code, vì update
// thay nguyên khối bin/.
func TestStateNamNgoaiThuMucCode(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))
	bin := l.Bin() + string(filepath.Separator)
	appData, err := l.AppData("app-1")
	if err != nil {
		t.Fatalf("AppData: %v", err)
	}
	for _, p := range []string{l.DB(), l.MasterKey(), l.NodeData(), l.AppsDir(), appData} {
		if strings.HasPrefix(p, bin) {
			t.Errorf("%q nằm trong %q — update sẽ xoá mất state", p, l.Bin())
		}
	}
}

func TestAppDataChanDuongDanLeoRaNgoai(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))
	xau := []string{"", ".", "..", "../../etc", "a/b", `a\b`, "a\x00b"}
	for _, id := range xau {
		if got, err := l.AppData(id); err == nil {
			t.Errorf("AppData(%q) = %q, muốn lỗi", id, got)
		}
	}
	got, err := l.AppData("7f3a9c1e")
	if err != nil {
		t.Fatalf("AppData(hợp lệ): %v", err)
	}
	if want := filepath.Join(l.AppsDir(), "7f3a9c1e"); got != want {
		t.Errorf("AppData = %q, muốn %q", got, want)
	}
}

// Mỗi tiến trình có vùng state riêng: agent và ota KHÔNG được chạm instance
// (nơi box giữ platform.db) — nhiều tiến trình cùng ghi một file SQLite là hỏng.
func TestStateCuaTungTienTrinhTachRoi(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))
	box := l.Instance() + string(filepath.Separator)
	for _, p := range []string{l.AgentData(), l.UpdateState(), l.RunDir()} {
		if strings.HasPrefix(p, box) {
			t.Errorf("%q nằm trong %q — tiến trình khác sẽ đụng state của box", p, l.Instance())
		}
	}
}

// Rollback của ota là rename Bin() ↔ BinPrevious(); rename chỉ nguyên tử khi hai
// đường dẫn cùng filesystem. Neo cả hai dưới Base là điều kiện cần kiểm được.
func TestRollbackCungCayVoiBin(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))
	base := l.Base() + string(filepath.Separator)
	for _, p := range []string{l.Bin(), l.BinPrevious()} {
		if !strings.HasPrefix(p, base) {
			t.Errorf("%q không nằm dưới %q — rename sẽ không nguyên tử", p, l.Base())
		}
	}
	if l.Bin() == l.BinPrevious() {
		t.Error("Bin và BinPrevious trùng nhau")
	}
}

func TestSocketChanTenXau(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))
	for _, name := range []string{"", "..", "a/b", `a\b`} {
		if got, err := l.Socket(name); err == nil {
			t.Errorf("Socket(%q) = %q, muốn lỗi", name, got)
		}
	}
	got, err := l.Socket("agent")
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if want := filepath.Join(l.RunDir(), "agent.sock"); got != want {
		t.Errorf("Socket = %q, muốn %q", got, want)
	}
}

func TestAddonDataChanTenXau(t *testing.T) {
	l := New(filepath.Join("srv", "keenrig"))
	if _, err := l.AddonData("../../instance"); err == nil {
		t.Error("AddonData chấp nhận tên leo ra ngoài")
	}
	got, err := l.AddonData("postgres")
	if err != nil {
		t.Fatalf("AddonData: %v", err)
	}
	if want := filepath.Join(l.Addons(), "postgres"); got != want {
		t.Errorf("AddonData = %q, muốn %q", got, want)
	}
}

func TestEnsureDirsIdempotentVaSietQuyen(t *testing.T) {
	l := New(t.TempDir())
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs lần 1: %v", err)
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs lần 2 (idempotent): %v", err)
	}
	for _, d := range []string{l.Bin(), l.Instance(), l.ProxyCerts(), l.Logs(), l.AppsDir(), l.RunDir(), l.AgentData()} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Errorf("thiếu thư mục %s: %v", d, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("%s không phải thư mục", d)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows không map perm POSIX — kiểm quyền 0700 phải chạy trên Linux (CI)")
	}
	fi, err := os.Stat(l.Instance())
	if err != nil {
		t.Fatalf("stat instance: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != PrivateDirPerm {
		t.Errorf("instance perm = %o, muốn %o (chứa master.key)", perm, PrivateDirPerm)
	}
}
