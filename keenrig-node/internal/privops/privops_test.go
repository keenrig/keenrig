package privops_test

// Test internal/privops.
//
// Hai tầng, và tầng thứ hai mới là tầng quan trọng:
//
//	Go      kiểm đối số trước khi gọi script, và dịch lỗi cho đúng.
//	SHELL   chính các script — chạy THẬT trên Linux, vì chúng là hàng rào cuối
//	        cùng và là thứ duy nhất còn đứng khi ai đó gọi chúng từ chỗ khác.
//
// Phần shell tự SKIP trên Windows: script là bash và bố cục thư mục là của
// Linux. Skip có lý do, không phải biến mất im lặng.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/privops"
)

// fakeRunner ghi lại mọi lời gọi thay vì thực thi.
type fakeRunner struct {
	calls  [][]string
	out    string
	err    error
	failOn map[string]error
}

func (f *fakeRunner) Run(_ context.Context, script string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{script}, args...))
	if e, ok := f.failOn[script]; ok {
		return "", e
	}
	return f.out, f.err
}

func (f *fakeRunner) last() []string {
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

// --- kiểm đối số ở phía Go ---------------------------------------------------------

// app-id độc hại phải bị chặn TRƯỚC KHI thành tiến trình.
//
// Script cũng chặn, nhưng chặn ở đây có hai giá trị riêng: thông báo lỗi tốt
// hơn, và một app-id hỏng không bao giờ trở thành một lời gọi `sudo`.
func TestHostileAppIDNeverReachesScript(t *testing.T) {
	f := &fakeRunner{}
	o := privops.New(f)
	ctx := context.Background()

	hostile := []string{
		"../../../etc", "..", ".", "", "a", "/etc/passwd",
		"app/../../root", "app;rm -rf /", "app id", "APP", "app_name",
		"-leading", "trailing-", strings.Repeat("x", 50), "app\x00",
		"$(whoami)", "`id`", "app\nrm -rf /",
	}
	for _, id := range hostile {
		t.Run(id, func(t *testing.T) {
			if _, err := o.CreateAppData(ctx, id); !errors.Is(err, privops.ErrInvalidArg) {
				t.Errorf("CreateAppData(%q) = %v, muốn ErrInvalidArg", id, err)
			}
			if err := o.RemoveAppData(ctx, id); !errors.Is(err, privops.ErrInvalidArg) {
				t.Errorf("RemoveAppData(%q) = %v, muốn ErrInvalidArg", id, err)
			}
			if _, err := o.DiskUsage(ctx, id); !errors.Is(err, privops.ErrInvalidArg) {
				t.Errorf("DiskUsage(%q) = %v, muốn ErrInvalidArg", id, err)
			}
			if err := o.ChownAppData(ctx, id, 1000, 1000); !errors.Is(err, privops.ErrInvalidArg) {
				t.Errorf("ChownAppData(%q) = %v, muốn ErrInvalidArg", id, err)
			}
		})
	}
	if len(f.calls) != 0 {
		t.Fatalf("có %d lời gọi sudo với app-id độc hại: %v", len(f.calls), f.calls)
	}
}

func TestValidAppIDReachesScript(t *testing.T) {
	f := &fakeRunner{out: "/var/lib/keenrig/apps/app-1"}
	o := privops.New(f)
	ctx := context.Background()

	path, err := o.CreateAppData(ctx, "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/var/lib/keenrig/apps/app-1" {
		t.Errorf("path = %q", path)
	}
	if got := f.last(); len(got) != 3 || got[0] != privops.ScriptAppData ||
		got[1] != "create" || got[2] != "app-1" {
		t.Errorf("lời gọi = %v", got)
	}
}

func TestChownFormatsUIDGID(t *testing.T) {
	f := &fakeRunner{}
	o := privops.New(f)
	if err := o.ChownAppData(context.Background(), "app-1", 1000, 1001); err != nil {
		t.Fatal(err)
	}
	got := f.last()
	if len(got) != 4 || got[3] != "1000:1001" {
		t.Errorf("lời gọi = %v, muốn uid:gid dạng số", got)
	}
	// uid âm là lỗi lập trình, không phải một giá trị hợp lệ nào đó.
	if err := o.ChownAppData(context.Background(), "app-1", -1, 0); !errors.Is(err, privops.ErrInvalidArg) {
		t.Errorf("uid âm = %v", err)
	}
}

func TestChownAppVolume(t *testing.T) {
	f := &fakeRunner{}
	o := privops.New(f)
	ctx := context.Background()
	if err := o.ChownAppVolume(ctx, "app-1", "data", 1000, 1000); err != nil {
		t.Fatal(err)
	}
	got := f.last()
	if len(got) != 5 || got[0] != privops.ScriptAppData || got[1] != "chown-volume" ||
		got[2] != "app-1" || got[3] != "data" || got[4] != "1000:1000" {
		t.Errorf("lời gọi = %v", got)
	}
	// Tên volume là một đoạn đường dẫn thật dưới apps/<id>/volumes/ — không
	// được để "..", "/" hay rỗng tới tay sudo.
	f.calls = nil
	for _, v := range []string{"", "..", "../instance", "a/b", "-x", "Data", "x;rm"} {
		if err := o.ChownAppVolume(ctx, "app-1", v, 1000, 1000); !errors.Is(err, privops.ErrInvalidArg) {
			t.Errorf("ChownAppVolume(volume=%q) = %v, muốn ErrInvalidArg", v, err)
		}
	}
	if err := o.ChownAppVolume(ctx, "app-1", "data", -1, 0); !errors.Is(err, privops.ErrInvalidArg) {
		t.Errorf("uid âm = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("có %d lời gọi sudo với đối số độc hại: %v", len(f.calls), f.calls)
	}
}

func TestDiskUsageParsesBytes(t *testing.T) {
	f := &fakeRunner{out: "1048576\n"}
	o := privops.New(f)
	n, err := o.DiskUsage(context.Background(), "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1048576 {
		t.Errorf("= %d, muốn 1048576", n)
	}

	// Đầu ra không phải số phải là LỖI, không phải 0. Trả 0 âm thầm nghĩa là
	// UI hiện "0 byte" cho một app đang chiếm 40GB.
	f2 := &fakeRunner{out: "du: cannot read directory"}
	if _, err := privops.New(f2).DiskUsage(context.Background(), "app-1"); err == nil {
		t.Error("đầu ra rác được nhận là 0 byte")
	}
}

// Service là KIỂU RIÊNG: gõ sai tên dịch vụ phải là lỗi biên dịch.
func TestRestartServicePassesName(t *testing.T) {
	f := &fakeRunner{}
	o := privops.New(f)
	for _, svc := range []privops.Service{
		privops.ServiceCaddy, privops.ServiceDocker, privops.ServiceBox, privops.ServiceAgent,
	} {
		if err := o.RestartService(context.Background(), svc); err != nil {
			t.Fatal(err)
		}
		if got := f.last(); len(got) != 2 || got[1] != string(svc) {
			t.Errorf("lời gọi = %v", got)
		}
	}
}

// --- phân biệt "chưa cài đặt" với "thao tác thất bại" ------------------------------

// Hai loại lỗi này dẫn người vận hành tới hai chỗ khác nhau. Gộp lại thì họ đi
// tìm lỗi trong app trong khi vấn đề nằm ở sudoers.
func TestUnavailableIsDistinct(t *testing.T) {
	f := &fakeRunner{failOn: map[string]error{
		privops.ScriptAppData: privops.ErrUnavailable,
	}}
	o := privops.New(f)
	if err := o.RemoveAppData(context.Background(), "app-1"); !errors.Is(err, privops.ErrUnavailable) {
		t.Errorf("err = %v, muốn ErrUnavailable", err)
	}
}

// AvailableAll phải kiểm ĐỦ bộ script — thiếu một cái là một khả năng im lặng
// không dùng được cho tới lúc ai đó bấm đúng nút đó.
func TestAvailableAllChecksEveryScript(t *testing.T) {
	f := &fakeRunner{}
	o := privops.New(f)
	if bad := o.AvailableAll(context.Background()); len(bad) != 0 {
		t.Fatalf("bad = %v", bad)
	}
	if len(f.calls) != len(privops.AllScripts()) {
		t.Fatalf("gọi %d script, muốn %d", len(f.calls), len(privops.AllScripts()))
	}
	for _, c := range f.calls {
		if len(c) != 2 || c[1] != "--check" {
			t.Errorf("lời gọi kiểm phải dùng --check (không tác dụng phụ): %v", c)
		}
	}
}

func TestAvailableAllReportsBroken(t *testing.T) {
	f := &fakeRunner{failOn: map[string]error{
		privops.ScriptReboot: privops.ErrUnavailable,
	}}
	bad := privops.New(f).AvailableAll(context.Background())
	if len(bad) != 1 || bad[privops.ScriptReboot] == nil {
		t.Errorf("bad = %v, muốn đúng reboot.sh hỏng", bad)
	}
}

// AllScripts phải khớp file sudoers. Không có test này thì thêm một hàm mới mà
// quên sudoers là một khả năng chết im lặng.
func TestAllScriptsIsComplete(t *testing.T) {
	want := map[string]bool{
		"caddy-bootstrap.sh": true, "nginx-bootstrap.sh": true, "nginx-ctl.sh": true,
		"restartservice.sh": true,
		"appdata.sh":        true, "du.sh": true, "reboot.sh": true,
		"pair.sh": true,
	}
	got := privops.AllScripts()
	if len(got) != len(want) {
		t.Fatalf("AllScripts() = %v, muốn %d mục", got, len(want))
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("script %q không có trong sudoers/keenrig", s)
		}
	}
}

// Token sai hình dạng bị chặn ở phía Go, trước khi gọi sudo.
func TestPairRejectsMalformedToken(t *testing.T) {
	f := &fakeRunner{}
	for _, tok := range []string{"", "abc", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 64) + "\n"} {
		if _, err := privops.New(f).Pair(context.Background(), tok); !errors.Is(err, privops.ErrInvalidArg) {
			t.Errorf("Pair(%q) err = %v, muốn ErrInvalidArg", tok, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("sudo bị gọi với token hỏng: %v", f.calls)
	}
}
