package privops

import (
	"os/exec"
	"testing"
)

// Đầu vào lấy từ /proc/<pid>/status của keenrig-box trên VPS 2026-10-14 —
// unit không ghi NoNewPrivileges mà cờ vẫn bật (xem NoNewPrivs).
func TestNoNewPrivsIn(t *testing.T) {
	cases := map[string]bool{
		"Uid:\t997\t997\t997\t997\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n": true,
		"Uid:\t997\t997\t997\t997\nNoNewPrivs:\t0\nSeccomp:\t0\n":                            false,
		"Uid:\t0\t0\t0\t0\n": false, // kernel cũ không có dòng này
		"":                   false,
	}
	for in, want := range cases {
		if got := noNewPrivsIn(in); got != want {
			t.Errorf("noNewPrivsIn(%q) = %v, muốn %v", in, got, want)
		}
	}
}

func TestIsUnavailableOnNoNewPrivs(t *testing.T) {
	// isUnavailable chỉ xét stderr khi err là *exec.ExitError.
	var err error = &exec.ExitError{}
	for _, msg := range []string{
		"sudo: The \"no new privileges\" flag is set, which prevents sudo from running as root.",
		"sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set",
	} {
		if !isUnavailable(err, msg) {
			t.Errorf("isUnavailable(%q) = false, muốn true", msg)
		}
	}
}
