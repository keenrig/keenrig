//go:build unix

package formattest

import (
	"io/fs"
	"os"
	"syscall"
)

// ownerOf đọc uid/gid từ kết quả lstat.
//
// Nằm trong file có build tag vì `syscall.Stat_t` không tồn tại trên Windows,
// nơi suite này vẫn phải BIÊN DỊCH được — dev chạy trên Windows, CI chạy trên
// Linux, và một suite không biên dịch được ở một bên là một suite không ai chạy.
func ownerOf(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, k := fi.Sys().(*syscall.Stat_t)
	if !k {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func isRoot() bool { return os.Geteuid() == 0 }
