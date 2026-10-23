//go:build !unix

package formattest

import "io/fs"

// Trên hệ không có uid/gid POSIX, khẳng định về chủ sở hữu không có nghĩa —
// subtest tự SKIP thay vì so hai con số bịa ra.
func ownerOf(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

func isRoot() bool { return false }
