//go:build linux

package sysmetrics

import "syscall"

// statfsUsage — đo đĩa tại mount point bằng statfs, đơn vị byte.
//
// Dùng Bavail (khả dụng cho tiến trình KHÔNG đặc quyền) chứ không Bfree: 5%
// reserved-for-root của ext4 nằm trong Bfree nhưng app không bao giờ ghi vào
// được — báo nó là "còn trống" thì đĩa đầy sớm hơn con số 5%.
func statfsUsage(path string) (used, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	avail := st.Bavail * bs
	if avail > total {
		return 0, 0, syscall.EINVAL
	}
	return total - avail, total, nil
}
