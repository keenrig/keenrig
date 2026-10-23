//go:build !linux

package sysmetrics

import "errors"

// Box chỉ chạy Linux; bản stub này tồn tại để test của các OS khác biên dịch
// được. Trả lỗi → trường disk VẮNG (ràng buộc 2), không phải một số bịa.
func statfsUsage(string) (uint64, uint64, error) {
	return 0, 0, errors.New("sysmetrics: disk usage is only measured on linux")
}
