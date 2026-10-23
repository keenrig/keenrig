package apps

import (
	"crypto/rand"
	"encoding/hex"
)

// newUUIDv4 sinh app id dạng UUID v4.
//
// Ngẫu nhiên MẬT MÃ, không phải số tăng dần: id app xuất hiện trong URL và
// trong tên container, nên id đoán được là để lộ số lượng app và cho phép dò
// tuần tự. crypto/rand lỗi thì panic — không có id an toàn nghĩa là không có
// cách nào tiếp tục đúng, và trả một id đoán được sẽ tệ hơn nhiều so với chết.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("apps: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
