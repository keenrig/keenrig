// Package keenrigcatalog — danh mục app đi kèm binary.
//
// # Vì sao đây là một MODULE riêng, không phải một thư mục trong keenrig-node
//
// `go:embed` không vượt được ranh giới module: một package trong keenrig-node
// không nhúng được file nằm ở keenrig-catalog/. Ba đường ra, và hai đường sai:
//
//	sai   Chép manifest sang keenrig-node/ → hai bản, và chúng sẽ trôi khỏi nhau.
//	sai   Đọc từ đĩa lúc chạy theo đường dẫn tương đối → binary phụ thuộc thư
//	      mục làm việc, và `keenrig-box serve` từ /root sẽ không thấy danh mục.
//	đúng  keenrig-catalog là module, nhúng manifest của chính nó, keenrig-node
//	      import nó như một thư viện.
//
// # Nhúng vào binary, KHÔNG tải từ mạng lúc chạy
//
// UI-11 nói self-host không được đòi tài khoản cloud và không được có lời gọi
// mạng BẮT BUỘC nào ra ngoài. Một danh mục tải từ mạng lúc khởi động sẽ biến
// "mất mạng" thành "không cài được app nào", và biến máy chủ phát hành danh
// mục thành một điểm chết cho mọi instance trên đời.
//
// Danh mục từ xa vẫn sẽ có (nó mới là chỗ danh mục lớn nằm), nhưng nó là phần
// THÊM VÀO tập nhúng sẵn, không thay thế.
package keenrigcatalog

import (
	"embed"
	"io/fs"
)

//go:embed manifests/*.json
var manifestFS embed.FS

//go:embed icons
var iconFS embed.FS

// Manifests trả filesystem chứa các manifest JSON đi kèm binary.
func Manifests() fs.FS {
	sub, err := fs.Sub(manifestFS, "manifests")
	if err != nil {
		// Không xảy ra được: đường dẫn là hằng số và đã kiểm lúc biên dịch.
		// Panic thay vì trả lỗi vì đây là lỗi lập trình, và nó phải nổ lúc
		// khởi động chứ không biến thành "danh mục rỗng" im lặng.
		panic("keenrigcatalog: manifests/ could not be embedded: " + err.Error())
	}
	return sub
}

// Icons trả filesystem chứa icon. Có thể RỖNG — icon là trang trí, thiếu nó
// không được làm hỏng việc cài app.
func Icons() fs.FS {
	sub, err := fs.Sub(iconFS, "icons")
	if err != nil {
		return embed.FS{}
	}
	return sub
}
