package paths

// Đổi tên bố cục thư mục: instancedata → instance, platformdata → node,
// appsdata → apps.
//
// # Vì sao KHÔNG chỉ đổi tên rồi thôi
//
// Đổi tên một data directory mà không di trú là kiểu hỏng IM LẶNG tệ nhất
// trong cả hệ: box khởi động bình thường, EnsureDirs tạo các thư mục MỚI hoàn
// toàn rỗng, `/healthz` trả 200 — và mọi app của người dùng biến mất khỏi giao
// diện. Không lỗi, không log, không manh mối. Dữ liệu vẫn nằm nguyên trên đĩa
// dưới tên cũ, nhưng không ai biết để đi tìm.
//
// # Vì sao là rename chứ không phải copy
//
// os.Rename là thao tác của thư mục cha, nguyên tử trong cùng filesystem: hoặc
// tên cũ hoặc tên mới, không có trạng thái giữa. Copy sẽ nhân đôi dung lượng
// (appsdata có thể hàng chục GB) và để lại một cửa sổ mà cả hai tên cùng tồn
// tại với nội dung khác nhau.
//
// # Điều kiện an toàn của hàm này
//
// Chỉ đổi tên khi tên CŨ tồn tại VÀ tên MỚI chưa có. Cả hai cùng tồn tại nghĩa
// là ai đó đã can thiệp bằng tay, hoặc một lần di trú trước đã dừng giữa
// chừng — trộn hai cây thư mục lúc đó là đoán, và đoán sai ở đây là mất dữ
// liệu. Trường hợp đó ta DỪNG và báo, để người vận hành quyết định.
//
// # Vòng đời
//
// Xoá được sau bản phát hành công khai đầu tiên: khi không còn bản cài nào
// mang tên cũ thì hàm này chỉ là một lần stat thừa mỗi lần khởi động.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrLayoutConflict — cả tên cũ lẫn tên mới cùng tồn tại.
var ErrLayoutConflict = errors.New("paths: both the old and the new directory names exist")

// legacyDirs — ánh xạ tên CŨ → tên MỚI, theo thứ tự di trú.
//
// instance đi đầu có chủ đích: nó chứa platform.db. Nếu quá trình dừng giữa
// chừng vì hết đĩa hay mất điện, ta muốn thứ đã sang tên mới là thứ quan trọng
// nhất, không phải thư mục log.
var legacyDirs = []struct{ old, new string }{
	{"instancedata", "instance"},
	{"platformdata", "node"},
	{"appsdata", "apps"},
}

// legacyFlatFiles — file từng nằm NGAY dưới <base> thay vì trong instance/.
//
// Đây là một bất nhất có thật đã tồn tại: main.go tự ghép
// filepath.Join(dataDir, "platform.db") trong khi paths.DB() nói
// <base>/instance/platform.db. Installer tạo instance/ với 0700 ĐỂ bảo vệ
// master.key, còn box lại ghi master.key vào thư mục <base> với quyền 0755.
var legacyFlatFiles = []string{"platform.db", "platform.db-wal", "platform.db-shm", "master.key"}

// MigrateLegacyLayout đổi tên các thư mục theo bố cục cũ, nếu có.
//
// Trả (danh sách đã đổi, lỗi). Gọi TRƯỚC EnsureDirs — ngược lại thì EnsureDirs
// tạo sẵn thư mục mới rỗng, và di trú sẽ thấy "cả hai cùng tồn tại" rồi từ
// chối, đúng cái bẫy nó sinh ra để tránh.
func (l Layout) MigrateLegacyLayout() ([]string, error) {
	var done []string
	for _, d := range legacyDirs {
		oldPath := filepath.Join(l.base, d.old)
		newPath := filepath.Join(l.base, d.new)

		oldInfo, oldErr := os.Stat(oldPath)
		if oldErr != nil || !oldInfo.IsDir() {
			continue // không có tên cũ — bản cài mới, không có gì để làm
		}
		if _, newErr := os.Stat(newPath); newErr == nil {
			// KHÔNG trộn. Trộn hai cây thư mục là đoán, và đoán sai ở đây là
			// mất dữ liệu người dùng.
			return done, fmt.Errorf("%w: %s and %s — merge them by hand, then delete the old directory",
				ErrLayoutConflict, oldPath, newPath)
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			return done, fmt.Errorf("paths: renaming %s → %s: %w", oldPath, newPath, err)
		}
		done = append(done, d.old+" → "+d.new)
	}

	moved, err := l.migrateFlatFiles()
	if err != nil {
		return done, err
	}
	return append(done, moved...), nil
}

// migrateFlatFiles chuyển platform.db + master.key từ <base> vào instance/.
//
// Chuyển CẢ -wal và -shm: bỏ lại file -wal nghĩa là mọi transaction đã commit
// nhưng chưa checkpoint bị mất. Một DB "mở được nhưng thiếu vài phút cuối" là
// kiểu hỏng không ai truy ra được nguyên nhân.
func (l Layout) migrateFlatFiles() ([]string, error) {
	var done []string
	for _, name := range legacyFlatFiles {
		oldPath := filepath.Join(l.base, name)
		newPath := filepath.Join(l.Instance(), name)

		if info, err := os.Stat(oldPath); err != nil || info.IsDir() {
			continue
		}
		if _, err := os.Stat(newPath); err == nil {
			return done, fmt.Errorf("%w: %s and %s", ErrLayoutConflict, oldPath, newPath)
		}
		if err := os.MkdirAll(l.Instance(), PrivateDirPerm); err != nil {
			return done, fmt.Errorf("paths: creating %s: %w", l.Instance(), err)
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			return done, fmt.Errorf("paths: moving %s → %s: %w", oldPath, newPath, err)
		}
		done = append(done, name+" → instance/"+name)
	}
	// Siết quyền SAU khi chuyển: master.key vừa rời một thư mục 0755, và để nó
	// nằm trong một thư mục cũng 0755 thì việc chuyển chẳng giải quyết gì.
	if len(done) > 0 {
		if err := os.Chmod(l.Instance(), PrivateDirPerm); err != nil {
			return done, fmt.Errorf("paths: tightening permissions on %s: %w", l.Instance(), err)
		}
	}
	return done, nil
}
