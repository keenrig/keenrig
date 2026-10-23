package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SnapshotTo ghi một bản sao NHẤT QUÁN của database ra dst.
//
// # Vì sao không phải io.Copy
//
// platform.db chạy ở chế độ WAL, nên tại một thời điểm bất kỳ dữ liệu nằm ở
// HAI nơi: file chính và file `-wal` chưa checkpoint. Chép mỗi file chính là
// mất mọi giao dịch chưa checkpoint — và mất theo cách tệ nhất: bản sao lưu
// vẫn mở được, vẫn chạy được, chỉ thiếu vài giao dịch cuối. Không có gì hỏng
// để lần ra; app đơn giản là quên mất vài phút cuối trước sự cố.
//
// Chép cả ba file (`db` + `-wal` + `-shm`) cũng không cứu được: ta chép chúng ở
// ba thời điểm khác nhau, trong khi một giao dịch có thể đang chạy giữa chừng.
// Kết quả là một bộ ba KHÔNG khớp nhau — và SQLite sẽ từ chối mở, hoặc tệ hơn,
// mở được với dữ liệu nửa vời.
//
// `VACUUM INTO` chạy TRONG chính connection đang phục vụ, nên SQLite dựng bản
// sao từ một ảnh chụp nhất quán của trạng thái đã commit. Nó cũng cho ra một
// file DUY NHẤT đã gộp WAL, không có `-wal`/`-shm` đi kèm — đúng thứ ta muốn
// nhét vào một archive.
//
// # Giá phải trả, nói thẳng
//
// VACUUM INTO ghi lại toàn bộ database, nên nó tốn thời gian và dung lượng
// tương đương kích thước DB, và nó giữ một khoá đọc suốt quá trình. Với
// platform.db (metadata của instance, hàng MB chứ không phải GB) thì đó là cái
// giá đúng. Nếu ngày nào DB lên hàng GB thì chỗ này phải đổi sang backup API
// theo trang — và lúc đó `dst` vẫn là hợp đồng, chỉ ruột đổi.
//
// # dst PHẢI chưa tồn tại
//
// Đây là luật của chính SQLite: `VACUUM INTO` từ chối ghi đè. Ta kiểm TRƯỚC để
// thông báo nói đúng chuyện gì xảy ra, thay vì để lỗi thô của driver đi lên tận
// người vận hành.
func (s *SQLite) SnapshotTo(ctx context.Context, dst string) error {
	if strings.TrimSpace(dst) == "" {
		return fmt.Errorf("store: snapshot destination is empty")
	}
	abs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(abs); err == nil {
		return fmt.Errorf("store: snapshot destination %s already exists — VACUUM INTO never overwrites", abs)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}

	// Đường dẫn đi vào câu SQL dưới dạng THAM SỐ, không nội suy chuỗi. Ở đây nó
	// không phải input của người dùng, nhưng `VACUUM INTO 'C:\...\it's'` sẽ hỏng
	// vì dấu nháy — và một hàm sao lưu hỏng khi đường dẫn có dấu nháy là thứ chỉ
	// lộ ra ở máy khách hàng. Cùng bài học với escapeDSNPath và ký tự '#'.
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, abs); err != nil {
		// Dọn phần đã ghi dở: một file DB cụt mang đúng tên bản đầy đủ là thứ
		// đi qua mọi lần kiểm và chỉ hỏng lúc restore.
		os.Remove(abs)
		return fmt.Errorf("store: snapshotting the database to %s: %w", abs, err)
	}
	return nil
}
