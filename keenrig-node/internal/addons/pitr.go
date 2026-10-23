package addons

import (
	"context"
	"errors"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
)

// PITR — năng lực khôi phục theo THỜI ĐIỂM, cho addon nào làm được (BK-03).
//
// # Vì sao là interface PHỤ, không phải method của Addon
//
// Vì không phải addon nào cũng làm được, và ép mọi driver hiện thực một thứ nó
// không làm được là bắt nó nói dối. Redis không có WAL liên tục: `RDB` là ảnh
// chụp định kỳ và `AOF` chỉ ghi lại lệnh — không cái nào cho "đưa về đúng
// 14:32:05". Một `RestoreToTime` của redis sẽ phải hoặc làm tròn im lặng, hoặc
// trả lỗi ở mọi lời gọi.
//
// Đây đúng mô hình `proxy.Capabilities` đã dùng: năng lực được KHAI BÁO, và
// tầng trên hỏi trước khi dùng. Caller kiểm bằng type assertion:
//
//	if p, ok := addon.(addons.PITR); ok { … }
//
// # Vì sao PITR là cấp CỤM, không phải cấp app
//
// Đây là điểm khác biệt quan trọng nhất so với `Addon.Backup`/`Restore`, và nó
// không phải lựa chọn của ta mà là bản chất của PostgreSQL: WAL ghi lại mọi
// thay đổi của TOÀN BỘ cluster, không tách theo database. Không có cách nào
// "đưa riêng database của app-shop về 14:32" — ta đưa CẢ postgres về 14:32, tức
// là mọi app dùng chung container đó cùng bị lùi thời gian.
//
// Nên hai cơ chế phục vụ hai ca khác nhau, và caller phải chọn đúng:
//
//	Addon.Backup/Restore   MỘT app, mốc thời gian là lần dump gần nhất.
//	                       Ca thường: "app này hỏng, lấy lại bản hôm qua".
//	PITR                   CẢ cụm, mốc thời gian bất kỳ.
//	                       Ca hiếm và nặng: "mất máy, dựng lại tới sát lúc chết".
type PITR interface {
	// EnableArchiving bật ghi WAL liên tục. Idempotent.
	//
	// Trả về true nếu addon phải được DỰNG LẠI để thiết lập có hiệu lực —
	// PostgreSQL đọc `archive_mode` lúc khởi động, không nhận qua reload. Caller
	// quyết định lúc nào chịu được lần khởi động lại đó, vì nó cắt kết nối của
	// MỌI app đang dùng cụm.
	EnableArchiving(ctx context.Context) (needsRestart bool, err error)

	// ArchiveStatus cho biết archiving đang bật hay không, và độ trễ hiện tại.
	ArchiveStatus(ctx context.Context) (ArchiveStatus, error)

	// BaseBackup chụp một bản nền vật lý vào dir.
	//
	// KHÔNG phải `pg_dump`: dump là ảnh chụp LOGIC, không dùng làm nền để replay
	// WAL lên trên được. Đây là lý do BK-03 không dùng lại được đường của BK-01.
	BaseBackup(ctx context.Context, dir string) error

	// RestoreToTime dựng lại cụm từ base + replay WAL tới target.
	//
	// target zero = replay tới điểm xa nhất có thể (mọi WAL đã archive).
	RestoreToTime(ctx context.Context, dir string, target time.Time) error

	// ShipWAL ép đóng segment hiện tại rồi đẩy mọi WAL đã archive lên dst.
	//
	// # Đây mới là thứ chặn RPO — không phải archive_timeout
	//
	// Hai lý do, và cả hai đều ĐO ĐƯỢC chứ không suy ra từ tài liệu:
	//
	// Một, thư mục archive nằm CÙNG ĐĨA với dữ liệu nó bảo vệ. Mất máy là mất cả
	// hai. Chừng nào WAL chưa rời khỏi máy đó thì "khôi phục theo thời điểm" chỉ
	// đúng với ca hỏng dữ liệu logic, không đúng với ca mất máy — mà ca mất máy
	// mới là ca người ta mua sao lưu để phòng.
	//
	// Hai, `archive_timeout` KHÔNG đáng tin để đóng segment trên một database ghi
	// thưa. Đo trên postgres:16-alpine với `archive_timeout=60s`: một giao dịch
	// nhỏ đơn lẻ KHÔNG làm postgres chuyển segment trong 180 giây, trong khi 150
	// giao dịch thì chuyển sau ~45 giây. Nên nền tảng phải TỰ ép đóng segment
	// theo nhịp của mình; `archive_timeout` chỉ còn là lưới đỡ.
	//
	// Vì thế RPO thật của hệ thống là CHU KỲ GỌI hàm này, cộng thời gian đẩy —
	// một con số nền tảng nắm trong tay, thay vì một con số phó mặc cho tải ghi
	// của app.
	ShipWAL(ctx context.Context, dst target.Target, prefix string) (Shipped, error)
}

// Shipped — kết quả một lượt đẩy WAL.
type Shipped struct {
	// Segments — số segment đã đẩy lên trong lượt này.
	Segments int
	// Bytes — tổng số byte đã đẩy.
	Bytes int64
	// Newest — segment mới nhất hiện có trên dst sau lượt này.
	//
	// Đây là thứ trả lời "khôi phục được tới đâu", nên nó phải đi ra ngoài chứ
	// không nằm lại trong log.
	Newest string
}

// ArchiveStatus — trạng thái ghi WAL liên tục.
type ArchiveStatus struct {
	// Enabled — archive_mode đang bật.
	Enabled bool
	// Timeout — khoảng ép chuyển segment kể cả khi chưa đầy.
	//
	// Đây là con số QUYẾT ĐỊNH RPO, và là chỗ một bản hiện thực cẩu thả sẽ xanh
	// trên máy ghi nhiều rồi hỏng im lặng trên máy ghi ít: PostgreSQL chỉ
	// archive một segment khi nó đầy 16 MB, nên một database thưa có thể HÀNG
	// GIỜ không archive gì dù `archive_mode=on`.
	Timeout time.Duration
	// LastArchived — segment gần nhất đã archive xong.
	LastArchived string
	// FailedCount — số lần `archive_command` thất bại.
	//
	// Khác 0 nghĩa là WAL đang DỒN LẠI trên đĩa: postgres giữ segment cho tới
	// khi archive được, nên một archive_command hỏng sẽ làm đầy đĩa rồi dừng cả
	// cụm. Đây là thứ phải cảnh báo, không phải thứ để trong log.
	FailedCount int64
}

// ErrPITRNotEnabled — chưa bật archiving mà đã đòi base backup hay restore.
var ErrPITRNotEnabled = errors.New("addons: continuous archiving is not enabled")

// PITROf trả năng lực PITR của một addon, hoặc nil nếu nó không có.
//
// Hàm nhỏ thay cho type assertion rải rác: nó cho một chỗ duy nhất để đặt godoc
// giải thích vì sao có addon không có năng lực này.
func PITROf(a Addon) PITR {
	p, ok := a.(PITR)
	if !ok {
		return nil
	}
	return p
}
