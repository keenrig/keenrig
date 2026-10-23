package target

// Retention — chọn bản sao lưu nào được xoá. Viết MỘT lần, chạy trên mọi target.
//
// # Vì sao đây là code khó nhất trong package này
//
// Mọi thứ khác ở đây làm sai thì mất một bản sao lưu. Cái này làm sai thì mất
// TẤT CẢ, và nó xảy ra vào lúc không ai nhìn — retention chạy theo lịch. Nên mọi
// quyết định dưới đây nghiêng về "giữ lại thứ đáng ra phải xoá", không bao giờ
// nghiêng về chiều còn lại.
//
// Ba lựa chọn cụ thể theo nguyên tắc đó:
//
//	Policy zero → LỖI, không phải "xoá hết"   Chính sách rỗng gần như luôn là
//	                                          cấu hình bị thiếu, không phải ý
//	                                          định. Diễn giải nó thành "không
//	                                          giữ gì" là biến một dòng cấu hình
//	                                          thiếu thành mất toàn bộ lịch sử.
//	KeepLast HOẶC KeepFor (hợp)               Không phải giao. Với giao, một
//	                                          trường bị đặt sai làm trường kia
//	                                          mất tác dụng bảo vệ; với hợp thì
//	                                          mỗi trường chỉ có thể GIỮ THÊM.
//	List lỗi → không xoá gì                   Một danh sách thiếu trông giống
//	                                          hệt "các bản đó đã bị xoá", và
//	                                          phần còn lại sẽ bị coi là đủ N bản.

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Policy — giữ lại gì. Một object được GIỮ nếu thoả BẤT KỲ điều kiện nào.
type Policy struct {
	// KeepLast — giữ N object mới nhất. 0 = không dùng tiêu chí này.
	KeepLast int
	// KeepFor — giữ mọi object mới hơn khoảng này. 0 = không dùng tiêu chí này.
	KeepFor time.Duration
}

// Zero — chính sách chưa được cấu hình.
func (p Policy) Zero() bool { return p.KeepLast <= 0 && p.KeepFor <= 0 }

// PruneResult — kết quả một lần dọn.
type PruneResult struct {
	// Kept/Deleted là KEY, không phải số lượng: người vận hành cần biết đã xoá
	// CÁI GÌ, và một con số không trả lời được câu đó lúc có sự cố.
	Kept    []string
	Deleted []string
	// Failed — key xoá không được. Prune KHÔNG dừng ở lỗi đầu tiên: một object
	// bị khoá không được ngăn phần còn lại được dọn, nếu không thì đĩa đầy dần
	// vì một entry hỏng.
	Failed map[string]error
}

// Prune xoá object dưới prefix theo policy. now truyền vào để test cố định được
// thời gian.
//
// dryRun = true: tính toán đầy đủ, KHÔNG xoá gì. Đây không phải tiện nghi mà là
// một phần của thiết kế: người vận hành phải xem được retention SẼ xoá gì trước
// khi để nó chạy theo lịch lần đầu.
func Prune(ctx context.Context, t Target, prefix string, p Policy, now time.Time, dryRun bool) (PruneResult, error) {
	var res PruneResult
	if p.Zero() {
		return res, fmt.Errorf("target: the retention policy is empty — refusing to prune "+
			"(prefix %q). Set KeepLast or KeepFor", prefix)
	}
	objs, err := t.List(ctx, prefix)
	if err != nil {
		// KHÔNG xoá gì. Danh sách thiếu trông giống "đã bị xoá rồi".
		return res, fmt.Errorf("target: listing %q in order to prune: %w", prefix, err)
	}

	// Mới nhất trước. ModTime là tiêu chí chính; key giảm dần là tiêu chí phá
	// hoà — cần nó vì hai object ghi trong cùng một giây có thể có ModTime BẰNG
	// NHAU (độ phân giải mtime của một số filesystem là 1 giây, và S3 trả về
	// theo giây). Không phá hoà thì thứ tự do sort không ổn định quyết định, và
	// mỗi lần chạy retention sẽ xoá một bản khác nhau.
	sorted := append([]Object(nil), objs...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].ModTime.Equal(sorted[j].ModTime) {
			return sorted[i].ModTime.After(sorted[j].ModTime)
		}
		return sorted[i].Key > sorted[j].Key
	})

	cutoff := time.Time{}
	if p.KeepFor > 0 {
		cutoff = now.Add(-p.KeepFor)
	}

	for i, o := range sorted {
		keep := false
		if p.KeepLast > 0 && i < p.KeepLast {
			keep = true
		}
		if p.KeepFor > 0 && o.ModTime.After(cutoff) {
			keep = true
		}
		if keep {
			res.Kept = append(res.Kept, o.Key)
			continue
		}
		if dryRun {
			res.Deleted = append(res.Deleted, o.Key)
			continue
		}
		if err := t.Delete(ctx, o.Key); err != nil {
			if res.Failed == nil {
				res.Failed = map[string]error{}
			}
			res.Failed[o.Key] = err
			continue
		}
		res.Deleted = append(res.Deleted, o.Key)
	}
	return res, nil
}
