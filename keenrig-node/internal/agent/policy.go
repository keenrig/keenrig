package agent

import (
	"math/rand"
	"time"
)

// Chính sách poll — nhịp gọi lên cloud, và cách nó phản ứng khi mọi thứ hỏng.
//
// # Vì sao đây là một kiểu riêng, tách khỏi vòng lặp
//
// Đây là phần DUY NHẤT của agent có luật phức tạp, và cũng là phần khó kiểm
// nhất nếu nó nằm lẫn trong một vòng lặp có `time.Sleep`. Tách ra thì nó là một
// hàm thuần: trạng thái + kết quả lần gọi vừa rồi → khoảng chờ tiếp theo. Test
// chạy trong micro-giây và không cần tua đồng hồ.
//
// # Ba luật, mỗi luật vì một cách một fleet tự giết chính nó
//
//	tôn trọng next_poll_ms   Server điều khiển nhịp (AG-03). Agent tự quyết định
//	                         nhịp nghĩa là cloud không hạ tải được khi quá tải —
//	                         đúng lúc nó cần nhất.
//	429 → backoff, cap 5'    Không backoff thì một cloud đang ngộp nhận nguyên
//	                         lượng traffic cũ cộng thêm phần thử lại. Cap 5 phút
//	                         vì quá đó thì một lần cloud hồi phục mất quá lâu
//	                         mới được nhận ra.
//	JITTER, luôn luôn        10k agent khởi động lại cùng lúc sau một sự cố sẽ
//	                         gọi lên cùng một giây nếu không có jitter — cloud
//	                         vừa sống lại đã bị đạp xuống. Đây là AG-04.
const (
	// DefaultInterval — nhịp khi chưa biết gì (chưa sync lần nào).
	DefaultInterval = 30 * time.Second
	// MinInterval — sàn tuyệt đối, kể cả khi server bảo nhanh hơn.
	//
	// Server nói `next_poll_ms: 100` vì một lỗi cấu hình sẽ biến fleet thành
	// một cuộc tấn công vào chính nó. Sàn nằm ở phía AGENT vì phía agent là nơi
	// chịu hậu quả và là nơi không sửa được từ xa.
	MinInterval = time.Second
	// MaxBackoff — trần thời gian chờ khi cloud lỗi hoặc 429.
	MaxBackoff = 5 * time.Minute
	// JitterFrac — biên độ nhiễu, ±20% khoảng chờ.
	JitterFrac = 0.2
)

// Outcome — kết quả một lần gọi sync, thứ quyết định nhịp tiếp theo.
type Outcome struct {
	// OK — sync thành công.
	OK bool
	// NextPollMS — server yêu cầu nhịp này (0 = không nói gì).
	NextPollMS int
	// RetryAfter — server trả 429 kèm Retry-After (0 = không phải 429).
	RetryAfter time.Duration
	// Err — lỗi mạng hoặc lỗi máy chủ.
	Err error
}

// Policy giữ trạng thái backoff giữa các lần gọi.
type Policy struct {
	// fails — số lần liên tiếp thất bại. Reset về 0 khi thành công.
	fails int
	// rand cho phép test cố định jitter. nil → dùng nguồn toàn cục.
	rand *rand.Rand
}

// NewPolicy dựng chính sách. r nil = jitter thật.
func NewPolicy(r *rand.Rand) *Policy { return &Policy{rand: r} }

// Next trả khoảng chờ trước lần gọi tiếp theo.
//
// Thứ tự ưu tiên có chủ đích:
//
//  1. 429 kèm Retry-After — server đang nói THẲNG là chờ bao lâu. Không có gì
//     agent biết rõ hơn thế.
//  2. Lỗi — backoff mũ từ nhịp hiện tại, cap 5 phút.
//  3. Thành công — theo `next_poll_ms`, kẹp trong [MinInterval, MaxBackoff].
//
// Mọi nhánh đều đi qua jitter. Không có đường nào trả về một con số tròn.
func (p *Policy) Next(o Outcome) time.Duration {
	switch {
	case o.RetryAfter > 0:
		// Vẫn tính là thất bại: một agent bị 429 liên tục mà không tăng backoff
		// sẽ bám đúng ở ngưỡng hạn mức mãi mãi.
		p.fails++
		return p.jitter(clamp(o.RetryAfter, MinInterval, MaxBackoff))

	case !o.OK || o.Err != nil:
		p.fails++
		return p.jitter(backoff(p.fails))

	default:
		p.fails = 0
		d := DefaultInterval
		if o.NextPollMS > 0 {
			d = time.Duration(o.NextPollMS) * time.Millisecond
		}
		return p.jitter(clamp(d, MinInterval, MaxBackoff))
	}
}

// Fails — số lần thất bại liên tiếp. Dùng cho log và metric.
func (p *Policy) Fails() int { return p.fails }

// backoff — mũ 2 từ 1 giây, cap MaxBackoff.
//
// 1s → 2s → 4s → … → 5' rồi đứng yên. Không dùng cấp số nhân lớn hơn: cloud
// hồi phục sau 30 giây mà agent còn chờ 20 phút là một sự cố tự kéo dài.
func backoff(fails int) time.Duration {
	if fails < 1 {
		fails = 1
	}
	d := time.Second
	for i := 1; i < fails && d < MaxBackoff; i++ {
		d *= 2
	}
	return clamp(d, MinInterval, MaxBackoff)
}

// jitter rút một giá trị ngẫu nhiên trong CỬA SỔ quanh d, đã cắt cho vừa biên.
//
// # Hai bản trước đều sai, và cái sai thứ hai chỉ lộ ra vì đếm phân bố
//
// Bản 1 kẹp TRƯỚC khi rải nhiễu: ở trần 5 phút, +20% cho ra 6 phút — "trần"
// không phải trần.
//
// Bản 2 kẹp SAU khi rải nhiễu. Không vượt biên nữa, nhưng test đếm phân bố phát
// hiện 200 agent chỉ cho ~95 khoảng chờ khác nhau ở lần thử lại ĐẦU TIÊN. Lý do:
// backoff đầu là 1 giây = đúng bằng MinInterval, nên NỬA DƯỚI của cửa sổ nhiễu
// (0,8s–1,0s) bị kẹp về đúng một điểm. Phép kẹp tạo ra một ĐỈNH XÁC SUẤT ngay
// tại biên — và biên chính là chỗ cả fleet cùng đứng sau một sự cố.
//
// Nói cách khác: chống thundering herd hỏng đúng vào lúc cần nó nhất, và nó
// hỏng theo cách không thể thấy được nếu chỉ kiểm "giá trị có nằm trong biên
// không".
//
// Bản này rút đều trong cửa sổ [max(lo, d−span), min(hi, d+span)]. Không có
// điểm nào bị dồn, và cả hai biên đều được tôn trọng.
func (p *Policy) jitter(d time.Duration) time.Duration {
	span := time.Duration(float64(d) * JitterFrac)
	lo := clamp(d-span, MinInterval, MaxBackoff)
	hi := clamp(d+span, MinInterval, MaxBackoff)
	if hi <= lo {
		return lo
	}
	var f float64
	if p.rand != nil {
		f = p.rand.Float64()
	} else {
		f = rand.Float64()
	}
	return lo + time.Duration(float64(hi-lo)*f)
}

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
