// Package signedtest — registry + bộ fuzz bit-flip cho MỌI artifact có chữ ký
// (SEC-02).
//
// # Vì sao nằm trong internal/ chứ không ở keenrig-tests/
//
// Cùng lý do storetest/addontest/targettest/formattest nằm trong internal/:
// module ngoài KHÔNG import được `internal/`. Bộ fuzz phải gọi thẳng hàm xác
// thực thật của từng package, nên nó phải sống cùng nhà với chúng.
package signedtest

import (
	"fmt"
	"sort"
	"sync"
)

// SEC-02 — "fuzz bit-flip MỌI artifact ký → 100% bị từ chối".
//
// # Vấn đề của chữ "MỌI", và cách khung này giải
//
// Gate liệt kê năm loại artifact ký: cert push, license, update, manifest,
// command promote. Hôm nay mới có MỘT (manifest phát hành); bốn cái kia sinh ra
// ở M3 và M5. Một test viết cứng cho manifest sẽ xanh mãi mãi và **ngừng nói
// đúng** ngay khi loại thứ hai ra đời — không đỏ, không cảnh báo, chỉ là gate
// SEC-02 lặng lẽ chỉ còn phủ 1/5.
//
// Nên đây là một REGISTRY: mỗi loại artifact ký tự đăng ký một [SignedArtifact],
// và bộ fuzz chạy trên tất cả những gì đã đăng ký. Thêm một artifact ký mà quên
// đăng ký thì [MustCoverAll] đỏ — danh sách kỳ vọng nằm ngay trong test, đối
// chiếu với những gì thực sự đăng ký.
//
// # Vì sao không dùng testing.F
//
// Thứ cần rải không phải "dữ liệu ngẫu nhiên" mà là VỊ TRÍ BIT bị lật, trên một
// artifact HỢP LỆ. Fuzz của Go sinh input từ corpus và tiến hoá theo coverage;
// ở đây không gian đã biết trước và hữu hạn (mỗi byte × 8 bit), nên duyệt có hệ
// thống vừa rẻ hơn vừa cho khẳng định mạnh hơn: *không một* vị trí nào lọt.

// SignedArtifact — một loại artifact có chữ ký, đủ để bộ fuzz làm việc với nó
// mà KHÔNG cần biết nó là gì.
type SignedArtifact struct {
	// Name — tên loại, dùng trong tên subtest và trong kiểm phủ.
	Name string
	// Valid trả về một artifact HỢP LỆ, mới tinh, mỗi lần gọi.
	//
	// Trả về bản mới mỗi lần chứ không dùng chung một slice: bộ fuzz sẽ sửa
	// bytes tại chỗ, và dùng chung sẽ làm phép thử thứ hai chạy trên rác của
	// phép thử thứ nhất.
	Valid func() []byte
	// Verify xác thực. Trả nil nghĩa là CHẤP NHẬN.
	Verify func([]byte) error
}

var (
	signedMu   sync.Mutex
	signedList []SignedArtifact
)

// RegisterSigned đăng ký một loại artifact ký vào bộ fuzz SEC-02.
//
// Gọi từ chính package sinh ra artifact đó (qua một file _test.go hoặc một hàm
// khởi tạo trong bộ test), để việc thêm artifact và việc phủ nó bằng fuzz nằm
// cạnh nhau — chứ không phải hai chỗ mà chỗ thứ hai sẽ bị quên.
func RegisterSigned(a SignedArtifact) {
	if a.Name == "" || a.Valid == nil || a.Verify == nil {
		panic("chaos: RegisterSigned thiếu Name/Valid/Verify")
	}
	signedMu.Lock()
	defer signedMu.Unlock()
	signedList = append(signedList, a)
}

// SignedArtifacts trả mọi loại đã đăng ký, đã sắp xếp theo tên.
func SignedArtifacts() []SignedArtifact {
	signedMu.Lock()
	defer signedMu.Unlock()
	out := append([]SignedArtifact(nil), signedList...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MustCoverAll đối chiếu danh sách đã đăng ký với danh sách KỲ VỌNG.
//
// Trả lỗi mô tả cả hai chiều lệch: loại có trong kỳ vọng mà chưa đăng ký (ai đó
// thêm artifact ký mà quên nối vào fuzz), và loại đã đăng ký mà không có trong
// kỳ vọng (danh sách kỳ vọng đã cũ).
func MustCoverAll(want []string) error {
	got := map[string]bool{}
	for _, a := range SignedArtifacts() {
		got[a.Name] = true
	}
	var missing, extra []string
	for _, w := range want {
		if !got[w] {
			missing = append(missing, w)
		}
		delete(got, w)
	}
	for name := range got {
		extra = append(extra, name)
	}
	sort.Strings(missing)
	sort.Strings(extra)
	switch {
	case len(missing) > 0 && len(extra) > 0:
		return fmt.Errorf("chưa đăng ký: %v; đăng ký nhưng không có trong danh sách kỳ vọng: %v", missing, extra)
	case len(missing) > 0:
		return fmt.Errorf("chưa đăng ký vào bộ fuzz SEC-02: %v", missing)
	case len(extra) > 0:
		return fmt.Errorf("đã đăng ký nhưng danh sách kỳ vọng chưa có: %v", extra)
	}
	return nil
}
