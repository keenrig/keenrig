package signedtest_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/release"
	"github.com/keenrig/keenrig/keenrig-node/internal/signedtest"
)

// SEC-02 — lật MỘT bit ở BẤT KỲ đâu trong một artifact đã ký → phải bị TỪ CHỐI,
// 100% các vị trí, không sót một chỗ nào.
//
// Duyệt CÓ HỆ THỐNG thay vì ngẫu nhiên: không gian là hữu hạn và đã biết (mỗi
// byte × 8 bit), nên duyệt hết vừa rẻ hơn vừa cho khẳng định mạnh hơn — "không
// một vị trí nào lọt" thay vì "10.000 lần thử không thấy lọt".

func init() {
	registerReleaseManifest()
}

func TestBitFlipInSignedArtifactIsAlwaysRejected(t *testing.T) {
	arts := signedtest.SignedArtifacts()
	if len(arts) == 0 {
		t.Fatal("không loại artifact ký nào đăng ký — bộ fuzz SEC-02 đang không kiểm gì")
	}

	for _, a := range arts {
		t.Run(a.Name, func(t *testing.T) {
			// Bản GỐC phải được chấp nhận. Không có khẳng định này thì một
			// Verify luôn-trả-lỗi sẽ làm cả test xanh mà không chứng minh gì.
			if err := a.Verify(a.Valid()); err != nil {
				t.Fatalf("artifact HỢP LỆ bị từ chối: %v — phần còn lại của test vô nghĩa", err)
			}

			base := a.Valid()
			accepted := 0
			for i := range base {
				for bit := range 8 {
					mutated := a.Valid()
					mutated[i] ^= 1 << bit
					if err := a.Verify(mutated); err == nil {
						accepted++
						if accepted <= 5 {
							t.Errorf("byte %d bit %d: bản đã SỬA vẫn được chấp nhận", i, bit)
						}
					}
				}
			}
			if accepted > 5 {
				t.Errorf("... và %d vị trí lật bit khác cũng lọt", accepted-5)
			}
			t.Logf("đã thử %d vị trí lật bit, %d lọt", len(base)*8, accepted)
		})
	}
}

// Danh sách KỲ VỌNG của gate SEC-02, chép từ đặc tả.
//
// Test này là chốt chặn để bộ fuzz không lặng lẽ teo lại: thêm một loại artifact
// ký mà quên nối vào registry thì nó đỏ ở đây. Loại chưa tồn tại được ghi kèm
// mốc, và dòng skip nói rõ còn thiếu gì — chứ không im lặng bỏ qua.
func TestSignedArtifactCoverage(t *testing.T) {
	// Chỉ những loại ĐÃ tồn tại mới nằm trong danh sách bắt buộc. Bốn loại còn
	// lại của SEC-02 sinh ra ở M3/M5:
	//
	//	cert push        PX-04, M3
	//	command promote  AG-*, M3
	//	license          LC-*, M5
	//	update payload   đã có chữ ký ở UP-01 nhưng verify đi qua VerifyArtifact
	//	                 (băm SHA-256), không phải chữ ký ed25519 — nó được phủ
	//	                 bởi release_test.go, không thuộc bộ này.
	want := []string{"release-manifest"}
	if err := signedtest.MustCoverAll(want); err != nil {
		t.Fatalf("bộ fuzz SEC-02 lệch danh sách kỳ vọng: %v", err)
	}
	t.Log("SEC-02 hiện phủ 1/5 loại artifact ký của đặc tả; " +
		"cert push + command promote (M3) và license (M5) sẽ đăng ký khi chúng ra đời")
}

// --- đăng ký loại artifact ký đang có ------------------------------------------

// registerReleaseManifest nối manifest phát hành (UP-01) vào bộ fuzz.
//
// Artifact được ký ở đây là CẶP (manifest, chữ ký) nối liền, vì gate nói "lật
// bit MỌI artifact ký" — mà một bit lật trong chữ ký cũng phải bị từ chối y như
// một bit lật trong nội dung.
func registerReleaseManifest() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	const keyID = "sec02"
	ring := release.Keyring{}
	if err := ring.Add(keyID, base64.StdEncoding.EncodeToString(pub)); err != nil {
		panic(err)
	}

	body, err := json.Marshal(map[string]any{
		"key_id":              keyID,
		"version":             "0.2.0",
		"min_upgradable_from": "0.1.0",
		"artifacts": []map[string]any{{
			"os": runtime.GOOS, "arch": runtime.GOARCH,
			"url":    "https://example.invalid/keenrig-box.tgz",
			"sha256": "1111111111111111111111111111111111111111111111111111111111111111",
			"size":   1024,
		}},
	})
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(priv, body)

	// Nối thành MỘT dãy byte: 4 byte độ dài manifest + manifest + chữ ký. Bộ
	// fuzz không cần biết cấu trúc; nó chỉ lật bit rồi hỏi "có nhận không".
	valid := func() []byte {
		out := make([]byte, 0, 4+len(body)+len(sig))
		n := len(body)
		out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		out = append(out, body...)
		out = append(out, sig...)
		return out
	}

	signedtest.RegisterSigned(signedtest.SignedArtifact{
		Name:  "release-manifest",
		Valid: valid,
		Verify: func(b []byte) error {
			if len(b) < 4 {
				return fmt.Errorf("quá ngắn")
			}
			n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
			if n < 0 || 4+n > len(b) {
				// Độ dài bị lật bit → không tách được. Đó cũng là TỪ CHỐI, và
				// đúng như vậy: một artifact không phân tích được thì không
				// được dùng.
				return fmt.Errorf("độ dài không hợp lệ")
			}
			manifest, signature := b[4:4+n], b[4+n:]
			_, verr := release.Verify(manifest, base64.StdEncoding.EncodeToString(signature), ring)
			return verr
		},
	})
}
