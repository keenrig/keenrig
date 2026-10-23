package crypt_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/crypt"
)

const pass = "mot-passphrase-du-dai-de-qua-nguong"

func seal(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := crypt.Wrap(&buf, pass)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func openAll(t *testing.T, ct []byte, passphrase string) ([]byte, error) {
	t.Helper()
	r, err := crypt.Unwrap(bytes.NewReader(ct), passphrase)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Dữ liệu đi vào phải bằng dữ liệu đi ra, ở nhiều cỡ quanh RANH GIỚI CHUNK.
//
// Các cỡ không phải bịa: 0, đúng một chunk, đúng một chunk trừ/cộng một byte, và
// nhiều chunk lẻ. Lỗi phân chunk gần như luôn nằm đúng ở những chỗ đó, và một
// test chỉ chạy "vài KB" sẽ không bao giờ chạm tới.
func TestRoundTripAtChunkBoundaries(t *testing.T) {
	n := int(crypt.ChunkSize)
	for _, size := range []int{0, 1, n - 1, n, n + 1, 2 * n, 3*n + 7} {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i*31 + i/251)
		}
		got, err := openAll(t, seal(t, plain), pass)
		if err != nil {
			t.Errorf("size %d: %v", size, err)
			continue
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("size %d: đọc lại %d byte, khác từ byte %d", size, len(got), firstDiff(got, plain))
		}
	}
}

func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// Ghi 0 byte vẫn phải ra một stream HỢP LỆ.
//
// Ca này có thật: cây rỗng đã ra một archive tgz hợp lệ, và lớp mã hoá không
// được biến nó thành một file mà chính ta từ chối đọc.
func TestEmptyPayloadIsValidStream(t *testing.T) {
	ct := seal(t, nil)
	if len(ct) == 0 {
		t.Fatal("stream rỗng — không phân biệt được với lỗi ghi")
	}
	got, err := openAll(t, ct, pass)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("= %d byte, muốn 0", len(got))
	}
}

// Sai passphrase → ErrWrongPassphrase, và KHÔNG ra một byte plaintext nào.
func TestWrongPassphrase(t *testing.T) {
	ct := seal(t, []byte("bi mat cua instance"))
	got, err := openAll(t, ct, pass+"x")
	if !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Errorf("= %v, muốn ErrWrongPassphrase", err)
	}
	if len(got) != 0 {
		t.Errorf("trả %d byte plaintext dù xác thực thất bại", len(got))
	}
}

// Passphrase quá ngắn bị từ chối lúc TẠO, không phải lúc bị lấy cắp.
//
// Bản sao lưu là mục tiêu bẻ khoá ngoại tuyến: kẻ lấy được bucket thử vô hạn lần
// trên máy của họ. argon2id làm mỗi lần thử đắt, nhưng nó không cứu được "abc".
func TestWeakPassphraseRejectedOnWrite(t *testing.T) {
	for _, p := range []string{"", "abc", strings.Repeat("a", crypt.MinPassphraseLen-1)} {
		if _, err := crypt.Wrap(io.Discard, p); !errors.Is(err, crypt.ErrWeakPassphrase) {
			t.Errorf("Wrap(%q) = %v, muốn ErrWeakPassphrase", p, err)
		}
	}
	// Nhưng ĐỌC không được có cửa độ dài: một archive ghi bằng bản cũ, hoặc bằng
	// một chính sách khác, vẫn phải mở được. Passphrase ngắn lúc đọc chỉ có thể
	// SAI (câu trả lời về dữ liệu), không bao giờ là "quá yếu" (câu trả lời về
	// cấu hình) — nhầm hai thứ này là bảo người vận hành đi sửa cấu hình trong
	// khi thứ họ cần là gõ lại đúng passphrase.
	_, err := crypt.Unwrap(bytes.NewReader(seal(t, []byte("x"))), "ngan")
	if errors.Is(err, crypt.ErrWeakPassphrase) {
		t.Errorf("Unwrap = %v — đường ĐỌC không được ép độ dài", err)
	}
	if !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Errorf("Unwrap = %v, muốn ErrWrongPassphrase", err)
	}
}

// CẮT CỤT phải là LỖI, ở mọi vị trí cắt.
//
// Đây là cách hỏng thật nhất của một bản sao lưu: đầy đĩa hay mất mạng giữa lúc
// đẩy lên. GCM một mình KHÔNG bắt được ca này — mọi chunk còn lại đều hợp lệ.
// Thứ bắt được là cờ chunk-cuối trong nonce.
func TestTruncationIsAlwaysAnError(t *testing.T) {
	plain := bytes.Repeat([]byte("du lieu cua instance\n"), 20000) // > 3 chunk
	ct := seal(t, plain)

	hdr := crypt.PrefixLen
	cuts := []struct {
		name string
		at   int
	}{
		{"giữa header", 20},
		{"mất verifier", hdr - 1},
		{"ngay sau header", hdr},
		{"giữa chunk đầu", hdr + 1000},
		{"đúng ranh giới chunk 1", hdr + int(crypt.ChunkSize) + 16},
		{"đúng ranh giới chunk 2", hdr + 2*(int(crypt.ChunkSize)+16)},
		{"thiếu 1 byte cuối", len(ct) - 1},
	}
	for _, c := range cuts {
		t.Run(c.name, func(t *testing.T) {
			got, err := openAll(t, ct[:c.at], pass)
			if err == nil {
				t.Fatalf("stream bị cắt tại %d lại đọc hết bình thường (%d byte)", c.at, len(got))
			}
			if len(got) == len(plain) {
				t.Error("trả đủ plaintext dù stream đã cụt")
			}
			// Và lỗi KHÔNG được nói là "sai passphrase": người vận hành sẽ gõ lại
			// passphrase mãi trong khi thứ hỏng là chính bản sao lưu.
			if errors.Is(err, crypt.ErrWrongPassphrase) {
				t.Errorf("= %v — cắt cụt bị gọi nhầm thành sai passphrase", err)
			}
		})
	}
}

// Đảo THỨ TỰ hai chunk phải bị bắt.
//
// Không có counter trong nonce thì hai chunk đổi chỗ vẫn xác thực được từng cái
// một, và bản sao lưu giải nén ra dữ liệu xáo trộn mà không có gì đỏ.
func TestChunkReorderIsRejected(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), 3*int(crypt.ChunkSize))
	ct := seal(t, plain)
	size := int(crypt.ChunkSize) + 16
	hdr := crypt.PrefixLen

	swapped := bytes.Clone(ct)
	copy(swapped[hdr:hdr+size], ct[hdr+size:hdr+2*size])
	copy(swapped[hdr+size:hdr+2*size], ct[hdr:hdr+size])

	if _, err := openAll(t, swapped, pass); err == nil {
		t.Fatal("hai chunk đổi chỗ vẫn giải mã được")
	}
}

// Lật MỘT bit ở bất kỳ đâu cũng phải bị bắt.
func TestBitFlipIsRejected(t *testing.T) {
	ct := seal(t, bytes.Repeat([]byte("du lieu"), 20000))
	for _, at := range []int{0, 20, crypt.PrefixLen - 1, crypt.PrefixLen, crypt.PrefixLen + 500, len(ct) / 2, len(ct) - 1} {
		bad := bytes.Clone(ct)
		bad[at] ^= 0x01
		if _, err := openAll(t, bad, pass); err == nil {
			t.Errorf("lật bit tại %d vẫn giải mã được", at)
		}
	}
}

// Header là dữ liệu TỪ BÊN NGOÀI, và tham số vô lý trong đó phải bị từ chối
// TRƯỚC khi gọi argon2.
//
// Một archive dựng tay khai `mem = 4 TiB` sẽ làm tiến trình restore bị OOM kill
// — một cú DoS bằng một file, ngay lúc instance đang cần restore nhất.
func TestAbsurdKDFParamsRejectedBeforeDerivation(t *testing.T) {
	ct := seal(t, []byte("x"))
	// mem nằm ở byte 20..24 (magic 14 + ver 1 + kdf 1 + time 4).
	bad := bytes.Clone(ct)
	bad[20], bad[21], bad[22], bad[23] = 0xff, 0xff, 0xff, 0xff
	_, err := crypt.Unwrap(bytes.NewReader(bad), pass)
	if !errors.Is(err, crypt.ErrBadStream) {
		t.Errorf("= %v, muốn ErrBadStream", err)
	}
}

// Không phải stream của ta → ErrBadStream, không phải "sai passphrase".
//
// Hai lỗi dẫn tới hai hành động khác nhau: đi tìm đúng file, hay gõ lại
// passphrase. Đoán nhầm làm người vận hành gõ lại mãi một passphrase đúng.
func TestNotOurStream(t *testing.T) {
	for _, junk := range [][]byte{
		nil,
		[]byte("ngan"),
		bytes.Repeat([]byte("khong phai archive"), 100),
		append([]byte("KEENRIG-BACKUP"), bytes.Repeat([]byte{0}, 5)...), // magic đúng, phần còn lại cụt
	} {
		_, err := crypt.Unwrap(bytes.NewReader(junk), pass)
		if !errors.Is(err, crypt.ErrBadStream) {
			t.Errorf("Unwrap(%d byte rác) = %v, muốn ErrBadStream", len(junk), err)
		}
	}
}

// CheckPassphrase trả lời được chỉ với PrefixLen byte đầu.
//
// Thứ tự thao tác của restore phụ thuộc vào điều này: kiểm TRƯỚC khi tải về
// gigabyte. Sai passphrase lộ ra sau vài chục byte thay vì sau mười phút — và ở
// giữa mười phút đó là một người vận hành đang mất dữ liệu.
func TestCheckPassphraseNeedsOnlyThePrefix(t *testing.T) {
	ct := seal(t, bytes.Repeat([]byte("du lieu rat dai"), 100000))
	prefix := ct[:crypt.PrefixLen]

	if err := crypt.CheckPassphrase(bytes.NewReader(prefix), pass); err != nil {
		t.Errorf("passphrase đúng mà báo %v", err)
	}
	if err := crypt.CheckPassphrase(bytes.NewReader(prefix), pass+"x"); !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Errorf("= %v, muốn ErrWrongPassphrase", err)
	}
	// Thiếu một byte của prefix thì KHÔNG được đoán bừa.
	if err := crypt.CheckPassphrase(bytes.NewReader(prefix[:len(prefix)-1]), pass); !errors.Is(err, crypt.ErrBadStream) {
		t.Errorf("prefix cụt = %v, muốn ErrBadStream", err)
	}
}

// Sửa header bị bắt ở verifier, không phải ở giữa chừng lần giải nén.
//
// Header không được mã hoá, nên nó là chỗ dễ sửa nhất. Verifier phủ cả 45 byte
// của nó, nên đổi `chunk` hay `time` thành một lỗi rõ ràng ngay từ đầu thay vì
// một lỗi khó hiểu sau khi đã ghi nửa cây ra đĩa.
func TestHeaderTamperIsCaughtByVerifier(t *testing.T) {
	ct := seal(t, bytes.Repeat([]byte("x"), 5000))
	// chunk size nằm ở 4 byte cuối của header (offset 41..45).
	bad := bytes.Clone(ct)
	bad[41], bad[42], bad[43], bad[44] = 0x00, 0x01, 0x00, 0x00 // 64 KiB → 65536, đổi sang giá trị khác
	bad[44] = 0x01
	if _, err := openAll(t, bad, pass); err == nil {
		t.Fatal("sửa header vẫn giải mã được")
	}
}

// HasMagic phân biệt archive đã mã hoá với archive chưa.
//
// Cần cho ca restore một bản sao lưu cũ chưa mã hoá: nói đúng "bản này không mã
// hoá" thay vì "sai passphrase".
func TestHasMagic(t *testing.T) {
	if !crypt.HasMagic(seal(t, []byte("x"))) {
		t.Error("stream của chính ta lại không nhận ra")
	}
	// tgz bắt đầu bằng 1f 8b.
	if crypt.HasMagic([]byte{0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Error("nhận nhầm một archive gzip là stream đã mã hoá")
	}
	if crypt.HasMagic([]byte("KEENRIG")) {
		t.Error("nhận nhầm một prefix ngắn hơn magic")
	}
}

// Hai lần mã hoá cùng một dữ liệu phải ra HAI chuỗi byte khác nhau.
//
// Salt ngẫu nhiên mỗi archive là thứ làm counter bắt đầu từ 0 vẫn an toàn. Hệ
// quả đã ghi trong godoc: tính tất định của tgz KHÔNG còn ở tầng ciphertext, nên
// "bản đêm nay có khác đêm qua không" phải so băm của archive TRƯỚC khi mã hoá.
func TestSaltMakesEveryArchiveDifferent(t *testing.T) {
	plain := []byte("cung mot noi dung")
	if bytes.Equal(seal(t, plain), seal(t, plain)) {
		t.Error("hai lần mã hoá ra cùng một chuỗi byte — salt không ngẫu nhiên")
	}
}

// Không đặt biến → ErrNoPassphrase, lỗi RIÊNG.
func TestPassphraseFromEnv(t *testing.T) {
	if _, err := crypt.PassphraseFromEnv(nil); !errors.Is(err, crypt.ErrNoPassphrase) {
		t.Errorf("lookup nil = %v, muốn ErrNoPassphrase", err)
	}
	for _, v := range []string{"", "   ", "\t\n"} {
		_, err := crypt.PassphraseFromEnv(func(string) (string, bool) { return v, true })
		if !errors.Is(err, crypt.ErrNoPassphrase) {
			t.Errorf("giá trị %q = %v, muốn ErrNoPassphrase", v, err)
		}
	}
	// Khoảng trắng đầu/cuối KHÔNG bị cắt: nó là ký tự hợp lệ của passphrase, và
	// cắt nó đi làm bản sao lưu ghi bằng phiên bản này mở không được bằng phiên
	// bản khác.
	got, err := crypt.PassphraseFromEnv(func(k string) (string, bool) {
		if k == crypt.EnvPassphrase {
			return "  co khoang trang  ", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "  co khoang trang  " {
		t.Errorf("= %q — khoảng trắng bị cắt", got)
	}
}

// Quên Close là tạo ra một archive KHÔNG đọc được — và nó phải hỏng NGAY, không
// phải hỏng lúc restore.
//
// Chunk cuối là thứ duy nhất đánh dấu "stream đã hết", và nó chỉ được ghi ở
// Close. Test này khoá hành vi đó lại: nếu ai đó sau này làm Write tự đóng dấu
// cuối thì bản sao lưu bị ngắt giữa chừng sẽ trở thành hợp lệ.
func TestForgettingCloseYieldsAnUnreadableStream(t *testing.T) {
	var buf bytes.Buffer
	w, err := crypt.Wrap(&buf, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("x"), 3*int(crypt.ChunkSize))); err != nil {
		t.Fatal(err)
	}
	// KHÔNG Close.
	if _, err := openAll(t, buf.Bytes(), pass); err == nil {
		t.Error("stream chưa Close lại đọc được — dấu hiệu 'hết stream' không còn tường minh")
	}
}

// Backup ghi TRUOC khi doi ten du an van phai NHAN RA duoc.
//
// Magic cu "SPEEDUP-BACKUP" va magic moi deu dai 14 byte, nen bo cuc header
// khong doi va mot stream cu chi khac dung 14 byte dau. Bai nay bat duoc hai
// cach hong: bo legacyMagic (HasMagic tu choi stream cu), va doi do dai magic
// (14 byte thay vao khong con phu het magic moi).
func TestLegacyMagicIsStillRecognised(t *testing.T) {
	stream := seal(t, []byte("noi dung backup cu"))
	if !crypt.HasMagic(stream) {
		t.Fatal("HasMagic tu choi stream vua ghi ra")
	}

	legacy := []byte("SPEEDUP-BACKUP") // 14 byte, dung bang magic hien tai
	old := append([]byte{}, stream...)
	copy(old, legacy)

	if !crypt.HasMagic(old) {
		t.Fatal("HasMagic tu choi magic cu — backup ghi truoc khi doi ten thanh khong nhan ra duoc")
	}

	// Nhung DOC thi phai hong: header la AAD cua moi chunk, nen sua magic lam
	// sai xac thuc. Day la bang chung magic that su nam trong AAD chu khong chi
	// la mot nhan trang tri o dau file.
	r, err := crypt.Unwrap(bytes.NewReader(old), pass)
	if err == nil {
		if _, e := io.ReadAll(r); e == nil {
			t.Fatal("doc duoc stream da bi sua magic — header khong nam trong AAD?")
		}
	}
}
