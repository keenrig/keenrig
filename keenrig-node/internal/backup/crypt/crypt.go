// Package crypt — mã hoá bản sao lưu bằng một passphrase RIÊNG.
//
// # Vì sao lớp này tồn tại, và vì sao nó nằm ĐÚNG ở đây
//
// Snapshot chứa `instance/master.key` — khoá bọc mọi secret của mọi app. Để nó
// trong bản sao lưu là điều kiện CẦN: một bản sao lưu mà rebuild T0 không mở
// được nếu thiếu một thứ máy cháy mang theo thì nó không phải bản sao lưu, và
// điều đó chỉ lộ ra đúng lúc rebuild. Nhưng "tự đủ" không được đồng nghĩa với
// "ai cầm cũng mở được": bản sao lưu nằm trên NAS dùng chung và bucket S3 có
// credential rò rỉ là hai ca THẬT.
//
// Nên archive được mã hoá bằng `KEENRIG_BACKUP_PASSPHRASE` — thứ DUY NHẤT người
// vận hành phải giữ ngoài hệ thống.
//
// Vị trí: giữa `format` và `target`. Không nhét vào tgz (driver format thứ hai
// phải viết lại), không nhét vào s3 (driver `dir` sẽ không có). Nó là một lớp
// bọc stream, đúng chỗ hai seam gặp nhau.
//
// # KHÔNG sinh passphrase hộ
//
// Sinh hộ rồi cất vào `instance/` là quay lại đúng ca "khoá cháy cùng máy", chỉ
// khác tên biến. Không đặt biến → [ErrNoPassphrase], và caller phải kêu to.
//
// Hệ quả phải nói thẳng: **mất passphrase là mất tất cả.** Không có cửa sau, và
// đó là điều kiện để lớp này có nghĩa.
//
// # Cấu trúc stream, và mỗi lựa chọn vì một cách hỏng cụ thể
//
//	header 45 byte, KHÔNG mã hoá, nhưng được xác thực (AAD của MỌI chunk)
//	  magic  14B  "KEENRIG-BACKUP"    nhìn là biết, kể cả khi đuôi file nói sai
//	  ver     1B  = 1
//	  kdf     1B  = 1 (argon2id)
//	  time    4B  · mem 4B (KiB) · threads 1B    tham số argon2 ĐI THEO archive
//	  salt   16B
//	  chunk   4B  cỡ chunk plaintext
//	verifier 16B  tag GCM của plaintext RỖNG, AAD = 45 byte header
//	sau đó: các chunk AES-256-GCM, mỗi chunk = 64 KiB plaintext + 16B tag
//
// **Tham số KDF đi theo archive, không nằm trong code.** Nếu chúng nằm trong
// code thì nâng tham số cho máy mới sẽ làm mọi archive cũ mở không được — và
// đó là mất dữ liệu do một lần chỉnh cấu hình.
//
// **Verifier 16 byte trả lời "passphrase có đúng không" mà không cần đọc dữ
// liệu.** Không có nó thì hai lỗi khác hẳn nhau trở nên không phân biệt được:
// một archive bị cắt cụt GIỮA chunk đầu trông y hệt một passphrase sai — cả hai
// chỉ là một lần `Open` thất bại. Người vận hành sẽ gõ lại một passphrase đúng
// mãi trong khi thứ hỏng là bản sao lưu. Nó còn cho [CheckPassphrase] fail
// nhanh: sai passphrase lộ ra sau 61 byte, không phải sau khi tải về 3 GB.
//
// **Chunk, không phải một khối.** Snapshot là gigabyte; `aead.Open` trên một
// khối nghĩa là giữ cả bản sao lưu trong RAM trên VPS 2 vCPU. Chunk cũng cho ta
// thứ quan trọng hơn: dữ liệu được XÁC THỰC TRƯỚC KHI đi ra ngoài. Giải mã một
// khối rồi mới kiểm tag là đã ghi 3 GB dữ liệu chưa xác thực ra đĩa.
//
// **Nonce = counter(11B) || cờ-chunk-cuối(1B), không phải ngẫu nhiên.** Đây là
// chỗ chống được cách tấn công mà GCM một mình không chống: cắt bớt và đảo thứ
// tự. Counter làm chunk đổi chỗ không giải mã được; cờ ở chunk cuối làm một
// archive bị cắt cụt thành LỖI thay vì thành "khôi phục xong, thiếu một nửa".
// Salt ngẫu nhiên 16 byte cho mỗi archive nên counter bắt đầu từ 0 vẫn an toàn:
// khoá khác nhau thì cặp (khoá, nonce) không lặp.
//
// # Đánh đổi: archive mã hoá KHÔNG còn tất định
//
// `tgz` cố ý tất định để "bản đêm nay có khác đêm qua không" trả lời được bằng
// một phép so băm. Salt ngẫu nhiên xoá mất tính chất đó ở tầng ciphertext. Cách
// giữ lại: metadata snapshot ghi **băm của archive TRƯỚC khi mã hoá**. Muốn so
// hai bản thì so con số đó, đừng so byte của file. Ghi ở đây vì đây là chỗ tính
// chất kia bị mất.
package crypt

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// EnvPassphrase — biến mang passphrase. KHÔNG có giá trị mặc định và KHÔNG sinh
// hộ; xem godoc package.
const EnvPassphrase = "KEENRIG_BACKUP_PASSPHRASE"

// MinPassphraseLen — độ dài tối thiểu khi TẠO bản sao lưu.
//
// Bản sao lưu là mục tiêu bẻ khoá NGOẠI TUYẾN: kẻ lấy được bucket có thể thử vô
// hạn lần trên máy của họ, không ai chặn được. argon2id làm mỗi lần thử đắt,
// nhưng nó không cứu được `abc`. Từ chối lúc CẤU HÌNH — ồn ào, sửa được ngay —
// thay vì lúc bản sao lưu bị lấy đi.
//
// Chỉ ép khi ghi. Lúc đọc thì nhận mọi passphrase: archive cũ không có lỗi gì.
const MinPassphraseLen = 12

var (
	// ErrNoPassphrase — chưa đặt EnvPassphrase.
	//
	// Lỗi RIÊNG, không gộp vào "cấu hình sai": "chưa bật mã hoá sao lưu" dẫn tới
	// một hành động khác hẳn "passphrase quá ngắn".
	ErrNoPassphrase = errors.New("crypt: no backup passphrase configured")
	// ErrWeakPassphrase — passphrase ngắn hơn MinPassphraseLen.
	ErrWeakPassphrase = errors.New("crypt: backup passphrase is too short")
	// ErrBadStream — không phải stream của Keenrig, hoặc header hỏng.
	ErrBadStream = errors.New("crypt: not a Keenrig encrypted backup")
	// ErrWrongPassphrase — verifier trong header không mở được.
	//
	// DỨT KHOÁT, không phải suy đoán: verifier là một tag GCM riêng, không dính
	// tới dữ liệu, nên nó trả lời đúng một câu "khoá dẫn xuất có khớp không".
	// Nhờ vậy nó tách hẳn khỏi ErrCorrupt — hai lỗi dẫn tới hai hành động khác
	// nhau (gõ lại passphrase, hay đi tìm bản sao lưu khác), và bắt người vận
	// hành tự đoán giữa lúc đang mất dữ liệu là điều tệ nhất làm được ở đây.
	ErrWrongPassphrase = errors.New("crypt: wrong passphrase, or the backup was not encrypted by this instance")
	// ErrCorrupt — một chunk không xác thực được, hoặc stream bị CẮT CỤT.
	//
	// Cắt cụt PHẢI là lỗi: một bản sao lưu thiếu đuôi giải nén ra nửa cây rồi
	// báo thành công là cách restore "xong" với một nửa dữ liệu.
	ErrCorrupt = errors.New("crypt: the backup is corrupt or truncated")
)

// Tham số argon2id mặc định khi TẠO. Đọc thì dùng tham số ghi trong header.
//
// 64 MiB × 3 lượt: chạy một lần cho mỗi lần sao lưu, nên vài trăm ms trên VPS 2
// vCPU là cái giá không ai thấy — trong khi nó nhân chi phí của kẻ dò từ điển
// lên nhiều bậc.
const (
	defaultTime    uint32 = 3
	defaultMemKiB  uint32 = 64 * 1024
	defaultThreads uint8  = 4
	saltLen               = 16
	keyLen                = 32 // AES-256
	// ChunkSize — plaintext mỗi chunk.
	ChunkSize uint32 = 64 * 1024
)

// Trần cho tham số ĐỌC TỪ HEADER. Header không được mã hoá, nên nó là dữ liệu
// từ bên ngoài: một archive dựng tay khai `mem = 4 TiB` sẽ làm tiến trình
// restore bị OOM kill — một cú DoS bằng một file, ngay lúc instance đang cần
// restore nhất.
const (
	maxMemKiB  uint32 = 1024 * 1024 // 1 GiB
	maxTime    uint32 = 16
	maxThreads uint8  = 16
	maxChunk   uint32 = 4 * 1024 * 1024
	minChunk   uint32 = 4 * 1024
)

// magic — 14 byte, va con so 14 la mot RANG BUOC chu khong phai tinh co.
//
// headerLen tinh tu no, va header duoc dung lam AAD cho MOI chunk. Doi do
// dai magic la doi bo cuc header, tuc la moi ban backup da ghi truoc do
// khong con doc duoc.
//
// Ten cu "SPEEDUP-BACKUP" cung dai dung 14 byte, nen doi thuong hieu KHONG
// pha duoc dinh dang: doc van chap nhan ca hai (xem legacyMagic), ghi thi
// dung ten moi. Mot magic la DANH TINH cua dinh dang, khong phai nhan hieu.
var magic = []byte("KEENRIG-BACKUP")

// legacyMagic — magic truoc khi doi ten du an. Chi chap nhan khi DOC.
var legacyMagic = []byte("SPEEDUP-BACKUP")

const headerLen = 14 + 1 + 1 + 4 + 4 + 1 + saltLen + 4

// PrefixLen — số byte đứng trước chunk đầu tiên (header + verifier).
//
// Xuất ra vì [CheckPassphrase] chỉ cần đúng chừng này byte, và caller muốn đọc
// trước một đoạn từ Target thì cần biết đọc bao nhiêu.
const PrefixLen = headerLen + aeadOverhead

// verifierCtr — counter DÀNH RIÊNG cho verifier, không chunk nào dùng.
//
// Chunk đếm từ 0 lên; để chạm tới giá trị này cần 2^64 chunk, tức nhiều hơn số
// byte có thể tồn tại. Nhờ vậy verifier và chunk không bao giờ dùng chung một
// cặp (khoá, nonce) — điều kiện sống còn của GCM.
const verifierCtr uint64 = ^uint64(0)

// PassphraseFromEnv đọc passphrase. Không đặt hoặc rỗng → [ErrNoPassphrase].
func PassphraseFromEnv(lookup func(string) (string, bool)) (string, error) {
	if lookup == nil {
		return "", ErrNoPassphrase
	}
	v, ok := lookup(EnvPassphrase)
	// KHÔNG TrimSpace: khoảng trắng đầu/cuối là ký tự hợp lệ của passphrase, và
	// cắt nó đi làm bản sao lưu ghi bằng phiên bản này mở không được bằng phiên
	// bản khác. Chỉ coi chuỗi TOÀN khoảng trắng là "chưa đặt".
	if !ok || strings.TrimSpace(v) == "" {
		return "", ErrNoPassphrase
	}
	return v, nil
}

// HasMagic nhận biết stream đã mã hoá qua vài byte đầu.
//
// Dùng để restore một archive KHÔNG mã hoá mà vẫn nói đúng lý do khi thất bại:
// "bản sao lưu này không mã hoá" là một câu khác hẳn "sai passphrase", và đoán
// nhầm sẽ làm người vận hành gõ lại passphrase mãi.
func HasMagic(prefix []byte) bool {
	if len(prefix) < len(magic) {
		return false
	}
	head := string(prefix[:len(magic)])
	return head == string(magic) || head == string(legacyMagic)
}

// --- header ----------------------------------------------------------------------

type header struct {
	time    uint32
	memKiB  uint32
	threads uint8
	salt    [saltLen]byte
	chunk   uint32
	raw     [headerLen]byte // dùng làm AAD; giữ nguyên byte đã đọc/ghi
}

func newHeader() (*header, error) {
	h := &header{time: defaultTime, memKiB: defaultMemKiB, threads: defaultThreads, chunk: ChunkSize}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return nil, fmt.Errorf("crypt: generating salt: %w", err)
	}
	b := h.raw[:0]
	b = append(b, magic...)
	b = append(b, 1, 1)
	b = binary.BigEndian.AppendUint32(b, h.time)
	b = binary.BigEndian.AppendUint32(b, h.memKiB)
	b = append(b, h.threads)
	b = append(b, h.salt[:]...)
	b = binary.BigEndian.AppendUint32(b, h.chunk)
	if len(b) != headerLen {
		return nil, fmt.Errorf("crypt: header is %d bytes, expected %d", len(b), headerLen)
	}
	return h, nil
}

func readHeader(r io.Reader) (*header, error) {
	h := &header{}
	if _, err := io.ReadFull(r, h.raw[:]); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadStream, err)
	}
	b := h.raw[:]
	if !HasMagic(b) {
		return nil, fmt.Errorf("%w: wrong magic bytes", ErrBadStream)
	}
	if v := b[14]; v != 1 {
		return nil, fmt.Errorf("%w: stream version %d is not supported by this build", ErrBadStream, v)
	}
	if k := b[15]; k != 1 {
		return nil, fmt.Errorf("%w: key derivation function %d is not supported by this build", ErrBadStream, k)
	}
	h.time = binary.BigEndian.Uint32(b[16:20])
	h.memKiB = binary.BigEndian.Uint32(b[20:24])
	h.threads = b[24]
	copy(h.salt[:], b[25:25+saltLen])
	h.chunk = binary.BigEndian.Uint32(b[25+saltLen:])

	// Kiểm TRẦN trước khi gọi argon2: header không được mã hoá nên nó là dữ liệu
	// ngoài. Xem godoc của maxMemKiB.
	switch {
	case h.time == 0 || h.time > maxTime:
		return nil, fmt.Errorf("%w: argon2 time cost %d is out of range 1..%d", ErrBadStream, h.time, maxTime)
	case h.memKiB == 0 || h.memKiB > maxMemKiB:
		return nil, fmt.Errorf("%w: argon2 memory %d KiB is out of range 1..%d", ErrBadStream, h.memKiB, maxMemKiB)
	case h.threads == 0 || h.threads > maxThreads:
		return nil, fmt.Errorf("%w: argon2 parallelism %d is out of range 1..%d", ErrBadStream, h.threads, maxThreads)
	case h.chunk < minChunk || h.chunk > maxChunk:
		return nil, fmt.Errorf("%w: chunk size %d is out of range %d..%d", ErrBadStream, h.chunk, minChunk, maxChunk)
	}
	return h, nil
}

func (h *header) aead(passphrase string) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(passphrase), h.salt[:], h.time, h.memKiB, h.threads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// verifier — tag GCM của plaintext RỖNG với chính header làm AAD.
func (h *header) verifier(aead cipher.AEAD) []byte {
	return aead.Seal(nil, nonce(verifierCtr, false), nil, h.raw[:])
}

// checkVerifier phân biệt DỨT KHOÁT "sai passphrase" với mọi lỗi khác.
//
// Nó cũng bảo vệ luôn header: verifier phủ cả 45 byte kia, nên sửa `chunk` hay
// `time` trong một archive bắt được ở đây thay vì thành một lỗi khó hiểu ở giữa
// chừng lần giải nén.
func (h *header) checkVerifier(aead cipher.AEAD, got []byte) error {
	if _, err := aead.Open(nil, nonce(verifierCtr, false), got, h.raw[:]); err != nil {
		return ErrWrongPassphrase
	}
	return nil
}

// nonce dựng từ counter và cờ chunk cuối. Xem godoc package.
func nonce(ctr uint64, last bool) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[3:11], ctr)
	if last {
		n[11] = 1
	}
	return n[:]
}

// --- ghi -----------------------------------------------------------------------

// Wrap bọc w thành một stream mã hoá.
//
// Caller PHẢI Close: chunk cuối — thứ duy nhất đánh dấu "stream đã hết" — chỉ
// được ghi ở đó. Quên Close là tạo ra một archive mà chính ta cũng từ chối đọc.
func Wrap(w io.Writer, passphrase string) (io.WriteCloser, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, fmt.Errorf("%w: %d characters, at least %d are required",
			ErrWeakPassphrase, len(passphrase), MinPassphraseLen)
	}
	h, err := newHeader()
	if err != nil {
		return nil, err
	}
	aead, err := h.aead(passphrase)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(h.raw[:]); err != nil {
		return nil, err
	}
	if _, err := w.Write(h.verifier(aead)); err != nil {
		return nil, err
	}
	return &writer{w: w, h: h, aead: aead, buf: make([]byte, 0, h.chunk)}, nil
}

type writer struct {
	w      io.Writer
	h      *header
	aead   cipher.AEAD
	buf    []byte
	ctr    uint64
	closed bool
}

func (e *writer) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("crypt: write after close")
	}
	n := len(p)
	for len(p) > 0 {
		room := int(e.h.chunk) - len(e.buf)
		take := min(room, len(p))
		e.buf = append(e.buf, p[:take]...)
		p = p[take:]
		if len(e.buf) == int(e.h.chunk) {
			// Chunk đầy KHÔNG được đóng dấu "cuối": ta chưa biết còn dữ liệu nữa
			// hay không. Nếu hoá ra nó là cuối thật thì Close ghi thêm một chunk
			// RỖNG có cờ — 16 byte, và đó là cái giá để "hết stream" luôn có một
			// dấu hiệu tường minh.
			if err := e.flush(false); err != nil {
				return n - len(p), err
			}
		}
	}
	return n, nil
}

func (e *writer) flush(last bool) error {
	ct := e.aead.Seal(nil, nonce(e.ctr, last), e.buf, e.h.raw[:])
	e.ctr++
	e.buf = e.buf[:0]
	_, err := e.w.Write(ct)
	return err
}

// Close ghi chunk cuối. KHÔNG đóng w — caller mở nó thì caller đóng nó.
func (e *writer) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.flush(true)
}

// --- đọc -----------------------------------------------------------------------

// Unwrap mở một stream đã mã hoá.
//
// Trả io.Reader chứ không phải io.ReadCloser: không có gì để đóng, và một Close
// giả tạo cảm giác sai rằng có tài nguyên phải trả.
func Unwrap(r io.Reader, passphrase string) (io.Reader, error) {
	// Buffer nhỏ là ĐỦ, và có chủ đích: bufio ở đây chỉ để nhìn trước MỘT byte
	// sau mỗi chunk. io.ReadFull tự lặp, và với lần đọc lớn thì bufio đọc thẳng
	// vào đích. Cấp một buffer bằng cỡ chunk là giữ thừa vài MB cho mỗi lần
	// restore mà không mua được gì.
	br := bufio.NewReaderSize(r, 8192)
	h, aead, err := openPrefix(br, passphrase)
	if err != nil {
		return nil, err
	}
	return &reader{r: br, h: h, aead: aead}, nil
}

// CheckPassphrase đọc ĐÚNG [PrefixLen] byte đầu và trả lời passphrase có mở
// được archive này không.
//
// Có mặt vì thứ tự thao tác của restore: kiểm trước khi tải về gigabyte. Sai
// passphrase lộ ra sau 61 byte thay vì sau mười phút — và ở giữa mười phút đó
// là một người vận hành đang mất dữ liệu.
func CheckPassphrase(r io.Reader, passphrase string) error {
	_, _, err := openPrefix(r, passphrase)
	return err
}

func openPrefix(r io.Reader, passphrase string) (*header, cipher.AEAD, error) {
	h, err := readHeader(r)
	if err != nil {
		return nil, nil, err
	}
	var tag [aeadOverhead]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrBadStream, err)
	}
	aead, err := h.aead(passphrase)
	if err != nil {
		return nil, nil, err
	}
	if err := h.checkVerifier(aead, tag[:]); err != nil {
		return nil, nil, err
	}
	return h, aead, nil
}

const aeadOverhead = 16 // tag GCM

type reader struct {
	r     *bufio.Reader
	h     *header
	aead  cipher.AEAD
	ct    []byte // đệm ciphertext, dùng lại giữa các chunk
	plain []byte
	ctr   uint64
	done  bool
}

func (d *reader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}

// next đọc và XÁC THỰC một chunk.
//
// "Chunk này có phải cuối không" được trả lời bằng cách nhìn TRƯỚC một byte, chứ
// không đoán từ độ dài. Đoán từ độ dài là mở cửa cho một kẻ cắt cụt đúng ranh
// giới chunk: một archive mất phần đuôi vẫn có mọi chunk còn lại hợp lệ, và
// không có gì phân biệt nó với một archive đầy đủ.
func (d *reader) next() error {
	full := int(d.h.chunk) + aeadOverhead
	if cap(d.ct) < full {
		d.ct = make([]byte, full)
	}
	buf := d.ct[:full]
	n, err := io.ReadFull(d.r, buf)
	switch {
	case err == nil:
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		if n < aeadOverhead {
			return fmt.Errorf("%w: stream ends mid-chunk (%d bytes)", ErrCorrupt, n)
		}
	default:
		return err
	}

	last := n < full
	if !last {
		if _, perr := d.r.Peek(1); errors.Is(perr, io.EOF) {
			last = true
		}
	}

	// Tới đây passphrase CHẮC CHẮN đúng — verifier trong header đã trả lời rồi.
	// Nên mọi thất bại từ điểm này là bản sao lưu hỏng hoặc bị cắt, không bao giờ
	// là "gõ sai". Đó là toàn bộ lý do verifier tồn tại.
	plain, oerr := d.aead.Open(nil, nonce(d.ctr, last), buf[:n], d.h.raw[:])
	if oerr != nil {
		if last {
			return fmt.Errorf("%w: stream ends without a valid final chunk", ErrCorrupt)
		}
		return fmt.Errorf("%w: chunk %d failed authentication", ErrCorrupt, d.ctr)
	}
	d.ctr++
	d.plain = plain
	d.done = last
	return nil
}
