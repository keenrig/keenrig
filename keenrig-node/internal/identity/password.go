package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Băm mật khẩu bằng argon2id, định dạng PHC chuẩn:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt-b64>$<hash-b64>
//
// # Vì sao argon2id chứ không phải bcrypt
//
// bcrypt giới hạn 72 byte đầu vào (âm thầm cắt phần dư) và chỉ có một trục chi
// phí là CPU. argon2id có thêm trục BỘ NHỚ, vốn là thứ GPU/ASIC khó nhân bản —
// đúng mối đe doạ thật với một file DB bị lấy cắp.
//
// # Vì sao tham số nằm TRONG chuỗi hash
//
// Ba năm nữa ta muốn nâng m= lên. Nếu tham số nằm ở một hằng số toàn cục thì
// mọi hash cũ lập tức không xác thực được nữa. Nằm trong chuỗi thì hash cũ vẫn
// verify đúng bằng tham số cũ, và ta nâng dần khi người dùng đổi mật khẩu.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

var (
	// ErrBadPassword — mật khẩu sai. KHÔNG phân biệt với "không có user" ở tầng
	// gọi: phân biệt là cho phép dò xem tài khoản nào tồn tại.
	ErrBadPassword = errors.New("identity: invalid credentials")
	// ErrHashFormat — chuỗi hash trong DB không đọc được.
	ErrHashFormat = errors.New("identity: invalid hash string")
)

// MinPasswordLen — 12 ký tự.
//
// Chọn độ dài thay vì luật "phải có hoa/số/ký tự đặc biệt": luật thành phần
// đẩy người dùng tới "Password1!" — ngắn, đoán được, và họ dùng lại ở mọi nơi.
// Độ dài là ràng buộc duy nhất tương quan thật với độ khó dò.
const MinPasswordLen = 12

// HashPassword sinh salt ngẫu nhiên rồi băm.
func HashPassword(plain string) (string, error) {
	if len([]rune(plain)) < MinPasswordLen {
		return "", fmt.Errorf("identity: the password must be at least %d characters", MinPasswordLen)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword so sánh bằng thời gian hằng số.
//
// subtle.ConstantTimeCompare chứ không phải bytes.Equal: so sánh thường thoát
// sớm ở byte đầu khác nhau. Với hash thì rò rỉ đó ít giá trị hơn với token,
// nhưng nó không tốn gì và ta không muốn có hai quy ước so sánh trong cùng một
// codebase.
func VerifyPassword(encoded, plain string) error {
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(plain), salt, params.time, params.memory, params.threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBadPassword
	}
	return nil
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, ErrHashFormat
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParams{}, nil, nil, ErrHashFormat
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return argonParams{}, nil, nil, ErrHashFormat
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, ErrHashFormat
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return argonParams{}, nil, nil, ErrHashFormat
	}
	return p, salt, hash, nil
}
