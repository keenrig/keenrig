package license_test

// Install — verify TRƯỚC ghi, ghi nguyên tử. Test dùng chữ ký Ed25519 thật:
// một Install viết tay quanh một Verify giả sẽ xanh mà không kiểm gì cả.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/license"
)

// signedEnvelope — một phong bì ký thật + bộ khoá verify được nó.
func signedEnvelope(t *testing.T, now time.Time) ([]byte, license.Keys) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(contracts.LicensePayload{
		LicenseID: "lic-i", InstanceID: "inst-i", EnvID: "env-i",
		Features: contracts.Features{Plan: "standard", Runtime: "docker", MaxNodes: 1},
		IssuedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), GraceDays: 14,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(contracts.LicenseEnvelope{
		V: contracts.LicenseEnvelopeV, KeyID: "active",
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, license.Keys{"active": pub}
}

func TestInstallWritesAVerifiedLicenseVerbatim(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	raw, keys := signedEnvelope(t, now)
	path := filepath.Join(t.TempDir(), "license.json")

	st, err := license.Install(path, raw, keys, now)
	if err != nil {
		t.Fatalf("Install một license hợp lệ: %v", err)
	}
	if st.Status != license.StatusValid || st.Plan != "standard" {
		t.Fatalf("state = %+v", st)
	}
	// File phải là NGUYÊN VĂN các byte đã giao: chữ ký ký trên byte, một bản
	// "tương đương JSON" là một bản không verify lại được.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("file trên đĩa khác các byte đã giao")
	}
	// Và Load — đường mà mọi admission đi — phải đọc lại được đúng bậc đó.
	back, err := license.Load(path, keys, now)
	if err != nil || back.Plan != "standard" {
		t.Fatalf("Load lại: plan=%q err=%v", back.Plan, err)
	}
}

func TestInstallRefusesATamperedLicenseAndTouchesNothing(t *testing.T) {
	now := time.Now().UTC()
	raw, keys := signedEnvelope(t, now)
	path := filepath.Join(t.TempDir(), "license.json")

	// Sửa MỘT byte trong payload (giữ nguyên chữ ký cũ): payload nằm dưới
	// base64 nên phải mở phong bì ra sửa — sửa chuỗi trong JSON ngoài chỉ đổi
	// được metadata, không đổi được thứ đã ký.
	var env contracts.LicenseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(payload, []byte(`"standard"`), []byte(`"pro"     `), 1)
	if bytes.Equal(tampered, payload) {
		t.Fatal("test hỏng: không tìm thấy chỗ để sửa")
	}
	env.Payload = base64.RawURLEncoding.EncodeToString(tampered)
	bad, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := license.Install(path, bad, keys, now); err == nil {
		t.Fatal("payload bị sửa (nâng bậc lậu) vẫn Install được")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("license hỏng đã chạm đĩa — mọi Load về sau sẽ đỏ")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("file tạm còn nằm lại")
	}
}

func TestABadInstallKeepsTheOldLicenseIntact(t *testing.T) {
	now := time.Now().UTC()
	raw, keys := signedEnvelope(t, now)
	path := filepath.Join(t.TempDir(), "license.json")
	if _, err := license.Install(path, raw, keys, now); err != nil {
		t.Fatal(err)
	}

	// Một phong bì rác đến sau — bản cũ phải còn nguyên từng byte.
	if _, err := license.Install(path, []byte(`{"v":1,"key_id":"x"}`), keys, now); err == nil {
		t.Fatal("phong bì rác vẫn được nhận")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("license cũ bị đụng: err=%v", err)
	}
}
