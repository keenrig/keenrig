package license_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/license"
)

// Bộ test này KHÔNG có mock chữ ký: khoá Ed25519 thật sinh trong test, ký thật,
// verify thật. Mock crypto là cách một bộ test xanh trong khi chữ ký chưa từng
// được kiểm.

type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	keys license.Keys
}

func newSigner(t *testing.T, keyID string) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{pub: pub, priv: priv, keys: license.Keys{keyID: pub}}
}

func (s *signer) sign(t *testing.T, keyID string, p contracts.LicensePayload) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	env := contracts.LicenseEnvelope{
		V:         contracts.LicenseEnvelopeV,
		KeyID:     keyID,
		Payload:   base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, raw)),
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func proPayload(expires time.Time) contracts.LicensePayload {
	return contracts.LicensePayload{
		LicenseID: "lic-1", InstanceID: "inst-1", EnvID: "env-1",
		Features: contracts.Features{
			Plan: "pro", Runtime: "swarm", MaxNodes: 10, // MaxApps/MaxDomains = 0 = ∞
		},
		IssuedAt: expires.Add(-30 * 24 * time.Hour), ExpiresAt: expires, GraceDays: 14,
	}
}

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// --- vòng đời ---------------------------------------------------------------

func TestAValidLicenseGrantsExactlyWhatItSays(t *testing.T) {
	s := newSigner(t, "active")
	st, err := license.Verify(s.sign(t, "active", proPayload(now.Add(24*time.Hour))), s.keys, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st.Status != license.StatusValid || st.Features.Runtime != "swarm" || st.Features.MaxNodes != 10 {
		t.Fatalf("state = %+v", st)
	}
}

func TestGraceKeepsFullRightsThenTheFloorApplies(t *testing.T) {
	s := newSigner(t, "active")
	expired := now.Add(-24 * time.Hour) // hết hạn hôm qua, grace 14 ngày
	raw := s.sign(t, "active", proPayload(expired))

	// Trong grace: ĐỦ quyền. Grace mà giảm quyền thì nó chỉ là hết hạn có trì
	// hoãn thông báo.
	st, err := license.Verify(raw, s.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != license.StatusGrace || st.Features.Runtime != "swarm" {
		t.Fatalf("trong grace phải đủ quyền: %+v", st)
	}

	// Quá grace: về SÀN starter — nhưng vẫn là một license đọc được, không phải lỗi.
	after := now.Add(15 * 24 * time.Hour)
	st, err = license.Verify(raw, s.keys, after)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != license.StatusExpired {
		t.Fatalf("status = %s, muốn expired", st.Status)
	}
	if st.Features.Runtime != "docker" || st.Features.MaxApps != contracts.StarterMaxApps {
		t.Fatalf("quá grace phải về sàn starter, được %+v", st.Features)
	}
	// App vượt sàn bị chặn, app ĐANG CHẠY không bị đụng — hạ bậc chỉ chặn thao
	// tác mới, và phép kiểm nhận `current` là để đúng như thế.
	if err := st.CanAddApp(contracts.StarterMaxApps); err == nil {
		t.Fatal("quá grace mà vẫn cài thêm được app vượt sàn starter")
	}
}

func TestNoLicenseFileMeansStarterNotAnError(t *testing.T) {
	st, err := license.Load(filepath.Join(t.TempDir(), "khong-ton-tai"), nil, now)
	if err != nil {
		t.Fatalf("thiếu file phải là bậc miễn phí, không phải lỗi: %v", err)
	}
	if st.Status != license.StatusNone || st.Features.Runtime != "docker" ||
		st.Features.MaxApps != contracts.StarterMaxApps || st.Features.MaxDomains != contracts.StarterMaxDomains {
		t.Fatalf("state = %+v", st)
	}
	// Sàn starter: docker chạy, swarm không.
	if err := st.RuntimeAllowed("docker"); err != nil {
		t.Errorf("docker phải LUÔN được phép: %v", err)
	}
	if err := st.RuntimeAllowed("swarm"); err == nil {
		t.Error("không license mà swarm vẫn qua")
	}
}

// File CÓ mà hỏng thì phải ĐỎ — khách đã trả tiền cho một license mà máy đang
// không nhận thì phải có một dòng đỏ nói vậy, không phải âm thầm rơi về free.
func TestACorruptedFileIsALoudErrorNotSilentStarter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license.json")
	if err := os.WriteFile(path, []byte("{rác}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := license.Load(path, nil, now); err == nil {
		t.Fatal("file hỏng phải là lỗi")
	}
}

// --- chữ ký -------------------------------------------------------------------

func TestATamperedPayloadIsRejected(t *testing.T) {
	s := newSigner(t, "active")
	raw := s.sign(t, "active", proPayload(now.Add(24*time.Hour)))

	var env contracts.LicenseEnvelope
	_ = json.Unmarshal(raw, &env)
	// Kẻ nắm file tự nâng bậc: sửa payload, giữ chữ ký.
	p := proPayload(now.Add(24 * time.Hour))
	p.Features.Runtime = "k8s"
	forged, _ := json.Marshal(p)
	env.Payload = base64.RawURLEncoding.EncodeToString(forged)
	rawForged, _ := json.Marshal(env)

	if _, err := license.Verify(rawForged, s.keys, now); !errors.Is(err, license.ErrBadSignature) {
		t.Fatalf("payload bị sửa phải là ErrBadSignature, được %v", err)
	}
}

func TestALicenseSignedByAStrangerIsRejected(t *testing.T) {
	honest := newSigner(t, "active")
	attacker := newSigner(t, "active") // khoá KHÁC, cùng key_id
	raw := attacker.sign(t, "active", proPayload(now.Add(24*time.Hour)))
	if _, err := license.Verify(raw, honest.keys, now); !errors.Is(err, license.ErrBadSignature) {
		t.Fatalf("chữ ký của khoá lạ phải bị từ chối, được %v", err)
	}
}

func TestAnUnknownKeyIDIsItsOwnError(t *testing.T) {
	s := newSigner(t, "active")
	raw := s.sign(t, "retired-2023", proPayload(now.Add(24*time.Hour)))
	if _, err := license.Verify(raw, s.keys, now); !errors.Is(err, license.ErrUnknownKey) {
		// Phân biệt với ErrBadSignature có chủ đích: "khoá đã bị xoay, cần
		// license mới" và "file bị sửa" là hai cuộc hội thoại hỗ trợ khác nhau.
		t.Fatalf("key_id lạ phải là ErrUnknownKey, được %v", err)
	}
}

// Xoay khoá: binary giữ HAI khoá, license ký bằng khoá nào cũng verify được.
func TestKeyRotationBothKeysVerify(t *testing.T) {
	active := newSigner(t, "active")
	next := newSigner(t, "next")
	keys := license.Keys{"active": active.pub, "next": next.pub}
	for name, raw := range map[string][]byte{
		"active": active.sign(t, "active", proPayload(now.Add(24*time.Hour))),
		"next":   next.sign(t, "next", proPayload(now.Add(24*time.Hour))),
	} {
		if _, err := license.Verify(raw, keys, now); err != nil {
			t.Errorf("khoá %s: %v", name, err)
		}
	}
}

// --- gates --------------------------------------------------------------------

func TestRuntimeGateSwarmDoesNotOpenK8s(t *testing.T) {
	s := newSigner(t, "active")
	st, err := license.Verify(s.sign(t, "active", proPayload(now.Add(24*time.Hour))), s.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RuntimeAllowed("docker"); err != nil {
		t.Errorf("docker: %v", err)
	}
	if err := st.RuntimeAllowed("swarm"); err != nil {
		t.Errorf("swarm (đúng bậc): %v", err)
	}
	// Hai bậc giá khác nhau — license swarm KHÔNG mở k8s.
	if err := st.RuntimeAllowed("k8s"); err == nil {
		t.Error("license swarm mở được k8s")
	}
}

func TestLimitsZeroMeansUnlimited(t *testing.T) {
	s := newSigner(t, "active")
	p := proPayload(now.Add(24 * time.Hour)) // MaxApps=0, MaxDomains=0
	st, err := license.Verify(s.sign(t, "active", p), s.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CanAddApp(10_000); err != nil {
		t.Errorf("MaxApps=0 phải là không giới hạn: %v", err)
	}
	if err := st.CanJoinNode(9); err != nil {
		t.Errorf("node thứ 10 trong hạn mức 10: %v", err)
	}
	if err := st.CanJoinNode(10); err == nil {
		t.Error("node thứ 11 vượt hạn mức 10 mà vẫn qua")
	}
}

func TestStarterFloorAllowsUpToItsLimitAndBlocksTheNext(t *testing.T) {
	st, _ := license.Load(filepath.Join(t.TempDir(), "x"), nil, now)
	for cur := 0; cur < contracts.StarterMaxApps; cur++ {
		if err := st.CanAddApp(cur); err != nil {
			t.Errorf("app thứ %d của bậc miễn phí: %v", cur+1, err)
		}
	}
	if err := st.CanAddApp(contracts.StarterMaxApps); err == nil {
		t.Errorf("bậc miễn phí cho cài app thứ %d", contracts.StarterMaxApps+1)
	}
	if err := st.CanAddDomain(contracts.StarterMaxDomains - 1); err != nil {
		t.Errorf("domain cuối cùng trong hạn mức starter: %v", err)
	}
	if err := st.CanAddDomain(contracts.StarterMaxDomains); err == nil {
		t.Errorf("bậc miễn phí cho thêm domain thứ %d", contracts.StarterMaxDomains+1)
	}
}

// --- ParseKeys ------------------------------------------------------------------

func TestParseKeysRejectsHalfEntries(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	good := "active=" + base64.RawURLEncoding.EncodeToString(pub)
	if _, err := license.ParseKeys(good); err != nil {
		t.Fatalf("chuỗi hợp lệ: %v", err)
	}
	for name, raw := range map[string]string{
		"thiếu dấu =":  "active",
		"khoá sai cỡ":  "active=" + base64.RawURLEncoding.EncodeToString([]byte("ngắn")),
		"không base64": "active=%%%",
	} {
		if _, err := license.ParseKeys(raw); err == nil {
			t.Errorf("%s: phải bị từ chối", name)
		}
	}
	if k, err := license.ParseKeys(""); err != nil || k != nil {
		t.Errorf("chuỗi rỗng = không khoá, không lỗi; được %v %v", k, err)
	}
}

// --- hợp đồng hai phía: golden do BÊN KÝ sinh, BÊN VERIFY phải nhận ------------
//
// Hai package (cloud ký, node verify) là internal/ của hai module không import
// được nhau, nên hợp đồng byte được ghim qua một fixture chung ở
// keenrig-contracts/go/testdata — bên cloud có test ký khớp từng byte với
// fixture này, bên đây phải verify được nó. Một trong hai lệch định dạng
// (mã hoá base64, cách marshal, cấu trúc phong bì) là một trong hai test đỏ.
func TestGoldenFixtureFromTheCloudSignerVerifies(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..",
		"keenrig-contracts", "go", "testdata", "license-golden.json"))
	if err != nil {
		t.Fatalf("thiếu golden fixture (bên cloud sinh bằng KEENRIG_WRITE_GOLDEN=1): %v", err)
	}
	keys, err := license.ParseKeys("golden=fqDjvVLiB8nTsOumXAcE5m_KLY4WWhdSGLF0_EFg5BM")
	if err != nil {
		t.Fatal(err)
	}
	// `now` trong hạn của fixture (ký 2026-09-01, TTL 30 ngày).
	st, err := license.Verify(raw, keys, time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("license do bên ký thật sinh ra mà bên verify từ chối: %v", err)
	}
	if st.Status != license.StatusValid || st.Features.Runtime != "swarm" || st.Features.MaxNodes != 10 {
		t.Fatalf("golden phải ra pro/swarm/10 node: %+v", st)
	}
}
