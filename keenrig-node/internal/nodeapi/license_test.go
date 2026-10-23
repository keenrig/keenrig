package nodeapi_test

// PUT /node/v1/license — cửa agent giao license mới cho box (M5).

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/nodeapi"
)

type fakeInstaller struct {
	mu    sync.Mutex
	raw   []byte
	calls int
	err   error
}

func (f *fakeInstaller) InstallLicense(raw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.raw = append([]byte(nil), raw...)
	return f.err
}

func licenseServer(t *testing.T, li nodeapi.LicenseInstaller) *httptest.Server {
	t.Helper()
	h := nodeapi.New(nodeapi.Options{
		License: li,
		Version: nodeapi.Version{Process: "keenrig-box", Version: "0.0.1-test"},
		Metrics: metrics.NewRegistry(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func putLicense(t *testing.T, srv *httptest.Server, body []byte) (int, string) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPut, srv.URL+"/node/v1/license", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

// Byte phải tới installer NGUYÊN VĂN: chữ ký Ed25519 ký trên byte, một lần
// parse-rồi-dựng-lại ở tầng HTTP là một chỗ chữ ký ngừng khớp.
func TestLicenseRouteHandsTheBytesToTheInstallerVerbatim(t *testing.T) {
	li := &fakeInstaller{}
	srv := licenseServer(t, li)
	body := []byte(`{"v":1,"key_id":"active","payload":"eyJ4IjoxfQ","signature":"c2ln"}`)

	code, out := putLicense(t, srv, body)
	if code != http.StatusOK {
		t.Fatalf("PUT license = %d (%s), muốn 200", code, out)
	}
	if li.calls != 1 || !bytes.Equal(li.raw, body) {
		t.Fatalf("installer nhận %d lần, byte khớp: %v", li.calls, bytes.Equal(li.raw, body))
	}
}

func TestARefusedLicenseComesBackWithTheReasonVerbatim(t *testing.T) {
	li := &fakeInstaller{err: errors.New("license: chữ ký không hợp lệ")}
	srv := licenseServer(t, li)

	code, out := putLicense(t, srv, []byte(`{"v":1}`))
	if code != http.StatusBadRequest {
		t.Fatalf("= %d, muốn 400", code)
	}
	// Lý do NGUYÊN VĂN: đây là dòng log duy nhất người vận hành có.
	if !strings.Contains(out, "chữ ký không hợp lệ") {
		t.Fatalf("body không mang lý do của installer: %s", out)
	}
}

func TestNoInstallerMeans501NotASilent200(t *testing.T) {
	srv := licenseServer(t, nil)
	code, _ := putLicense(t, srv, []byte(`{"v":1}`))
	if code != http.StatusNotImplemented {
		t.Fatalf("= %d, muốn 501 — nhận rồi vứt đi sẽ làm agent tưởng license đã có hiệu lực", code)
	}

	if code, _ := putLicense(t, licenseServer(t, &fakeInstaller{}), nil); code != http.StatusBadRequest {
		t.Fatalf("body rỗng = %d, muốn 400", code)
	}
}
