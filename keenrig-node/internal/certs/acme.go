package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// ACMEIssuer — xin cert qua ACME với thử thách HTTP-01 kiểu WEBROOT.
//
// # Vì sao webroot chứ không phải tự mở cổng 80
//
// Cổng 80 đã thuộc về gateway (nó phải nghe ở đó để phục vụ app và để chuyển
// hướng HTTPS). Một tiến trình thứ hai giành cổng 80 chỉ trong lúc xin cert là
// công thức cho "xin cert được nhưng app tắt 30 giây". Thay vào đó box ghi file
// thử thách vào paths.ACMEChallenges() và gateway phục vụ nó như tệp tĩnh —
// cùng mô hình certbot webroot, và là mô hình duy nhất chung sống được với một
// gateway ta không sở hữu.
//
// # Khoá tài khoản
//
// Nằm trong bảng secrets, KHÔNG sinh mới mỗi lần: CA tính rate limit theo tài
// khoản, và một tài khoản mới mỗi lần khởi động sẽ chạm trần "new account" rồi
// chạm trần "new order" mà không hiểu vì sao.
type ACMEIssuer struct {
	st        store.Store
	layout    paths.Layout
	directory string
	email     string
	// httpTimeout — trần cho toàn bộ một lần xin cert.
	timeout time.Duration
	// insecure — CHỈ cho pebble trong test/CI (xem ACMEOptions).
	insecure bool
}

// DirectoryLetsEncrypt / DirectoryLetsEncryptStaging — hai directory dùng thật.
// Pebble (dùng trong test e2e) truyền directory riêng qua ACMEOptions.
const (
	DirectoryLetsEncrypt        = acme.LetsEncryptURL
	DirectoryLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	secretACMEAccount           = "certs/acme-account-key"
	// defaultIssueTimeout — HTTP-01 phải chờ CA đi vòng qua Internet để gọi
	// ngược lại ta; 3 phút là rộng rãi mà vẫn không treo vòng lặp vô hạn.
	defaultIssueTimeout = 3 * time.Minute
)

type ACMEOptions struct {
	// Directory — URL ACME directory; rỗng → Let's Encrypt production.
	Directory string
	// Email liên hệ; CA dùng để cảnh báo cert sắp hết hạn. Rỗng cũng được.
	Email string
	// Timeout cho một lần Issue; zero → defaultIssueTimeout.
	Timeout time.Duration
	// InsecureSkipVerify CHỈ dành cho pebble trong test/CI: pebble ký bằng CA
	// tự tạo. Bật trong sản xuất là vô hiệu hoá toàn bộ giá trị của ACME.
	InsecureSkipVerify bool
}

func NewACMEIssuer(st store.Store, layout paths.Layout, opts ACMEOptions) *ACMEIssuer {
	if opts.Directory == "" {
		opts.Directory = DirectoryLetsEncrypt
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultIssueTimeout
	}
	return &ACMEIssuer{
		st: st, layout: layout,
		directory: opts.Directory,
		email:     opts.Email,
		timeout:   opts.Timeout,
		insecure:  opts.InsecureSkipVerify,
	}
}

// httpClient — client riêng khi nói chuyện với pebble (CA tự ký).
// nil nghĩa là dùng client mặc định của acme, tức là XÁC THỰC ĐẦY ĐỦ.
func (a *ACMEIssuer) httpClient() *http.Client {
	if !a.insecure {
		return nil
	}
	return &http.Client{
		Timeout: a.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // chỉ bật cho pebble, xem ACMEOptions
		},
	}
}

func (a *ACMEIssuer) Name() string { return "acme:" + a.directory }

// Issue chạy trọn một order ACME cho MỘT fqdn.
//
// Một cert một domain (không SAN gộp nhiều domain): gộp thì một domain trỏ sai
// DNS sẽ làm hỏng cert của TẤT CẢ domain trong nhóm, và người dùng thấy toàn bộ
// site chết vì một cấu hình sai ở nơi khác.
func (a *ACMEIssuer) Issue(ctx context.Context, fqdn string) (Bundle, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	client, err := a.client(ctx)
	if err != nil {
		return Bundle{}, err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(fqdn))
	if err != nil {
		return Bundle{}, fmt.Errorf("creating the order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := a.solveHTTP01(ctx, client, authzURL); err != nil {
			return Bundle{}, err
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return Bundle{}, fmt.Errorf("waiting for the order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: fqdn},
		DNSNames: []string{fqdn},
	}, key)
	if err != nil {
		return Bundle{}, err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return Bundle{}, fmt.Errorf("finalize order: %w", err)
	}
	if len(der) == 0 {
		return Bundle{}, errors.New("certs: the CA returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return Bundle{}, fmt.Errorf("parse cert: %w", err)
	}

	certPEM := encodeChainPEM(der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		FQDN:      fqdn,
		CertPEM:   certPEM,
		KeyPEM:    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		NotAfter:  leaf.NotAfter,
		IssuedAt:  time.Now(),
		IssuerURL: a.directory,
	}, nil
}

// solveHTTP01 ghi file thử thách rồi báo CA kiểm.
//
// XOÁ file trong defer: token còn nằm lại dưới webroot sau khi xong là rác lộ
// ra Internet, và nó tích tụ theo mỗi lần gia hạn.
func (a *ACMEIssuer) solveHTTP01(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("reading the authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil // CA còn nhớ lần xác thực trước
	}

	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("certs: %s has no http-01 challenge", authz.Identifier.Value)
	}

	resp, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	path, err := a.challengePath(chal.Token)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), paths.DirPerm); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(resp), 0o644); err != nil {
		return err
	}
	defer os.Remove(path)

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accepting the challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("the CA could not validate %s: %w", authz.Identifier.Value, err)
	}
	return nil
}

// challengePath — <ACMEChallenges>/.well-known/acme-challenge/<token>.
//
// Kiểm token trước khi ghép đường dẫn: token đến TỪ CA, nghĩa là từ ngoài. Một
// token chứa "/" hay ".." sẽ ghi file ra ngoài webroot. Cùng lý do
// paths.AppData từ chối segment không an toàn.
func (a *ACMEIssuer) challengePath(token string) (string, error) {
	if token == "" || strings.ContainsAny(token, `/\`) || strings.Contains(token, "..") {
		return "", fmt.Errorf("certs: unsafe challenge token: %q", token)
	}
	return filepath.Join(a.layout.ACMEChallenges(), ".well-known", "acme-challenge", token), nil
}

// client dựng acme.Client với khoá tài khoản lấy từ secrets (tạo nếu chưa có).
func (a *ACMEIssuer) client(ctx context.Context) (*acme.Client, error) {
	key, err := a.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: a.directory}
	if hc := a.httpClient(); hc != nil {
		c.HTTPClient = hc
	}

	acct := &acme.Account{}
	if a.email != "" {
		acct.Contact = []string{"mailto:" + a.email}
	}
	// Register idempotent theo nghĩa ta cần: tài khoản đã tồn tại → ErrAccountAlreadyExists.
	if _, err := c.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("registering the ACME account: %w", err)
	}
	return c, nil
}

func (a *ACMEIssuer) accountKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	raw, err := a.st.GetSecret(ctx, secretACMEAccount)
	if err == nil && len(raw) > 0 {
		var holder struct {
			KeyPEM []byte `json:"key_pem"`
		}
		if json.Unmarshal(raw, &holder) == nil {
			if blk, _ := pem.Decode(holder.KeyPEM); blk != nil {
				if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
					return k, nil
				}
			}
		}
		// Khoá hỏng: sinh lại. Mất lịch sử tài khoản ở CA nhưng vẫn xin được
		// cert — tốt hơn là kẹt vĩnh viễn.
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(map[string][]byte{
		"key_pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	})
	if err != nil {
		return nil, err
	}
	if err := a.st.PutSecret(ctx, secretACMEAccount, blob); err != nil {
		return nil, err
	}
	return k, nil
}

func encodeChainPEM(der [][]byte) []byte {
	var out []byte
	for _, b := range der {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	return out
}
