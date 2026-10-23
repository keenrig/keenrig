package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Client REST tối giản cho Kubernetes API.
//
// # Vì sao KHÔNG dùng k8s.io/client-go
//
// client-go là lựa chọn đúng cho một controller thật. Ở đây nó sai cỡ:
//
//   - Ta cần đúng 6 thao tác: apply/get/delete Deployment, apply/delete
//     Service, list Pod. client-go mang theo scheme, informer, workqueue,
//     discovery, và một cây phụ thuộc lớn hơn toàn bộ keenrig-node.
//   - Binary là MỘT file cho MỌI bậc. Bậc docker miễn phí sẽ phải tải thêm
//     ~40MB cho một driver họ không bao giờ dùng.
//
// Đây là cùng lập luận đã dùng cho internal/metrics (không lấy client_golang)
// và internal/identity (tự viết TOTP): phụ thuộc nặng chỉ đáng khi ta dùng
// phần lớn của nó.
//
// # Giới hạn, nói thẳng
//
// Client này hỗ trợ: token (in-cluster + kubeconfig), client certificate, CA
// tuỳ chỉnh. KHÔNG hỗ trợ: exec credential plugin (aws eks get-token, gke
// gcloud), auth-provider đã lỗi thời, impersonation. Với BYO kubeconfig của
// EKS/GKE dùng exec plugin, người vận hành phải cấp một ServiceAccount token
// thay vì kubeconfig của cloud CLI — và lỗi lúc mở nói đúng điều đó.
// Khi nào cần đủ các cơ chế trên thì đổi sang client-go; hình dạng Driver
// không đổi vì mọi lời gọi đã đi qua đúng một chỗ là file này.
type restClient struct {
	base      string
	token     string
	namespace string
	http      *http.Client
}

const (
	// inClusterTokenPath — kubelet mount ServiceAccount vào đây.
	inClusterTokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAPath     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	inClusterNSPath     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	defaultHTTPTimeout  = 30 * time.Second
	defaultNamespaceEnv = "KEENRIG_K8S_NAMESPACE"
)

// newInClusterClient dựng client khi keenrig-box CHÍNH LÀ một pod.
func newInClusterClient() (*restClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("k8s: not running inside a cluster (KUBERNETES_SERVICE_HOST/PORT missing)")
	}
	token, err := os.ReadFile(inClusterTokenPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: reading the ServiceAccount token: %w", err)
	}
	pool := x509.NewCertPool()
	if ca, err := os.ReadFile(inClusterCAPath); err == nil {
		pool.AppendCertsFromPEM(ca)
	}
	ns := "default"
	if b, err := os.ReadFile(inClusterNSPath); err == nil && len(bytes.TrimSpace(b)) > 0 {
		ns = string(bytes.TrimSpace(b))
	}
	return &restClient{
		base:      "https://" + host + ":" + port,
		token:     strings.TrimSpace(string(token)),
		namespace: ns,
		http: &http.Client{
			Timeout:   defaultHTTPTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// kubeconfig — chỉ những trường ta thật sự đọc.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string         `yaml:"token"`
			ClientCertificateData string         `yaml:"client-certificate-data"`
			ClientKeyData         string         `yaml:"client-key-data"`
			Exec                  map[string]any `yaml:"exec"`
			AuthProvider          map[string]any `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// newKubeconfigClient dựng client từ file kubeconfig.
func newKubeconfigClient(path string) (*restClient, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("k8s: reading kubeconfig %s: %w", path, err)
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("k8s: parse kubeconfig %s: %w", path, err)
	}
	if kc.CurrentContext == "" {
		return nil, fmt.Errorf("k8s: kubeconfig %s has no current-context", path)
	}

	var clusterName, userName, ns string
	for _, c := range kc.Contexts {
		if c.Name == kc.CurrentContext {
			clusterName, userName, ns = c.Context.Cluster, c.Context.User, c.Context.Namespace
		}
	}
	if clusterName == "" {
		return nil, fmt.Errorf("k8s: kubeconfig has no context %q", kc.CurrentContext)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	server := ""
	for _, c := range kc.Clusters {
		if c.Name != clusterName {
			continue
		}
		server = c.Cluster.Server
		if c.Cluster.InsecureSkipTLSVerify {
			// Tôn trọng lựa chọn của người vận hành nhưng KHÔNG im lặng: đây là
			// tắt xác thực server, và nó phải đọc được trong log.
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // do kubeconfig khai tường minh
		}
		pool := x509.NewCertPool()
		switch {
		case c.Cluster.CertificateAuthorityData != "":
			pem, derr := base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorityData)
			if derr != nil {
				return nil, fmt.Errorf("k8s: certificate-authority-data is malformed: %w", derr)
			}
			pool.AppendCertsFromPEM(pem)
			tlsCfg.RootCAs = pool
		case c.Cluster.CertificateAuthority != "":
			pem, rerr := os.ReadFile(c.Cluster.CertificateAuthority)
			if rerr != nil {
				return nil, fmt.Errorf("k8s: reading certificate-authority: %w", rerr)
			}
			pool.AppendCertsFromPEM(pem)
			tlsCfg.RootCAs = pool
		}
	}
	if server == "" {
		return nil, fmt.Errorf("k8s: kubeconfig has no cluster %q", clusterName)
	}

	token := ""
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		// Từ chối SỚM và nói rõ: exec plugin là cách EKS/GKE cấp token, và nếu
		// ta im lặng bỏ qua thì lỗi sẽ hiện ra dưới dạng 401 khó hiểu lúc deploy.
		if len(u.User.Exec) > 0 {
			return nil, fmt.Errorf("k8s: kubeconfig uses an exec credential plugin (%v) — "+
				"this driver does not support it; issue a ServiceAccount token and use a static-token kubeconfig",
				u.User.Exec["command"])
		}
		if len(u.User.AuthProvider) > 0 {
			return nil, fmt.Errorf("k8s: kubeconfig uses auth-provider (deprecated) — use a ServiceAccount token instead")
		}
		token = u.User.Token
		if u.User.ClientCertificateData != "" && u.User.ClientKeyData != "" {
			certPEM, err1 := base64.StdEncoding.DecodeString(u.User.ClientCertificateData)
			keyPEM, err2 := base64.StdEncoding.DecodeString(u.User.ClientKeyData)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("k8s: the client cert/key in kubeconfig is malformed")
			}
			pair, perr := tls.X509KeyPair(certPEM, keyPEM)
			if perr != nil {
				return nil, fmt.Errorf("k8s: client cert/key could not be paired: %w", perr)
			}
			tlsCfg.Certificates = []tls.Certificate{pair}
		}
	}
	if token == "" && len(tlsCfg.Certificates) == 0 {
		return nil, fmt.Errorf("k8s: kubeconfig has neither a token nor a client certificate for user %q", userName)
	}

	if ns == "" {
		ns = "default"
	}
	return &restClient{
		base:      strings.TrimSuffix(server, "/"),
		token:     token,
		namespace: ns,
		http: &http.Client{
			Timeout:   defaultHTTPTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// apiError mang mã HTTP để caller phân biệt 404 với lỗi thật.
type apiError struct {
	Status int
	Body   string
	Path   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("k8s: %s → %d: %s", e.Path, e.Status, strings.TrimSpace(e.Body))
}

func isNotFound(err error) bool {
	var ae *apiError
	return asAPIError(err, &ae) && ae.Status == http.StatusNotFound
}

func isConflict(err error) bool {
	var ae *apiError
	return asAPIError(err, &ae) && ae.Status == http.StatusConflict
}

func asAPIError(err error, out **apiError) bool {
	for err != nil {
		if ae, ok := err.(*apiError); ok {
			*out = ae
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (c *restClient) do(ctx context.Context, method, path, contentType string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &apiError{Status: resp.StatusCode, Body: string(raw), Path: method + " " + path}
	}
	return raw, nil
}

func (c *restClient) get(ctx context.Context, path string, out any) error {
	raw, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *restClient) post(ctx context.Context, path string, body, out any) error {
	raw, err := c.do(ctx, http.MethodPost, path, "application/json", body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// put dùng cho update toàn phần (replace). Kubernetes yêu cầu resourceVersion
// khớp — đó là optimistic locking của nó, cùng vai trò với Version.Index của swarm.
func (c *restClient) put(ctx context.Context, path string, body, out any) error {
	raw, err := c.do(ctx, http.MethodPut, path, "application/json", body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *restClient) delete(ctx context.Context, path string) error {
	_, err := c.do(ctx, http.MethodDelete, path, "", nil)
	if err != nil && isNotFound(err) {
		return nil // xoá thứ không còn tồn tại là thành công
	}
	return err
}

// ping kiểm kết nối + quyền ngay lúc mở driver.
func (c *restClient) ping(ctx context.Context) error {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := c.get(ctx, "/version", &v); err != nil {
		return fmt.Errorf("k8s: could not reach the API server: %w", err)
	}
	return nil
}
