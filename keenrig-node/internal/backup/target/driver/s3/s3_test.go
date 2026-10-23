package s3

// BT-01 nhánh S3 — chạy trên MinIO THẬT trong Docker.
//
// # Vì sao phải là server thật, không phải httptest
//
// Phần dễ sai nhất của driver này là CHỮ KÝ SigV4, và một server giả sẽ nhận mọi
// chữ ký ta gửi. Nó chỉ chứng minh ta gọi đúng thứ tự method của chính mình —
// đúng cái sai mà godoc của addontest đã nói.
//
// MinIO tự kiểm chữ ký và trả 403 SignatureDoesNotMatch nếu ta ký sai. Đó là
// oracle mạnh hơn mọi test vector chép tay, vì nó kiểm cả những phần ta không
// nghĩ tới: thứ tự header, mã hoá đường dẫn, canonical query, scope theo ngày.
//
// Tự SKIP khi không có Docker — skip có lý do, không biến mất im lặng.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target/targettest"
)

const (
	minioImage  = "quay.io/minio/minio:latest"
	minioUser   = "keenrigminio"
	minioSecret = "keenrigminio-secret-key"
	testBucket  = "keenrig-backup-test"
)

// endpoint của MinIO đang chạy; rỗng = không có Docker, mọi test S3 SKIP.
var endpoint string

func TestMain(m *testing.M) {
	code := func() int {
		if os.Getenv("KEENRIG_SKIP_DOCKER") != "" {
			return m.Run()
		}
		ep, stop, err := startMinio()
		if err != nil {
			fmt.Fprintf(os.Stderr, "MinIO không dựng được (%v) — test S3 sẽ SKIP\n", err)
			return m.Run()
		}
		defer stop()
		endpoint = ep
		return m.Run()
	}()
	os.Exit(code)
}

// startMinio dựng MinIO với cổng công bố ra 127.0.0.1 rồi tạo bucket.
//
// Cổng công bố là bắt buộc: driver nói HTTP từ tiến trình test (trên host), khác
// driver addon vốn chạy lệnh BÊN TRONG container và không cần host tới được.
func startMinio() (string, func(), error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil, err
	}
	port, err := freePort()
	if err != nil {
		return "", nil, err
	}
	name := fmt.Sprintf("keenrig-minio-test-%d", port)
	cmd := exec.Command("docker", "run", "-d", "--rm",
		"--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:9000", port),
		"-e", "MINIO_ROOT_USER="+minioUser,
		"-e", "MINIO_ROOT_PASSWORD="+minioSecret,
		minioImage, "server", "/data")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("docker run: %v: %s", err, out)
	}
	stop := func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	}

	ep := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitLive(ep, 60*time.Second); err != nil {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		stop()
		return "", nil, fmt.Errorf("MinIO không sẵn sàng: %v\n%s", err, logs)
	}
	if err := createBucket(ep, testBucket); err != nil {
		stop()
		return "", nil, err
	}
	return ep, stop, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// waitLive đợi endpoint /minio/health/live.
//
// Đợi ĐÚNG tín hiệu sẵn sàng của MinIO, không sleep một khoảng cố định: sleep
// ngắn thì test đỏ ngẫu nhiên, sleep dài thì mỗi lần chạy tốn thời gian đó.
func waitLive(ep string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		resp, err := http.Get(ep + "/minio/health/live")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("health trả %s", resp.Status)
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return last
}

// createBucket gọi PUT /<bucket> — dùng CHÍNH bộ ký của driver.
//
// Nghĩa là bucket chỉ tạo được nếu chữ ký đã đúng: harness thất bại trước cả khi
// suite chạy nếu SigV4 sai, và thông báo lỗi nói rõ hơn "một subtest nào đó 403".
func createBucket(ep, bucket string) error {
	u, err := url.Parse(ep + "/" + bucket)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, u.String(), nil)
	if err != nil {
		return err
	}
	sign(req, creds{keyID: minioUser, secret: minioSecret, region: "us-east-1"},
		emptySHA256, time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("tạo bucket: %w", err)
	}
	defer drain(resp)
	// 409 BucketAlreadyOwnedByYou là chấp nhận được: container --rm nên bình
	// thường không xảy ra, nhưng nó không phải lỗi.
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("tạo bucket trả %s — %s", resp.Status, errBody(resp))
	}
	return nil
}

// prefix duy nhất cho mỗi subtest — suite đòi target SẠCH.
var prefixSeq int

func newTarget(t *testing.T, maxKeys int) target.Target {
	t.Helper()
	if endpoint == "" {
		t.Skip("không có MinIO (thiếu Docker hoặc KEENRIG_SKIP_DOCKER) — bỏ qua test S3")
	}
	prefixSeq++
	d, err := New(context.Background(), Options{
		Bucket:   testBucket,
		Prefix:   fmt.Sprintf("run/%d", prefixSeq),
		Endpoint: endpoint,
		KeyID:    minioUser,
		Secret:   minioSecret,
		Insecure: true, // MinIO test chạy HTTP trên loopback
		MaxKeys:  maxKeys,
	})
	if err != nil {
		t.Fatalf("s3.New: %v", err)
	}
	return d
}

func TestS3Conformance(t *testing.T) {
	targettest.RunConformance(t, func(t *testing.T) target.Target { return newTarget(t, 0) })
}

// Phân trang: MaxKeys=2 với 5 object buộc ba trang.
//
// Bỏ phân trang là loại lỗi im lặng nhất trong cả package: S3 trả tối đa 1000 key,
// nên trên một bucket có 1500 bản sao lưu thì retention chỉ thấy 1000 bản đầu — và
// "1000 bản, giữ 30" nghĩa là nó xoá đúng những bản nó thấy rồi để lại 500 bản cũ
// hơn mãi mãi.
func TestListPaginates(t *testing.T) {
	tg := newTarget(t, 2)
	ctx := context.Background()
	want := []string{"s/01", "s/02", "s/03", "s/04", "s/05"}
	for _, k := range want {
		if err := tg.Put(ctx, k, strings.NewReader(k), int64(len(k))); err != nil {
			t.Fatal(err)
		}
	}
	objs, err := tg.List(ctx, "s/")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range objs {
		got = append(got, o.Key)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("List = %v, muốn %v — phân trang bị bỏ", got, want)
	}
}

// Credential SAI phải nổ lúc MỞ, không lúc Put.
//
// Đây là toàn bộ lý do New gọi ping: một credential sai chỉ lộ ra lúc snapshot
// đầu tiên chạy theo lịch, tức là lúc không ai xem log.
func TestBadCredentialsFailAtOpen(t *testing.T) {
	if endpoint == "" {
		t.Skip("không có MinIO")
	}
	_, err := New(context.Background(), Options{
		Bucket: testBucket, Endpoint: endpoint,
		KeyID: minioUser, Secret: "sai-be-bet", Insecure: true,
	})
	if !errors.Is(err, target.ErrBadConfig) {
		t.Fatalf("= %v, muốn ErrBadConfig", err)
	}
	// Và thông báo phải nói được điều gì. "403" một mình buộc người vận hành đi
	// đoán giữa sai khoá, sai bucket và sai giờ hệ thống.
	if !strings.Contains(err.Error(), "403") && !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Errorf("thông báo không nói vì sao: %v", err)
	}
}

func TestMissingBucketFailsAtOpen(t *testing.T) {
	if endpoint == "" {
		t.Skip("không có MinIO")
	}
	_, err := New(context.Background(), Options{
		Bucket: "khong-he-ton-tai", Endpoint: endpoint,
		KeyID: minioUser, Secret: minioSecret, Insecure: true,
	})
	if !errors.Is(err, target.ErrBadConfig) {
		t.Fatalf("= %v, muốn ErrBadConfig", err)
	}
}

// Key có ký tự cần mã hoá phải đi qua được — đây là chỗ canonicalURI hay sai.
//
// Nếu ta mã hoá khác server thì chữ ký không khớp và MinIO trả 403. Test này là
// cách duy nhất biết uriEncode đúng, vì hai bên phải mã hoá GIỐNG NHAU.
func TestKeysNeedingURIEncoding(t *testing.T) {
	tg := newTarget(t, 0)
	ctx := context.Background()
	for _, k := range []string{
		"co khoang trang.tgz",
		"dau+cong.tgz",
		"dau~nga.tgz",
		"ngoac(tron).tgz",
		"dau=bang&va.tgz",
		"tieng-viet-có-dấu.tgz",
		"phan tram %20 trong ten.tgz",
	} {
		t.Run(k, func(t *testing.T) {
			if err := tg.Put(ctx, k, strings.NewReader(k), int64(len(k))); err != nil {
				t.Fatalf("Put: %v", err)
			}
			rc, err := tg.Get(ctx, k)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer rc.Close()
			buf := new(bytes.Buffer)
			if _, err := buf.ReadFrom(rc); err != nil {
				t.Fatal(err)
			}
			if buf.String() != k {
				t.Errorf("= %q, muốn %q", buf.String(), k)
			}
			// Và nó phải xuất hiện trong List với ĐÚNG key đã ghi: nếu ta mã hoá
			// lúc ghi mà không giải mã lúc đọc thì key trong List là %20-hoá.
			objs, err := tg.List(ctx, k)
			if err != nil {
				t.Fatal(err)
			}
			if len(objs) != 1 || objs[0].Key != k {
				t.Errorf("List = %+v, muốn đúng %q", objs, k)
			}
		})
	}
}
