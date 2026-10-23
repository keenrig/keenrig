// Package redis — addon Redis, MỘT CONTAINER MỖI APP.
//
// # Vì sao ngược postgres
//
// postgres dùng chung một container vì mỗi instance idle chiếm 25–50 MB, và cách
// ly được ở tầng SQL (role + REVOKE). Redis KHÔNG có tầng đó:
//
//	Không có "database riêng" thật. `SELECT n` chỉ là 16 không gian khoá trong
//	CÙNG một tiến trình, cùng một giới hạn bộ nhớ, cùng một lệnh `FLUSHALL`.
//	Một app gọi `FLUSHALL` xoá dữ liệu của mọi app khác — và nó không cần quyền
//	gì đặc biệt để làm vậy.
//
// Redis 6+ có ACL, nhưng chúng không giới hạn được bộ nhớ per-app: một app ghi
// đầy `maxmemory` làm mọi app khác bị evict. Với một nền tảng self-host mà người
// dùng cài app của người khác, đó là chia sẻ số phận.
//
// Đổi lại: redis-alpine idle chiếm ~3 MB. Một container mỗi app là cái giá rẻ
// cho cách ly ở tầng TIẾN TRÌNH — và đó là lý do bảng cân đối ra ngược postgres.
//
// # Hệ quả trên interface: KHÔNG có gì đổi
//
// `Teardown` của postgres xoá DB rồi để container chạy; ở đây nó gỡ hẳn
// container. Conformance kiểm CÙNG một khẳng định — "app A mất dữ liệu, app B
// thì không" — và mỗi driver tự chọn cách thoả. Nếu suite phải sửa để driver này
// pass thì suite đang sai, không phải driver.
//
// # Mật khẩu qua FILE CẤU HÌNH, không qua đối số hay env
//
// `redis-server --requirepass abc` hiện mật khẩu trong `docker inspect` và trong
// `ps`. Box sở hữu data directory, nên ta ghi `redis.conf` vào đó rồi trỏ Cmd
// vào file — mật khẩu không nằm trong bất kỳ chỗ nào Docker đưa ra ngoài.
package redis

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

const (
	// imageKey — khoá trong infra.json. MỘT image, nhiều container.
	imageKey  = "redis"
	redisPort = 6379
	dumpFile  = "dump.rdb"
	confFile  = "redis.conf"
	// readyTimeout — redis lên trong ~100ms; 30 giây là biên rộng cho máy tải cao.
	readyTimeout  = 30 * time.Second
	passwordBytes = 32
)

func init() {
	addons.Register(addons.KindRedis, func(ctx context.Context, cfg addons.Config) (addons.Addon, error) {
		return New(cfg)
	})
}

type Driver struct {
	cfg addons.Config
}

var _ addons.Addon = (*Driver)(nil)

func New(cfg addons.Config) (*Driver, error) {
	if cfg.Store == nil {
		return nil, errors.New("redis: Store is missing — credentials must be stored encrypted")
	}
	if cfg.Runtime == nil {
		return nil, errors.New("redis: Runtime is missing — an infrastructure container is required")
	}
	if _, ok := cfg.Images[imageKey]; !ok {
		return nil, fmt.Errorf("redis: no digest-pinned image for %q", imageKey)
	}
	return &Driver{cfg: cfg}, nil
}

func (d *Driver) Kind() addons.Kind { return addons.KindRedis }

var appIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)

func checkAppID(appID string) error {
	if !appIDRe.MatchString(appID) {
		return fmt.Errorf("redis: invalid app id: %q", appID)
	}
	return nil
}

// infraName — tên container hạ tầng CHO MỘT APP.
//
// Đây là chỗ khác postgres rõ nhất: tên phụ thuộc appID, nên mỗi app có một
// container riêng và một alias DNS riêng trên network.
func infraName(appID string) string { return "redis-" + appID }

func secretRef(appID string) string { return "addon/redis/" + appID }

type creds struct {
	Password string `json:"password"`
}

func newPassword() (string, error) {
	b := make([]byte, passwordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// --- hạ tầng -----------------------------------------------------------------------

func (d *Driver) dataDir(appID string) (string, error) {
	return d.cfg.Layout.AddonData(infraName(appID))
}

// writeConf ghi redis.conf vào data directory (box sở hữu nó).
//
// Ba dòng cấu hình, mỗi dòng có lý do:
//
//	requirepass   Không có nó thì bất kỳ container nào trên network `keenrig0`
//	              đều đọc/ghi được redis của app khác — chỉ cần biết tên.
//	appendonly no Chỉ dùng RDB. Bật AOF thì `SAVE` không còn là "toàn bộ dữ liệu
//	              nằm trong dump.rdb", và Backup sẽ bỏ mất phần trong AOF.
//	save ""       Tắt lưu tự động theo lịch. Ta gọi `SAVE` tường minh lúc Backup;
//	              lịch nền chạy song song chỉ làm thời điểm của bản dump thành
//	              không xác định.
func (d *Driver) writeConf(appID, password string) error {
	dir, err := d.dataDir(appID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("redis: creating %s: %w", dir, err)
	}
	// Mật khẩu base64 RawURL không chứa khoảng trắng, dấu nháy hay '#', nên
	// không cần trích dẫn. Kiểm lại thay vì tin: một lần đổi cách sinh mật khẩu
	// mà quên chỗ này là một file cấu hình hỏng và redis không khởi động được.
	if strings.ContainsAny(password, " \t\r\n\"'#") {
		return fmt.Errorf("redis: the password contains characters that need quoting in redis.conf")
	}
	conf := "requirepass " + password + "\nappendonly no\nsave \"\"\ndir /data\n"
	return os.WriteFile(filepath.Join(dir, confFile), []byte(conf), 0o600)
}

func (d *Driver) ensureInfra(ctx context.Context, appID, password string) (addons.InfraStatus, error) {
	if err := d.writeConf(appID, password); err != nil {
		return addons.InfraStatus{}, err
	}
	dir, err := d.dataDir(appID)
	if err != nil {
		return addons.InfraStatus{}, err
	}

	st, err := d.cfg.Runtime.EnsureInfra(ctx, addons.InfraSpec{
		Name:  infraName(appID),
		Image: d.cfg.Images[imageKey],
		// Trỏ vào file trong /data — mật khẩu KHÔNG nằm trong Cmd.
		Cmd:          []string{"redis-server", "/data/" + confFile},
		DataDir:      dir,
		Port:         redisPort,
		InfraVersion: d.cfg.InfraVersion,
	})
	if err != nil {
		return st, err
	}
	if !st.Ready {
		return st, fmt.Errorf("%w: %s: %s", addons.ErrInfraNotReady, infraName(appID), st.Message)
	}
	if err := d.waitReady(ctx, appID, password); err != nil {
		return st, err
	}
	return st, nil
}

// waitReady đợi redis trả PONG.
//
// Container "Running" chưa nghĩa là redis nhận lệnh: nó còn nạp RDB. Với một
// dataset lớn, nạp mất vài giây — và lệnh đầu tiên trong lúc đó nhận
// "LOADING Redis is loading the dataset in memory".
func (d *Driver) waitReady(ctx context.Context, appID, password string) error {
	deadline := time.Now().Add(readyTimeout)
	var last string
	for {
		res, err := d.redisCLI(ctx, appID, password, "PING")
		if err == nil && res.OK() && strings.Contains(string(res.Stdout), "PONG") {
			return nil
		}
		switch {
		case err != nil:
			last = err.Error()
		default:
			last = strings.TrimSpace(string(res.Stderr) + string(res.Stdout))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %s did not return PONG after %s: %s",
				addons.ErrInfraNotReady, infraName(appID), readyTimeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// redisCLI chạy redis-cli trong container của app.
//
// Mật khẩu qua biến REDISCLI_AUTH, KHÔNG qua `-a`: redis-cli với `-a` in cảnh
// báo "Using a password with -a is insecure" ra stderr, và mật khẩu nằm trong
// `ps`. Biến môi trường là đường redis-cli tự khuyến nghị.
func (d *Driver) redisCLI(ctx context.Context, appID, password string, args ...string) (addons.ExecResult, error) {
	return d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName(appID),
		Cmd:  append([]string{"redis-cli"}, args...),
		Env:  map[string]string{"REDISCLI_AUTH": password},
	})
}

// --- Setup -------------------------------------------------------------------------

func (d *Driver) Setup(ctx context.Context, appID string) (addons.Creds, error) {
	if err := checkAppID(appID); err != nil {
		return addons.Creds{}, err
	}
	c, err := d.loadOrCreateCreds(ctx, appID)
	if err != nil {
		return addons.Creds{}, err
	}
	st, err := d.ensureInfra(ctx, appID, c.Password)
	if err != nil {
		return addons.Creds{}, err
	}
	env := d.envFor(appID, c, st)
	if err := addons.ValidateEnv(env); err != nil {
		return addons.Creds{}, err
	}
	return addons.Creds{Env: env, SecretRef: secretRef(appID)}, nil
}

func (d *Driver) loadOrCreateCreds(ctx context.Context, appID string) (creds, error) {
	raw, err := d.cfg.Store.GetSecret(ctx, secretRef(appID))
	if err == nil {
		var c creds
		if uerr := json.Unmarshal(raw, &c); uerr != nil {
			return creds{}, fmt.Errorf("redis: the stored credentials could not be decoded: %w", uerr)
		}
		return c, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return creds{}, err
	}
	pw, err := newPassword()
	if err != nil {
		return creds{}, err
	}
	blob, err := json.Marshal(creds{Password: pw})
	if err != nil {
		return creds{}, err
	}
	if err := d.cfg.Store.PutSecret(ctx, secretRef(appID), blob); err != nil {
		return creds{}, err
	}
	return creds{Password: pw}, nil
}

func (d *Driver) envFor(appID string, c creds, st addons.InfraStatus) map[string]string {
	addr := net.JoinHostPort(st.Host, strconv.Itoa(st.Port))
	return map[string]string{
		// Định dạng URL của redis: mật khẩu nằm ở phần userinfo, user để trống.
		"KEENRIG_REDIS_URL":      "redis://:" + c.Password + "@" + addr + "/0",
		"KEENRIG_REDIS_HOST":     st.Host,
		"KEENRIG_REDIS_PORT":     strconv.Itoa(st.Port),
		"KEENRIG_REDIS_PASSWORD": c.Password,
	}
}

// --- Env ---------------------------------------------------------------------------

func (d *Driver) Env(ctx context.Context, appID string) (map[string]string, error) {
	if err := checkAppID(appID); err != nil {
		return nil, err
	}
	c, err := d.credsOf(ctx, appID)
	if err != nil {
		return nil, err
	}
	st, err := d.ensureInfra(ctx, appID, c.Password)
	if err != nil {
		return nil, err
	}
	return d.envFor(appID, c, st), nil
}

func (d *Driver) credsOf(ctx context.Context, appID string) (creds, error) {
	raw, err := d.cfg.Store.GetSecret(ctx, secretRef(appID))
	if errors.Is(err, store.ErrNotFound) {
		return creds{}, fmt.Errorf("%w: redis/%s", addons.ErrNotProvisioned, appID)
	}
	if err != nil {
		return creds{}, err
	}
	var c creds
	if err := json.Unmarshal(raw, &c); err != nil {
		return creds{}, fmt.Errorf("redis: credentials could not be decoded: %w", err)
	}
	return c, nil
}

// --- Teardown ----------------------------------------------------------------------

// Teardown gỡ HẲN container của app này, và xoá cả data directory.
//
// Khác postgres: ở đó Teardown xoá DB rồi để container chạy vì app khác đang
// dùng. Ở đây container thuộc riêng app này, nên không có gì phải giữ.
//
// Xoá data directory ở đây chứ không để cho `appdata.sh`: thư mục này nằm dưới
// `node/addons/`, không phải `apps/` — nó là dữ liệu HẠ TẦNG của app, và chủ sở
// hữu vòng đời của nó là driver addon.
func (d *Driver) Teardown(ctx context.Context, appID string) error {
	if err := checkAppID(appID); err != nil {
		return err
	}
	if _, err := d.cfg.Store.GetSecret(ctx, secretRef(appID)); errors.Is(err, store.ErrNotFound) {
		// Chưa từng setup. Vẫn gọi RemoveInfra: một container có thể sót lại từ
		// lần Teardown bị ngắt sau khi secret đã xoá.
		return d.cfg.Runtime.RemoveInfra(ctx, infraName(appID))
	} else if err != nil {
		return err
	}

	if err := d.cfg.Runtime.RemoveInfra(ctx, infraName(appID)); err != nil {
		// KHÔNG xoá secret khi container còn: xoá secret trước nghĩa là mất mật
		// khẩu để nói chuyện với một container vẫn đang chạy và giữ dữ liệu.
		return err
	}
	if dir, err := d.dataDir(appID); err == nil {
		// --one-file-system không có ở Go; nhưng thư mục này do CHÍNH TA tạo và
		// tên nó đã qua checkAppID, nên không có đường để nó trỏ ra ngoài.
		if rerr := os.RemoveAll(dir); rerr != nil {
			return fmt.Errorf("redis: deleting %s: %w", dir, rerr)
		}
	}
	if err := d.cfg.Store.DeleteSecret(ctx, secretRef(appID)); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// --- Backup / Restore --------------------------------------------------------------

// Backup buộc redis ghi RDB rồi COPY file từ data directory.
//
// Đọc file trực tiếp thay vì `redis-cli --rdb`: data directory là bind mount mà
// box sở hữu, nên đọc thẳng khỏi phải đẩy vài trăm MB qua đường exec của Docker.
func (d *Driver) Backup(ctx context.Context, appID, dir string) error {
	c, err := d.credsOf(ctx, appID)
	if err != nil {
		return err
	}
	if _, err := d.ensureInfra(ctx, appID, c.Password); err != nil {
		return err
	}

	// SAVE (đồng bộ) chứ không BGSAVE: BGSAVE trả về ngay và ta không biết lúc
	// nào file xong. Đọc file giữa lúc BGSAVE đang ghi là đọc một RDB dở.
	res, err := d.redisCLI(ctx, appID, c.Password, "SAVE")
	if err != nil {
		return err
	}
	if !res.OK() || !strings.Contains(strings.ToUpper(string(res.Stdout)), "OK") {
		return res.Err("redis SAVE cho " + appID)
	}

	src, err := d.dataDir(appID)
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(filepath.Join(src, dumpFile))
	if err != nil {
		return fmt.Errorf("redis: reading %s: %w", dumpFile, err)
	}
	if len(blob) == 0 {
		return fmt.Errorf("redis: %s is empty — an empty backup only reveals itself at restore time", dumpFile)
	}
	return os.WriteFile(filepath.Join(dir, dumpFile), blob, 0o600)
}

// Restore ghi RDB vào data directory rồi DỰNG LẠI container.
//
// Redis chỉ nạp RDB LÚC KHỞI ĐỘNG — ghi file vào một redis đang chạy không có
// tác dụng gì, và tệ hơn: lần `SAVE` tiếp theo sẽ GHI ĐÈ file vừa đặt bằng dữ
// liệu trong bộ nhớ. Nên restore bắt buộc phải qua một lần khởi động lại.
//
// RemoveInfra + EnsureInfra là "khởi động lại" bằng đúng hai primitive đã có.
// Dữ liệu sống sót vì nó nằm ở bind mount, không trong container.
func (d *Driver) Restore(ctx context.Context, appID, dir string) error {
	c, err := d.credsOf(ctx, appID)
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(filepath.Join(dir, dumpFile))
	if err != nil {
		return fmt.Errorf("redis: reading the dump: %w", err)
	}

	// Gỡ container TRƯỚC khi ghi file: một redis đang chạy có thể `SAVE` (do
	// SHUTDOWN hoặc do lệnh của app) và ghi đè đúng file ta vừa đặt.
	if err := d.cfg.Runtime.RemoveInfra(ctx, infraName(appID)); err != nil {
		return err
	}
	dst, err := d.dataDir(appID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dst, dumpFile), blob, 0o600); err != nil {
		return fmt.Errorf("redis: ghi dump: %w", err)
	}
	_, err = d.ensureInfra(ctx, appID, c.Password)
	return err
}
