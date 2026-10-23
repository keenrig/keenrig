// Package postgres — addon PostgreSQL DÙNG CHUNG.
//
// MỘT container phục vụ mọi app. `Setup` tạo database + role riêng BÊN TRONG
// nó; `Teardown` xoá database + role của app đó, container vẫn chạy vì app khác
// đang dùng.
//
// # Vì sao dùng chung chứ không một container mỗi app
//
// Mỗi PostgreSQL idle chiếm ~25–50 MB RSS. Trên một VPS 2 GB, mười app nghĩa là
// nửa GB nằm không làm gì. Cái giá phải trả được ghi thẳng ở đây: cách ly là cách ly Ở TẦNG SQL (role + REVOKE), không
// phải ở tầng tiến trình. Một lỗ leo thang quyền trong PostgreSQL là một lỗ giữa
// các app — với redis (một container mỗi app) thì không.
//
// Đó là lý do `Setup` REVOKE quyền trên schema public và đặt owner tường minh:
// mặc định của PostgreSQL trước phiên bản 15 cho MỌI role tạo bảng trong
// public của MỌI database. Không revoke thì "database riêng" chỉ là tên gọi.
//
// # Driver KHÔNG ghi bảng `app_addons`
//
// Nó chỉ ghi `secrets` (credential của chính nó). Bảng `app_addons` là STATE
// VÒNG ĐỜI APP và thuộc reconciler — nó có khoá ngoại tới `apps`, nên driver ghi
// vào đó nghĩa là driver phải biết app đã tồn tại trong store chưa.
//
// Điều này lộ ra khi chạy conformance: suite cấp phát addon cho một app id
// KHÔNG có row trong `apps` (nó không test app, nó test addon), và `PutAppAddon`
// trả ErrNotFound. Ranh giới đúng là: driver cấp phát, reconciler ghi nhận.
//
// # Mọi lệnh đi qua Exec, không qua kết nối TCP
//
// Xem godoc addons.InfraRuntime.Exec: `pg_dump` là nhị phân chỉ có trong image,
// nên Exec là bắt buộc dù sao — và khi đã có nó, mở thêm một đường TCP cho DDL
// là hai cơ chế cho cùng một việc.
package postgres

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

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

const (
	// infraName — tên container hạ tầng. MỘT cái cho cả instance.
	infraName = "postgres"
	// superUser — role quản trị bên trong container.
	superUser = "postgres"
	// pgPort — cổng PostgreSQL nghe bên trong container.
	pgPort = 5432
	// dumpFile — tên file trong thư mục backup.
	dumpFile = "postgres.dump"
	// passwordBytes — 32 byte ngẫu nhiên mật mã → 43 ký tự base64.
	passwordBytes = 32
)

func init() {
	addons.Register(addons.KindPostgres, func(ctx context.Context, cfg addons.Config) (addons.Addon, error) {
		return New(cfg)
	})
}

type Driver struct {
	cfg addons.Config
}

var _ addons.Addon = (*Driver)(nil)

func New(cfg addons.Config) (*Driver, error) {
	if cfg.Store == nil {
		return nil, errors.New("postgres: Store is missing — credentials must be stored encrypted")
	}
	if cfg.Runtime == nil {
		return nil, errors.New("postgres: Runtime is missing — an infrastructure container is required")
	}
	if _, ok := cfg.Images[infraName]; !ok {
		// Không đoán một image mặc định: image hạ tầng phải PIN DIGEST
		// (infra.schema.json), và một mặc định không pin là chỗ `latest` lọt vào.
		return nil, fmt.Errorf("postgres: no digest-pinned image for %q", infraName)
	}
	return &Driver{cfg: cfg}, nil
}

func (d *Driver) Kind() addons.Kind { return addons.KindPostgres }

// --- định danh bên trong DB --------------------------------------------------------

// identRe — app ID hợp lệ. CÙNG luật với apps.NormalizeSlug.
var identRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)

// dbName / roleName dịch appID thành định danh SQL.
//
// Gạch ngang → gạch dưới: PostgreSQL cho phép gạch ngang trong định danh CÓ
// TRÍCH DẪN, nhưng khi đó mọi câu lệnh phải nhớ trích dẫn nó. Một chỗ quên là
// một lỗi cú pháp lúc chạy. Đổi sang gạch dưới làm định danh không cần trích
// dẫn ở mọi nơi.
//
// Tiền tố `app_` để không bao giờ trùng role hệ thống (`postgres`, `pg_*`).
func dbName(appID string) string   { return "app_" + strings.ReplaceAll(appID, "-", "_") }
func roleName(appID string) string { return "app_" + strings.ReplaceAll(appID, "-", "_") }

func checkAppID(appID string) error {
	if !identRe.MatchString(appID) {
		return fmt.Errorf("postgres: invalid app id: %q", appID)
	}
	return nil
}

// secretRef — khoá tra cứu credential trong store.Secrets.
func secretRef(appID string) string { return "addon/postgres/" + appID }

// creds — thứ lưu trong bảng secrets (đã mã hoá AES-256-GCM).
type creds struct {
	DB       string `json:"db"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// --- hạ tầng -----------------------------------------------------------------------

// ensureInfra dựng container postgres dùng chung và đợi nó nhận kết nối.
func (d *Driver) ensureInfra(ctx context.Context) (addons.InfraStatus, error) {
	dataDir, err := d.cfg.Layout.AddonData(infraName)
	if err != nil {
		return addons.InfraStatus{}, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return addons.InfraStatus{}, fmt.Errorf("postgres: creating %s: %w", dataDir, err)
	}

	// Mật khẩu superuser lưu trong secrets, KHÔNG sinh lại mỗi lần: sinh lại
	// nghĩa là container đã khởi tạo với mật khẩu cũ không nhận mật khẩu mới,
	// và mọi lệnh DDL sau đó thất bại với "password authentication failed".
	su, err := d.superPassword(ctx)
	if err != nil {
		return addons.InfraStatus{}, err
	}

	// Thư mục archive WAL nằm CẠNH pgdata, trong CÙNG một mount.
	//
	// InfraSpec chỉ có MỘT DataDir, và đó là ràng buộc chứ không phải thiếu sót:
	// thêm mount thứ hai buộc cả ba runtime driver (docker/swarm/k8s) phải hiểu
	// nó. Đặt archive vào thư mục con thì mọi driver có sẵn đều chạy được.
	//
	// Cái phải nói thẳng: WAL archive nằm CÙNG ĐĨA với dữ liệu nó bảo vệ — đúng
	// cái bẫy §3 đã chốt cho backup target. Nó CHƯA đủ để gọi là sao lưu; phần
	// đẩy nó lên `target.Target` là điều kiện để BK-03 có nghĩa ngoài phòng thí
	// nghiệm.
	if err := os.MkdirAll(filepath.Join(dataDir, walArchiveSubdir), 0o700); err != nil {
		return addons.InfraStatus{}, fmt.Errorf("postgres: creating the WAL archive directory: %w", err)
	}

	st, err := d.cfg.Runtime.EnsureInfra(ctx, addons.InfraSpec{
		Name:  infraName,
		Image: d.cfg.Images[infraName],
		// Tham số archive đi qua ĐỐI SỐ của postgres, không qua postgresql.conf.
		//
		// File conf nằm TRONG pgdata, mà pgdata chỉ tồn tại sau lần `initdb` đầu
		// tiên — nên sửa file là bài toán con-gà-quả-trứng ở lần chạy đầu. Đối số
		// thì image postgres chuyển thẳng cho server ở MỌI lần khởi động.
		//
		// Không có bí mật nào ở đây (xem cảnh báo tại ExecSpec.Cmd) — chỉ là cấu
		// hình, và `docker inspect` thấy nó là chuyện bình thường.
		Cmd: archiveArgs(),
		Env: map[string]string{
			"POSTGRES_PASSWORD": su,
			// PGDATA nằm trong một thư mục CON của volume: image postgres từ
			// chối khởi tạo vào một thư mục đã có `lost+found` (mount point).
			"PGDATA": "/var/lib/postgresql/data/pgdata",
		},
		DataDir:      dataDir,
		Port:         pgPort,
		InfraVersion: d.cfg.InfraVersion,
	})
	if err != nil {
		return st, err
	}
	if !st.Ready {
		return st, fmt.Errorf("%w: %s: %s", addons.ErrInfraNotReady, infraName, st.Message)
	}
	// Container ĐANG CHẠY ≠ postgres NHẬN KẾT NỐI.
	//
	// Image postgres khởi tạo cluster ở lần chạy đầu (initdb, tạo user, restart
	// nội bộ) — mất vài giây tới vài chục giây trên đĩa chậm. Coi "Running" là
	// "sẵn sàng" nghĩa là câu SQL đầu tiên thất bại với "the database system is
	// starting up", và app đầu tiên trên một máy mới rơi vào trạng thái error.
	//
	// Kiểm sẵn sàng thuộc DRIVER, không thuộc runtime: chỉ driver postgres biết
	// `pg_isready` là câu trả lời. Nhồi nó vào InfraRuntime nghĩa là runtime phải
	// biết cách kiểm của mọi addon sẽ có trong tương lai.
	if err := d.waitReady(ctx); err != nil {
		return st, err
	}
	return st, nil
}

// readyTimeout — trần chờ postgres nhận kết nối.
//
// 90 giây vì initdb lần đầu trên một VPS đĩa chậm có thể mất tới một phút. Trần
// quá ngắn nghĩa là lần cài đầu tiên thất bại một cách ngẫu nhiên tuỳ máy.
const readyTimeout = 90 * time.Second

func (d *Driver) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)
	var last string
	for {
		res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
			Name: infraName,
			// -h 127.0.0.1 — QUA TCP, KHÔNG qua unix socket. Đây là chi tiết
			// quyết định, và nó là một lỗi đã đo được:
			//
			// Khi khởi tạo lần đầu, entrypoint của image postgres dựng một
			// server TẠM chỉ nghe UNIX SOCKET, chạy script init, rồi TẮT nó và
			// khởi động lại server thật. `pg_isready` qua socket trả OK NGAY
			// TRONG giai đoạn tạm đó — nên ta tưởng đã sẵn sàng, gửi câu SQL đầu
			// tiên, và nhận `FATAL: the database system is shutting down`.
			//
			// Server tạm KHÔNG nghe TCP. Vì vậy "trả lời được trên TCP" là dấu
			// hiệu duy nhất phân biệt server THẬT với server tạm.
			Cmd: []string{"pg_isready", "-q", "-h", "127.0.0.1", "-U", superUser},
		})
		if err == nil && res.OK() {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = strings.TrimSpace(string(res.Stderr) + string(res.Stdout))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %s did not accept connections after %s: %s",
				addons.ErrInfraNotReady, infraName, readyTimeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

const superSecretRef = "addon/postgres/_superuser"

func (d *Driver) superPassword(ctx context.Context) (string, error) {
	raw, err := d.cfg.Store.GetSecret(ctx, superSecretRef)
	if err == nil {
		return string(raw), nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	pw, err := newPassword()
	if err != nil {
		return "", err
	}
	if err := d.cfg.Store.PutSecret(ctx, superSecretRef, []byte(pw)); err != nil {
		return "", err
	}
	return pw, nil
}

func newPassword() (string, error) {
	b := make([]byte, passwordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// base64 RawURL: không có ký tự cần escape trong URL kết nối, và không có
	// dấu '=' để một chỗ nào đó cắt mất.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// psql chạy SQL qua STDIN, không qua đối số.
//
// Đối số dòng lệnh hiện trong `ps` của mọi tiến trình trong container. Một
// `psql -c "… PASSWORD 'abc'"` là mật khẩu nằm trong process list — và với
// container DÙNG CHUNG thì "mọi tiến trình" gồm cả tiến trình của app khác.
func (d *Driver) psql(ctx context.Context, sql string) (addons.ExecResult, error) {
	su, err := d.superPassword(ctx)
	if err != nil {
		return addons.ExecResult{}, err
	}
	return d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		// -v ON_ERROR_STOP=1: không có nó thì psql chạy tiếp sau một lệnh lỗi
		// và trả mã 0 — ta sẽ tin là thành công trong khi DB chưa được tạo.
		// -h 127.0.0.1 cùng lý do với pg_isready: socket có thể là server TẠM.
		Cmd:   []string{"psql", "-v", "ON_ERROR_STOP=1", "-q", "-h", "127.0.0.1", "-U", superUser, "-d", "postgres"},
		Stdin: []byte(sql),
		Env:   map[string]string{"PGPASSWORD": su},
	})
}

// --- Setup -------------------------------------------------------------------------

// Setup cấp database + role riêng cho app. IDEMPOTENT (AD-02).
//
// Idempotent ở đây có một yêu cầu cụ thể và dễ làm sai: gọi lần thứ hai phải
// trả về credential ĐÃ CÓ, KHÔNG sinh mật khẩu mới. Reconciler gọi Setup mỗi
// vòng hội tụ; sinh mật khẩu mới nghĩa là container app đang chạy với mật khẩu
// cũ mất kết nối, DB vẫn sống, và không có gì nói ra điều đó.
func (d *Driver) Setup(ctx context.Context, appID string) (addons.Creds, error) {
	if err := checkAppID(appID); err != nil {
		return addons.Creds{}, err
	}
	st, err := d.ensureInfra(ctx)
	if err != nil {
		return addons.Creds{}, err
	}

	c, existed, err := d.loadOrCreateCreds(ctx, appID)
	if err != nil {
		return addons.Creds{}, err
	}

	// SQL luôn chạy, kể cả khi credential đã có: container có thể đã bị dựng
	// lại (INFRA_VERSION bump, hoặc người vận hành xoá volume) trong khi
	// secret vẫn còn. Chỉ tin secret là tin một thứ không phải nguồn sự thật.
	if err := d.applySQL(ctx, appID, c); err != nil {
		return addons.Creds{}, err
	}

	env := d.envFor(c, st)
	if err := addons.ValidateEnv(env); err != nil {
		return addons.Creds{}, err
	}
	_ = existed
	return addons.Creds{Env: env, SecretRef: secretRef(appID)}, nil
}

func (d *Driver) loadOrCreateCreds(ctx context.Context, appID string) (creds, bool, error) {
	raw, err := d.cfg.Store.GetSecret(ctx, secretRef(appID))
	if err == nil {
		var c creds
		if uerr := json.Unmarshal(raw, &c); uerr != nil {
			return creds{}, false, fmt.Errorf("postgres: the stored credentials could not be decoded: %w", uerr)
		}
		return c, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return creds{}, false, err
	}

	pw, err := newPassword()
	if err != nil {
		return creds{}, false, err
	}
	c := creds{DB: dbName(appID), User: roleName(appID), Password: pw}
	blob, err := json.Marshal(c)
	if err != nil {
		return creds{}, false, err
	}
	if err := d.cfg.Store.PutSecret(ctx, secretRef(appID), blob); err != nil {
		return creds{}, false, err
	}
	return c, false, nil
}

// applySQL tạo role + database, và SIẾT quyền trên schema public.
//
// Phần REVOKE là phần dễ bỏ và là phần quan trọng nhất: PostgreSQL < 15 cho MỌI
// role quyền CREATE trên schema `public` của MỌI database. Không revoke thì
// "database riêng cho từng app" chỉ là tên gọi — app A tạo được bảng trong DB
// của app B.
func (d *Driver) applySQL(ctx context.Context, appID string, c creds) error {
	// Mật khẩu đi qua STDIN cùng phần SQL còn lại; không có đối số nào chứa nó.
	// Trích dẫn theo chuẩn SQL: nhân đôi dấu nháy đơn.
	pw := strings.ReplaceAll(c.Password, "'", "''")

	// DO block để CREATE ROLE idempotent: `CREATE ROLE IF NOT EXISTS` không tồn
	// tại trong PostgreSQL.
	sql := fmt.Sprintf(`
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '%[1]s') THEN
    CREATE ROLE %[1]s LOGIN PASSWORD '%[2]s';
  ELSE
    ALTER ROLE %[1]s LOGIN PASSWORD '%[2]s';
  END IF;
END
$$;
SELECT 'CREATE DATABASE %[3]s OWNER %[1]s'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '%[3]s')
\gexec
REVOKE ALL ON DATABASE %[3]s FROM PUBLIC;
GRANT ALL PRIVILEGES ON DATABASE %[3]s TO %[1]s;
`, c.User, pw, c.DB)

	res, err := d.psql(ctx, sql)
	if err != nil {
		return err
	}
	if !res.OK() {
		return res.Err("creating role/database for " + appID)
	}

	// REVOKE trên schema public phải chạy TRONG database đó, không ở `postgres`.
	su, err := d.superPassword(ctx)
	if err != nil {
		return err
	}
	res, err = d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name:  infraName,
		Cmd:   []string{"psql", "-v", "ON_ERROR_STOP=1", "-q", "-h", "127.0.0.1", "-U", superUser, "-d", c.DB},
		Stdin: []byte(fmt.Sprintf("REVOKE ALL ON SCHEMA public FROM PUBLIC;\nGRANT ALL ON SCHEMA public TO %s;\nALTER SCHEMA public OWNER TO %s;\n", c.User, c.User)),
		Env:   map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return err
	}
	if !res.OK() {
		return res.Err("tightening public schema privileges for " + c.DB)
	}
	return nil
}

// envFor dựng bộ biến tiêm vào container app.
//
// Có CẢ _URL lẫn các phần rời: nhiều image chỉ nhận URL, nhiều image khác chỉ
// nhận host/port/user/password rời. Cấp cả hai để không phải hỏi image dùng
// kiểu nào — và vì đây là hợp đồng công khai, thêm biến sau này dễ hơn bỏ biến.
func (d *Driver) envFor(c creds, st addons.InfraStatus) map[string]string {
	addr := net.JoinHostPort(st.Host, strconv.Itoa(st.Port))
	return map[string]string{
		"KEENRIG_POSTGRES_URL":      "postgres://" + c.User + ":" + c.Password + "@" + addr + "/" + c.DB,
		"KEENRIG_POSTGRES_HOST":     st.Host,
		"KEENRIG_POSTGRES_PORT":     strconv.Itoa(st.Port),
		"KEENRIG_POSTGRES_USER":     c.User,
		"KEENRIG_POSTGRES_PASSWORD": c.Password,
		"KEENRIG_POSTGRES_DATABASE": c.DB,
	}
}

// --- Env ---------------------------------------------------------------------------

func (d *Driver) Env(ctx context.Context, appID string) (map[string]string, error) {
	if err := checkAppID(appID); err != nil {
		return nil, err
	}
	raw, err := d.cfg.Store.GetSecret(ctx, secretRef(appID))
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: postgres/%s", addons.ErrNotProvisioned, appID)
	}
	if err != nil {
		return nil, err
	}
	var c creds
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("postgres: credentials could not be decoded: %w", err)
	}
	st, err := d.ensureInfra(ctx)
	if err != nil {
		return nil, err
	}
	return d.envFor(c, st), nil
}

// --- Teardown ----------------------------------------------------------------------

// Teardown xoá database + role của app NÀY. Container vẫn chạy (AD-04).
func (d *Driver) Teardown(ctx context.Context, appID string) error {
	if err := checkAppID(appID); err != nil {
		return err
	}
	raw, err := d.cfg.Store.GetSecret(ctx, secretRef(appID))
	if errors.Is(err, store.ErrNotFound) {
		return nil // chưa từng setup — idempotent
	}
	if err != nil {
		return err
	}
	var c creds
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("postgres: credentials could not be decoded: %w", err)
	}

	if _, err := d.ensureInfra(ctx); err != nil {
		// Hạ tầng chưa lên: KHÔNG xoá secret. Xoá secret rồi mới thấy không xoá
		// được DB nghĩa là DB thành mồ côi vĩnh viễn — không còn gì nhắc rằng
		// nó thuộc về ai.
		return err
	}

	// DROP DATABASE không chạy được khi còn kết nối. Ngắt trước.
	sql := fmt.Sprintf(`
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname = '%[1]s' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS %[1]s;
DROP ROLE IF EXISTS %[2]s;
`, c.DB, c.User)
	res, err := d.psql(ctx, sql)
	if err != nil {
		return err
	}
	if !res.OK() {
		return res.Err("dropping database/role for " + appID)
	}

	// Secret xoá SAU khi DB đã sạch — thứ tự này là điều kiện để lần gọi lại
	// sau một lần thất bại giữa chừng vẫn tìm được DB cần xoá.
	if err := d.cfg.Store.DeleteSecret(ctx, secretRef(appID)); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// --- Backup / Restore --------------------------------------------------------------

// Backup ghi dump của MỘT database ra dir.
//
// Dùng định dạng custom (-Fc) chứ không plain SQL: nó nén sẵn, và `pg_restore`
// đọc được nó vào một database có tên KHÁC — điều kiện để restore vào một app
// mới mà không phải sửa nội dung dump.
func (d *Driver) Backup(ctx context.Context, appID, dir string) error {
	c, err := d.credsOf(ctx, appID)
	if err != nil {
		return err
	}
	if _, err := d.ensureInfra(ctx); err != nil {
		return err
	}
	su, err := d.superPassword(ctx)
	if err != nil {
		return err
	}

	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		Cmd:  []string{"pg_dump", "-Fc", "--no-owner", "--no-acl", "-h", "127.0.0.1", "-U", superUser, "-d", c.DB},
		Env:  map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return err
	}
	if !res.OK() {
		return res.Err("pg_dump " + c.DB)
	}
	// Dump RỖNG là lỗi, không phải "database rỗng": pg_dump của một DB không có
	// bảng vẫn sinh header. Zero byte nghĩa là exec không chuyển được stdout, và
	// một backup rỗng chỉ lộ ra vào lúc người dùng cần restore.
	if len(res.Stdout) == 0 {
		return fmt.Errorf("postgres: pg_dump %s returned 0 bytes", c.DB)
	}
	return os.WriteFile(filepath.Join(dir, dumpFile), res.Stdout, 0o600)
}

// Restore nạp dump vào database của app. GHI ĐÈ dữ liệu hiện có.
func (d *Driver) Restore(ctx context.Context, appID, dir string) error {
	c, err := d.credsOf(ctx, appID)
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(filepath.Join(dir, dumpFile))
	if err != nil {
		return fmt.Errorf("postgres: reading the dump: %w", err)
	}
	if _, err := d.ensureInfra(ctx); err != nil {
		return err
	}
	su, err := d.superPassword(ctx)
	if err != nil {
		return err
	}

	// --clean --if-exists: xoá đối tượng cũ trước khi nạp. Không có nó thì
	// restore lên một DB đã có dữ liệu sinh hàng loạt lỗi "already exists" và
	// kết quả là một DB TRỘN giữa hai thời điểm — tệ hơn cả restore thất bại.
	//
	// --no-owner: dump lấy bằng superuser, nhưng nạp lại phải thuộc role của app.
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		Cmd: []string{"pg_restore", "--clean", "--if-exists", "--no-owner", "--no-acl",
			"--role", c.User, "-h", "127.0.0.1", "-U", superUser, "-d", c.DB},
		Stdin: blob,
		Env:   map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return err
	}
	// pg_restore trả mã ≠ 0 kèm CẢNH BÁO cho những đối tượng không tồn tại lúc
	// --clean. Đó không phải lỗi. Chỉ coi là lỗi khi stderr có dòng "error:".
	if !res.OK() && strings.Contains(strings.ToLower(string(res.Stderr)), "error:") {
		return res.Err("pg_restore " + c.DB)
	}
	return nil
}

func (d *Driver) credsOf(ctx context.Context, appID string) (creds, error) {
	if err := checkAppID(appID); err != nil {
		return creds{}, err
	}
	raw, err := d.cfg.Store.GetSecret(ctx, secretRef(appID))
	if errors.Is(err, store.ErrNotFound) {
		return creds{}, fmt.Errorf("%w: postgres/%s", addons.ErrNotProvisioned, appID)
	}
	if err != nil {
		return creds{}, err
	}
	var c creds
	if err := json.Unmarshal(raw, &c); err != nil {
		return creds{}, fmt.Errorf("postgres: credentials could not be decoded: %w", err)
	}
	return c, nil
}
