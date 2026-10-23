package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/keenrig/keenrig/keenrig-node/internal/buildinfo"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	addonimages "github.com/keenrig/keenrig/keenrig-node/addon-images"
	"github.com/keenrig/keenrig/keenrig-node/internal/addons"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/addons/driver/all"
	// Driver sao lưu: nạp để `backup`/`restore` chọn được chúng qua biến môi
	// trường. Cùng mô hình với ba dòng driver/all bên dưới — core không chỗ nào
	// biết tên driver cụ thể.
	"github.com/keenrig/keenrig/keenrig-node/internal/addons/infradocker"
	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/backup/format/driver/all"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/backup/target/driver/all"
	"github.com/keenrig/keenrig/keenrig-node/internal/catalog"
	"github.com/keenrig/keenrig/keenrig-node/internal/certs"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/health"
	"github.com/keenrig/keenrig/keenrig-node/internal/httpd"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity/oidc"
	"github.com/keenrig/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig/keenrig/keenrig-node/internal/jobs"
	"github.com/keenrig/keenrig/keenrig-node/internal/license"
	"github.com/keenrig/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig/keenrig/keenrig-node/internal/nodeapi"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/privops"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/all"
	"github.com/keenrig/keenrig/keenrig-node/internal/reconciler"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/runtime/driver/all"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
	"github.com/keenrig/keenrig/keenrig-node/internal/supervise"
	"github.com/keenrig/keenrig/keenrig-node/ui"
)

func main() {
	root := &cobra.Command{
		Use:           "keenrig-box",
		Short:         "Keenrig instance daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// `--version` là thứ keenrig-ota chạy thử trên binary mới TRƯỚC khi thay
	// bin/: in sai version = gói hỏng.
	root.Version = version
	root.SetVersionTemplate("keenrig-box " + version + "\n")

	var (
		dataDir       string
		httpAddr      string
		reconcileOn   bool
		secureCookies bool
	)
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run keenrig-box (node API + control API + reconciler)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(dataDir, httpAddr, reconcileOn, secureCookies)
		},
	}
	serve.Flags().StringVar(&dataDir, "data", "./data", "data directory")
	// SEC-01: mặc định LOOPBACK, không phải mọi giao diện.
	//
	// ":8080" phơi Admin UI ra Internet trên một cổng không có TLS. Đường vào
	// đúng là gateway ở 80/443 — nó chuyển tiếp về đây qua catch-all (PX-03).
	// Ai cần nghe rộng hơn vẫn đặt được bằng cờ này, nhưng đó phải là một hành
	// động tường minh chứ không phải giá trị họ vô tình thừa hưởng.
	serve.Flags().StringVar(&httpAddr, "http", "127.0.0.1:8080",
		"HTTP listen address (loopback by default — the gateway on 80/443 is the public entrance)")
	serve.Flags().BoolVar(&reconcileOn, "reconcile", true, "enable the reconcile loop (requires Docker)")
	serve.Flags().BoolVar(&secureCookies, "secure-cookies", true,
		"session cookies use __Host- + Secure (turn OFF only when serving plain HTTP in development)")
	root.AddCommand(serve)

	// backup/restore nhận CÙNG cờ --data với serve, và mỗi lệnh giữ bản sao
	// riêng: dùng chung một biến với `serve` sẽ làm giá trị mặc định của lệnh
	// này phụ thuộc thứ tự đăng ký cờ của lệnh kia.
	for _, c := range []*cobra.Command{
		newBackupCmd(&dataDir), newRestoreCmd(&dataDir), newResetPasswordCmd(&dataDir),
	} {
		c.Flags().StringVar(&dataDir, "data", "./data", "data directory")
		root.AddCommand(c)
	}
	root.AddCommand(newBackupListCmd())

	// `wal` có lệnh con, nên `--data` phải là cờ BỀN (persistent): đặt nó trên
	// từng lệnh con sẽ khiến `keenrig-box wal --data=… ship` im lặng không nhận.
	walCmd := newWALCmd(&dataDir)
	walCmd.PersistentFlags().StringVar(&dataDir, "data", "./data", "data directory")
	root.AddCommand(walCmd)

	if err := root.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func runServe(dataDir, addr string, reconcileOn, secureCookies bool) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	// layout: bố cục thư mục runtime. Driver proxy lấy MỌI đường dẫn từ đây,
	// không nhận qua env (xem proxy/registry.go).
	layout := paths.New(dataDir)

	// Di trú bố cục cũ TRƯỚC mọi thứ khác — trước cả khi mở store.
	//
	// Bản cài cũ có instancedata/ platformdata/ appsdata/. Mở store trước khi
	// đổi tên nghĩa là tạo một platform.db MỚI TINH ở chỗ mới, trong khi DB
	// thật vẫn nằm dưới tên cũ: box lên bình thường, /healthz trả 200, và mọi
	// app của người dùng biến mất. Không lỗi, không log, không manh mối.
	//
	// Lỗi ở đây thì DỪNG HẲN: chạy tiếp với một bố cục nửa vời là cách chắc
	// chắn nhất để làm hỏng thêm.
	if moved, merr := layout.MigrateLegacyLayout(); merr != nil {
		return fmt.Errorf("migrating the directory layout: %w", merr)
	} else if len(moved) > 0 {
		log.Printf("keenrig-box: renamed legacy layout: %v", moved)
	}

	// Dựng khung thư mục TRƯỚC khi mở store: layout.DB() nằm dưới instance/,
	// và MkdirAll của store chỉ tạo thư mục cha chứ không siết quyền 0700.
	if err := layout.EnsureDirs(); err != nil {
		return err
	}

	// platform.db và master.key nằm dưới instance/ (0700), KHÔNG phải ngay
	// dưới <base> (0755).
	//
	// Trước đây main tự ghép filepath.Join(dataDir, "platform.db") — lệch với
	// chính paths.DB() mà mọi phần khác dùng. Hệ quả không phải sự bất tiện:
	// installer tạo instance/ với 0700 ĐỂ bảo vệ master.key, còn box lại ghi
	// master.key vào một thư mục 0755. Mọi user trên máy đọc được khoá giải mã
	// mọi secret của instance, và không có gì trong hệ thống nói ra điều đó.
	st, err := store.Open(layout.DB(), layout.MasterKey())
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := st.AppendEvent(ctx, "box.start", "", "", nil); err != nil {
		return err
	}

	// License (M5): khoá công nhúng ldflags; env CHỈ có tác dụng ở bản build
	// không nhúng khoá (dev/test). Bản phát hành mà để env đè thì ai cũng tự
	// sinh cặp khoá, tự ký license Enterprise được — mã nguồn công khai nên
	// đây là cách vượt ai cũng đọc được (audit K1). Trạng thái đọc lại TỪ ĐĨA
	// mỗi lần cần — agent thay file license trong lúc box chạy, một bản cache
	// là một bản đã cũ. Khoá khai mà hỏng = từ chối khởi động (một khoá đọc sai
	// nghĩa là mọi license đều "giả mạo" và không ai hiểu vì sao); không khoá
	// nào = mọi thứ chạy ở sàn starter, đúng cho bản build dev.
	rawLicKeys := embeddedLicenseKeys
	if env := strings.TrimSpace(os.Getenv(envLicensePubkeys)); env != "" {
		if rawLicKeys == "" {
			rawLicKeys = env
		} else {
			log.Printf("keenrig-box: %s is ignored - this build has embedded licence keys", envLicensePubkeys)
		}
	}
	licKeys, err := license.ParseKeys(rawLicKeys)
	if err != nil {
		return fmt.Errorf("%s: %w", envLicensePubkeys, err)
	}
	licenseState := func() *license.State {
		lst, lerr := license.Load(layout.License(), licKeys, time.Now())
		if lerr != nil {
			// File CÓ mà hỏng/giả/ký bằng khoá lạ: nói TO mỗi lần đụng tới, và
			// thao tác MỚI chạy ở sàn starter cho tới khi file được thay —
			// app đang chạy không bị đụng (luật 3 của package license).
			log.Printf("keenrig-box: license file %s is INVALID (%v) — new actions run at the starter floor",
				layout.License(), lerr)
			return &license.State{Status: license.StatusNone, Plan: "starter", Features: license.StarterFeatures()}
		}
		return lst
	}
	if lst := licenseState(); lst.Payload != nil {
		log.Printf("keenrig-box: license %s (%s) — runtime %s, expires %s",
			lst.Plan, lst.Status, lst.Features.Runtime, lst.Payload.ExpiresAt.Format(time.RFC3339))
	} else {
		log.Printf("keenrig-box: no license — starter tier (docker · %d node · %d apps · %d domains)",
			contracts.StarterMaxNodes, contracts.StarterMaxApps, contracts.StarterMaxDomains)
	}

	// Reconciler chạy dưới supervisor (luật §2.1.1): driver docker được tạo BÊN
	// TRONG fn nên dockerd chưa lên chỉ làm supervisor retry theo backoff —
	// process vẫn sống và /healthz vẫn 200.
	// Reconciler dựng TRƯỚC và dùng lại qua mọi lần supervisor restart: node API
	// giữ con trỏ này cho /drain và /resume, nên nó không được đổi identity giữa
	// chừng — ota drain xong mà box thay bằng một reconciler khác chưa drain thì
	// cả cơ chế vô nghĩa. Driver docker vẫn tạo BÊN TRONG fn để dockerd chưa lên
	// chỉ làm supervisor retry.
	// Thao tác cần root đi qua sudo + script dưới <base>/scripts (xem
	// internal/privops). Kiểm NGAY LÚC KHỞI ĐỘNG chứ không đợi lúc dùng: một
	// sudoers sai sẽ chỉ lộ ra khi ai đó bấm nút xoá app và không có gì xảy
	// ra — không lỗi, không log, chỉ là dữ liệu ở lại trên đĩa mãi mãi.
	priv := privops.NewFromBase(dataDir)
	// Một dòng chỉ thẳng nguyên nhân, trước loạt "NOT available" bên dưới:
	// không có nó, người đọc log sẽ đi sửa sudoers — vốn không sai gì.
	if os.Geteuid() != 0 && privops.NoNewPrivs() {
		log.Printf("keenrig-box: this process runs with NoNewPrivs=1, so sudo can never elevate - " +
			"apps running as a non-root user (n8n, ...) will crash-loop with EACCES. " +
			"Remove the option that implies NoNewPrivileges from keenrig-box.service " +
			"(RestrictSUIDSGID=, ProtectKernelModules=, SystemCallFilter=, ...), then: systemctl daemon-reload && systemctl restart keenrig-box")
	}
	for script, perr := range priv.AvailableAll(ctx) {
		log.Printf("keenrig-box: privileged operation %q is NOT available: %v", script, perr)
	}

	// Gateway: chặn LỰA CHỌN vô nghĩa ngay lúc khởi động, trước cả supervisor.
	//
	// proxy.Available không nói chuyện với gateway — nó chỉ trả lời "chọn cái
	// này có vô nghĩa không". Câu đó phải hỏi ở ĐÂY vì lỗi của nó là VĨNH VIỄN
	// trong binary này: gõ sai tên, hoặc driver chưa hiện thực. Để supervisor
	// retry với một lỗi vĩnh viễn chỉ tạo ra một vòng lặp log.
	//
	// Ngược lại, "gateway chưa lên" là TẠM THỜI và đáng retry — nó vẫn được xử
	// lý bên trong fn như cũ. Cùng sự phân biệt mà ErrInfraNotReady đã dựng ở
	// tầng addon: chưa-xong ≠ hỏng.
	if err := proxy.Available(proxy.DriverFromEnv(os.LookupEnv)); err != nil {
		return fmt.Errorf("%s: %w", proxy.EnvDriver, err)
	}

	// instCfg dựng TRƯỚC reconciler: reconciler đọc tên miền gốc từ nó để định
	// tuyến Admin (xem WithPlatformHosts), và phải gắn trước khi goroutine chạy.
	instCfg := instance.New(st)
	rec := reconciler.New(st, nil, reconciler.Options{}).
		WithPlatformHosts(adminUpstream(addr), func(ctx context.Context) []string {
			info, err := instCfg.Info(ctx)
			if err != nil || info.ParentDomain == "" {
				return nil
			}
			return []string{info.ParentDomain, "admin." + info.ParentDomain}
		})
	var reconcilerDone <-chan struct{}
	if reconcileOn {
		reconcilerDone = supervise.Go(ctx, "reconciler", func(ctx context.Context) error {
			// Driver runtime chọn theo KEENRIG_RUNTIME (docker|swarm|k8s).
			// Mở BÊN TRONG fn để nền tảng chưa sẵn sàng (dockerd chưa lên,
			// cluster mất mạng) chỉ làm supervisor retry theo backoff — tiến
			// trình vẫn sống và /healthz vẫn 200.
			//
			// Gate license (M5): swarm/k8s cần bậc tương ứng trong license;
			// docker luôn qua. Hỏi trạng thái MỚI mỗi lần fn chạy lại — một
			// license vừa được agent thay phải có hiệu lực ở lần restart kế.
			//
			// License hết hạn/hạ bậc KHÔNG được làm sập app đang chạy (luật 2,
			// audit F2): runtime đã có app thì vẫn mở, và thao tác mới rơi về
			// sàn starter qua CanAddApp/CanAddDomain. Chỉ một box CHƯA có app
			// nào mới bị từ chối runtime ngoài bậc.
			gate := func(driver string) error {
				lerr := licenseState().RuntimeAllowed(driver)
				if lerr == nil {
					return nil
				}
				existing, err := st.ListApps(ctx)
				if err != nil {
					return err
				}
				if len(existing) == 0 {
					return lerr
				}
				log.Printf("keenrig-box: %v - keeping %d running app(s) on %q, new actions run at the starter floor",
					lerr, len(existing), driver)
				return nil
			}
			drv, err := runtime.OpenFromEnv(ctx, layout, os.LookupEnv, gate)
			if err != nil {
				return err
			}
			if c, ok := drv.(io.Closer); ok {
				defer c.Close()
			}
			rec := rec.WithRuntime(drv).WithHealth(health.New(health.Options{})).WithPrivOps(priv)
			// Gateway mở TRONG fn, giống driver docker: gateway chưa lên chỉ
			// làm supervisor retry, box vẫn sống và /healthz vẫn 200.
			if ctl, err := proxy.OpenFromEnv(ctx, layout, adminUpstream(addr), selfIPs(), os.LookupEnv); err != nil {
				log.Printf("keenrig-box: gateway not usable yet (%v) — continuing without routing", err)
			} else {
				rec = rec.WithProxy(ctl)
			}
			return rec.Run(ctx)
		}, supervise.Options{
			OnRestart: func(name string, cause error, next time.Duration) {
				log.Printf("supervisor: %s died (%v) — restarting in %s", name, cause, next)
				data, _ := json.Marshal(map[string]string{
					"module": name,
					"error":  cause.Error(),
					"next":   next.String(),
				})
				if err := st.AppendEvent(ctx, "module.restarted", "supervisor", name, data); err != nil && ctx.Err() == nil {
					log.Printf("supervisor: appending event: %v", err)
				}
			},
		})
	}

	// Xác thực: identity (session + TOTP) là đường CHÍNH. Bootstrap token vẫn
	// giữ nhưng CHỈ khi instance chưa có chủ — nó là cách duy nhất để luồng
	// thiết lập lần đầu chạy được từ CLI, và để nó sống mãi sau khi đã có chủ
	// là để lại một chìa khoá vạn năng không thu hồi được từng phần.
	// Tên miền gốc: bảng `settings` là nơi giữ, và có HAI nguồn không ngang hàng.
	//
	// KEENRIG_DOMAIN (`--domain` của trình cài) là đường standalone; tên do
	// cloud cấp đi vào qua agent → node API bên dưới và THẮNG: luật "cloud
	// thắng" sống ở internal/instance, ở đây chỉ gọi và nói ra kết quả. Ghi vào
	// DB thay vì đọc biến mỗi lần cần, vì Admin UI hỏi giá trị này qua API. Ghi
	// ở MỖI lần khởi động để đổi `--domain` trên box standalone chỉ cần sửa
	// unit rồi restart.
	if pd := strings.TrimSpace(os.Getenv(envParentDomain)); pd != "" {
		applied, err := instCfg.ApplyLocal(ctx, pd)
		switch {
		case errors.Is(err, instance.ErrInvalidDomain):
			// Tên hỏng trong unit không đáng làm box chết: app vẫn chạy, chỉ
			// mất gợi ý `<app>.<parent>` — và dòng log này nói rõ vì sao.
			log.Printf("keenrig-box: ignoring %s=%q: %v", envParentDomain, pd, err)
		case err != nil:
			return err
		case applied:
			info, _ := instCfg.Info(ctx)
			log.Printf("keenrig-box: parent domain %s (apps go to <app>.%s)", info.ParentDomain, info.ParentDomain)
		default:
			info, _ := instCfg.Info(ctx)
			log.Printf("keenrig-box: parent domain is managed by the control plane (%s); ignoring %s=%s",
				info.ParentDomain, envParentDomain, pd)
		}
	}

	identSvc := identity.New(st, identity.Options{Secure: secureCookies})
	needsSetup, err := identSvc.NeedsSetup(ctx)
	if err != nil {
		return err
	}
	var auth authz.Authenticator = identSvc
	if needsSetup {
		boot, token, created, berr := authz.LoadOrCreateBootstrap(ctx, st)
		if berr != nil {
			return berr
		}
		if created {
			log.Printf("keenrig-box: no owner yet — setup token (shown only once): %s", token)
		}
		auth = authz.Any(identSvc, boot)
	}

	domSvc := domains.New(st)
	appSvc := apps.New(st, domSvc, apps.Options{
		ResourceCaps: resourceCaps(ctx, layout),
		License:      licenseState,
	})
	// Cloud đổi tên miền gốc (địa chỉ tạm → tên miền riêng): app đi theo.
	instCfg.OnParentChanged = appSvc.RebaseDomains
	// Danh mục app (UI-01): bản NHÚNG trong binary, chồng thêm thư mục ngoài
	// nếu người vận hành có danh mục riêng. Không có lời gọi mạng nào lúc
	// khởi động — UI-11 cấm mọi phụ thuộc bắt buộc ra ngoài.
	cat := catalog.MustLoad(os.Getenv(envCatalogDir))
	// WithInstance: /api/v1/cloud đọc trạng thái pair mà agent báo qua node
	// API bên dưới — CÙNG instCfg, nên hai đầu không thể lệch khoá.
	apiSrv := api.New(appSvc, st, auth, api.WithIdentity(identSvc), api.WithCatalog(cat), api.WithInstance(instCfg), api.WithPairer(priv.Pair))

	// Node API (T9b) — hợp đồng giữa 4 tiến trình, trên unix socket.
	// Lỗi mở socket KHÔNG được làm box chết: control API và reconciler vẫn phục
	// vụ được, chỉ agent/ota tạm mất đường vào (và ND-06 nói họ phải tự retry).
	// metrics.Default, KHÔNG phải một registry mới.
	//
	// Đây từng là một lỗi im lặng và đã đo được: tiến trình có HAI registry —
	// cái được phơi ở /metrics và cái mà code thật ghi vào (metrics.Default).
	// Kết quả là /metrics chỉ có `keenrig_build_info`; ngay cả
	// `keenrig_uptime_seconds` cũng vắng, và không có gì đỏ để lần ra. Một
	// registry riêng chỉ đúng trong test, nơi mỗi test cần một registry sạch.
	reg := metrics.Default
	reg.SetProcessInfo(processName, version)
	nodeSrv := nodeapi.New(nodeapi.Options{
		Store:     st,
		Lifecycle: rec,
		// Vé "Mở Admin ↗" (CON-13) đi vào qua node API và ra qua
		// /_keenrig/admin-session bên dưới. Cắm identSvc vào CẢ HAI đầu: hai
		// kho vé khác nhau thì vé nhận được không bao giờ đổi được.
		AdminTickets: identSvc,
		// License mới từ agent (M5): verify bằng CHÍNH bộ khoá của box rồi mới
		// ghi — cùng bộ khoá mà licenseState đọc lại, nên "nhận được" và "có
		// hiệu lực" là một.
		License: licenseSink{layout: layout, keys: licKeys},
		// Tên miền gốc do cloud cấp (qua agent). Cùng Config với chỗ áp
		// KEENRIG_DOMAIN ở trên, nên "cloud thắng" là một luật, một chỗ.
		Domain: instCfg,
		// Trạng thái pair từ agent (AD-12). Cùng Config với /api/v1/cloud ở
		// trên: agent ghi, Admin UI đọc, một chỗ.
		CloudLink: instCfg,
		// Lệnh "cài app" từ Console (CON-09, qua agent). CÙNG catalog + CÙNG
		// apps service với /api/v1/catalog/{id}/install: một đường cài, hai cửa.
		Apps:    catalogInstaller{cat: cat, apps: appSvc},
		Version: nodeapi.Version{Process: processName, Version: version},
		Metrics: reg,
	})
	var nodeLn *nodeapi.Listener
	if ln, err := nodeapi.Listen(layout, nodeSrv); err != nil {
		log.Printf("keenrig-box: could not open the node API (%v) — agent/ota will retry", err)
	} else {
		nodeLn = ln
		if ln.Insecure {
			log.Printf("keenrig-box: WARNING node API is listening on TCP %s (dev-only path, "+
				"no file-permission protection) — development use only", ln.Addr)
		} else {
			log.Printf("keenrig-box: node API at %s", ln.Addr)
		}
		go func() {
			if err := ln.Serve(); err != nil {
				log.Printf("keenrig-box: node API stopped: %v", err)
			}
		}()
	}

	// /metrics phơi trên CỔNG HTTP nữa, không chỉ trên node API.
	//
	// Node API nghe unix socket, mà Prometheus không scrape được socket. Thiếu
	// dòng này thì số liệu của box là thứ không ai lấy được — và tệ hơn, SPA
	// nhận "/" nên một scraper trỏ vào /metrics sẽ nhận HTTP 200 kèm index.html
	// và báo "up" mãi mãi mà không có metric nào.
	httpdOpts := []httpd.Option{
		httpd.WithAPI(apiSrv),
		httpd.WithMetrics(reg.Handler()),
		// CON-13: cửa mà trình duyệt trình vé lên sau khi Console đổi nó.
		// Đăng ký LUÔN, kể cả khi identity chưa bật — handler tự trả 501 kèm lý
		// do, còn không đăng ký thì SPA ở "/" nuốt đường này và trả về
		// index.html với mã 200 (đúng cái bẫy đã đo được ở đường OIDC).
		httpd.WithAdminSession(apiSrv.AdminSessionHandler()),
	}
	// OIDC provider (ID-01) — chỉ bật khi người vận hành khai ĐỊA CHỈ CÔNG KHAI.
	//
	// Không có mặc định, và không đoán từ Host header. `issuer` đi vào claim
	// `iss` của mọi token và RP so khớp CHÍNH XÁC chuỗi đó; suy ra từ Host thì
	// một request qua địa chỉ khác (IP, localhost, một domain thứ hai) sinh ra
	// token với `iss` khác — RP từ chối, và thông báo lỗi không nhắc gì tới Host.
	//
	// Không khai thì endpoint KHÔNG tồn tại, thay vì tồn tại và cấp token sai.
	if issuer := os.Getenv(envOIDCIssuer); issuer != "" {
		prov, oerr := oidc.New(ctx, st, oidc.Options{Issuer: issuer})
		if oerr != nil {
			return fmt.Errorf("could not start the OpenID Connect provider: %w", oerr)
		}
		httpdOpts = append(httpdOpts, httpd.WithOIDC(prov.Handler(auth)))
		log.Printf("keenrig-box: OpenID Connect provider at %s%s", prov.Issuer(), oidc.DiscoveryPath)
	}
	if ui.Available() {
		httpdOpts = append(httpdOpts, httpd.WithUI(ui.Handler()))
	} else {
		// Nói ra thay vì im lặng phục vụ 404: "API chạy nhưng mở trình duyệt
		// thấy trắng" là triệu chứng khó lần nhất khi chưa ai chạy npm build.
		log.Printf("keenrig-box: no Admin assets in this binary (run `npm run build` in keenrig-node/ui) — serving the API only")
	}
	// Worker việc nền (T14) — chạy dưới supervisor như reconciler: một job
	// panic đã được bọc trong worker, nhưng worker chết vì lý do khác thì
	// supervisor dựng lại thay vì mất hẳn hàng đợi.
	worker := jobs.New(st, jobs.Options{Owner: reconciler.DefaultHolder()})
	registerHousekeep(worker, st)
	workerDone := supervise.Go(ctx, "jobs", worker.Run, supervise.Options{
		OnRestart: func(name string, cause error, next time.Duration) {
			log.Printf("supervisor: %s died (%v) — restarting in %s", name, cause, next)
		},
	})
	scheduleHousekeep(ctx, worker)

	srv := httpd.New(st, addr, httpdOpts...)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()
	log.Printf("keenrig-box serve: http=%s data=%s runtime=%s proxy=%s",
		addr, dataDir, runtime.DriverFromEnv(os.LookupEnv), proxy.DriverFromEnv(os.LookupEnv))

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
	}

	// Huỷ ctx (kể cả khi thoát vì httpd chết) để goroutine supervise bắt đầu dừng.
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && serveErr == nil {
		serveErr = err
	}
	if nodeLn != nil {
		if err := nodeLn.Shutdown(shutdownCtx); err != nil {
			log.Printf("keenrig-box: shutting down the node API: %v", err)
		}
	}

	// Đợi reconciler thoát hẳn TRƯỚC khi defer st.Close() chạy: nó có thể đang
	// giữa Apply (tới 60s) rồi mới SetStatus — đóng store sớm thì ghi vào DB đã
	// đóng. Quá hạn thì log cảnh báo và đóng luôn, không treo vô hạn.
	waitSupervised(reconcilerDone, supervisedShutdownTimeout)
	waitSupervised(workerDone, supervisedShutdownTimeout)

	log.Println("keenrig-box: stopped")
	return serveErr
}

// Env cho module certs (T9). Chỉ có nghĩa khi gateway KHÔNG có CapACME — với
// caddy mặc định, đặt hay không đặt đều không đổi gì.
//
// KEENRIG_ACME_EMAIL rỗng vẫn xin được cert; nó chỉ dùng để CA gửi cảnh báo
// sắp hết hạn. KEENRIG_ACME_INSECURE dành cho pebble trong CI — bật trong sản
// xuất là vô hiệu hoá toàn bộ giá trị của ACME.
const (
	envACMEDirectory = "KEENRIG_ACME_DIRECTORY"
	envACMEEmail     = "KEENRIG_ACME_EMAIL"
	envACMEInsecure  = "KEENRIG_ACME_INSECURE"
)

// certManagerFromEnv dựng manager cấp chứng chỉ.
//
// Luôn trả manager khác nil (issuer luôn có): thiếu directory thì mặc định là
// Let's Encrypt production. Trả nil khi thiếu cấu hình sẽ tạo ra một hệ chạy
// im lặng không HTTPS trên nginx, và người vận hành không có manh mối nào.
func certManagerFromEnv(st store.Store, layout paths.Layout) *certs.Manager {
	issuer := certs.NewACMEIssuer(st, layout, certs.ACMEOptions{
		Directory:          os.Getenv(envACMEDirectory),
		Email:              os.Getenv(envACMEEmail),
		InsecureSkipVerify: os.Getenv(envACMEInsecure) == "1",
	})
	return certs.New(st, layout, issuer, certs.Options{})
}

// addonProvisioner dựng tầng cấp phát addon từ infra.json nhúng trong binary.
//
// Image hạ tầng đọc từ file ĐÃ PIN DIGEST, không từ env: một `latest` lọt vào
// đây nghĩa là nâng cấp PostgreSQL xảy ra vào lúc ai đó đẩy lại một tag, chứ
// không phải lúc ta quyết định.
func addonProvisioner(layout paths.Layout, st store.Store) (*addons.Provisioner, error) {
	var f struct {
		InfraVersion int                           `json:"infra_version"`
		Images       map[string]addons.PinnedImage `json:"images"`
	}
	if err := json.Unmarshal(addonimages.InfraJSON, &f); err != nil {
		return nil, fmt.Errorf("infra.json could not be parsed: %w", err)
	}
	if f.InfraVersion < 1 || len(f.Images) == 0 {
		return nil, fmt.Errorf("infra.json is missing infra_version or images")
	}
	rt, err := infradocker.New()
	if err != nil {
		return nil, err
	}
	return addons.NewProvisioner(addons.Config{
		Layout: layout, Store: st, Runtime: rt,
		InfraVersion: f.InfraVersion, Images: f.Images,
	}), nil
}

// resourceCaps trả hạn mức mà runtime đang chọn thực thi được, cho admission.
//
// # Vì sao dò thật nhưng KHÔNG bắt buộc dò được
//
// Câu trả lời đúng phụ thuộc HOST, không chỉ driver: cùng Docker Engine, quota
// lớp ghi có trên overlay2/xfs+pquota và không có trên snapshotter overlayfs.
// Nên ta mở driver một lần, hỏi, rồi đóng.
//
// Nhưng dò được KHÔNG phải điều kiện để box khởi động. dockerd chưa lên là
// chuyện thường và đã được thiết kế để chịu được (driver thật mở bên trong
// goroutine được supervise, để /healthz vẫn 200). Nếu dò thất bại, ta rơi về
// `resources.ByDriver` — trần trên THEO THIẾT KẾ của driver. Hệ quả được chấp
// nhận có ý thức: trên host không đỡ quota, `disk_mb` lọt qua admission rồi bị
// `resources.Enforce` từ chối lúc Apply. App vào trạng thái error với thông báo
// nói đúng năng lực thiếu — tệ hơn một 400, nhưng vẫn KHÔNG im lặng.
//
// Timeout ngắn có chủ đích: đây là đường khởi động, và một daemon treo không
// được phép giữ box lại quá vài giây.
// licenseSink — phía nhận của `PUT /node/v1/license`: verify bằng bộ khoá của
// box rồi ghi nguyên tử xuống layout.License(). Một license không verify được
// KHÔNG chạm đĩa (license.Install lo cả hai vế); box không cần restart — mọi
// admission đọc lại file qua licenseState.
type licenseSink struct {
	layout paths.Layout
	keys   license.Keys
}

func (s licenseSink) InstallLicense(raw []byte) error {
	st, err := license.Install(s.layout.License(), raw, s.keys, time.Now())
	if err != nil {
		return err
	}
	log.Printf("keenrig-box: license installed — plan %s (%s), runtime %s, expires %s",
		st.Plan, st.Status, st.Features.Runtime, st.Payload.ExpiresAt.Format(time.RFC3339))
	return nil
}

// catalogInstaller — phía box của lệnh `app.install` (nodeapi.AppInstaller).
//
// Phép dịch manifest → desired là catalog.ToDesired, và phép tạo là
// apps.CreateFromDesired — đúng hai bước mà installFromCatalog của control API
// làm. Thêm đúng một thứ control API không cần: idempotent theo slug, vì agent
// có thể giao lại cùng một lệnh.
type catalogInstaller struct {
	cat  *catalog.Catalog
	apps *apps.Service
}

func (c catalogInstaller) InstallCatalogApp(ctx context.Context, catalogID, slug string, domains []string) (string, bool, error) {
	m, err := c.cat.Get(catalogID)
	if err != nil {
		return "", false, fmt.Errorf("%q is not in this box's catalog: %w", catalogID, err)
	}
	if slug == "" {
		slug = m.ID
	}
	list, err := c.apps.List(ctx)
	if err != nil {
		return "", false, err
	}
	for _, a := range list {
		if a.Slug == slug {
			return a.ID, false, nil
		}
	}
	desired, err := m.ToDesired(catalog.InstallOptions{Domains: domains})
	if err != nil {
		return "", false, err
	}
	app, err := c.apps.CreateFromDesired(ctx, slug, desired)
	if err != nil {
		return "", false, err
	}
	log.Printf("keenrig-box: installed %s from the catalog as %q (cloud command), domains %v", m.ID, slug, domains)
	return app.ID, true, nil
}

func resourceCaps(ctx context.Context, layout paths.Layout) resources.Caps {
	name := runtime.DriverFromEnv(os.LookupEnv)
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	drv, err := runtime.Open(probeCtx, name, runtime.ConfigFromEnv(layout, os.LookupEnv), runtime.AllowAll)
	if err != nil {
		log.Printf("keenrig-box: could not probe %s resource limits (%v) — admission falls back to the driver's design ceiling", name, err)
		return resources.ByDriver(name)
	}
	if c, ok := drv.(io.Closer); ok {
		defer c.Close()
	}
	caps, err := drv.ResourceCaps(probeCtx)
	if err != nil {
		log.Printf("keenrig-box: %s did not report resource limits (%v) — admission falls back to the driver's design ceiling", name, err)
		return resources.ByDriver(name)
	}
	return caps
}

// adminUpstream dịch cờ --http thành đích cho catch-all của gateway (PX-03).
//
// Lấy từ ĐÚNG cờ mà httpd đang nghe, không phải từ một biến riêng: hai nguồn
// sự thật cho "Admin UI ở đâu" sẽ lệch nhau vào lúc ai đó đổi cờ --http, và
// lúc lệch thì catch-all chuyển tiếp yêu cầu vào một cổng lạ trên máy.
//
// Host rỗng (":8080") nghĩa là nghe mọi giao diện — gateway nằm CÙNG MÁY nên
// 127.0.0.1 là đích đúng, và cũng là đích hẹp nhất.
func adminUpstream(addr string) proxy.Upstream {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Không phân giải được thì trả zero value: driver sẽ để catch-all ở 404.
		// Đoán một cổng ở đây là cách biến lỗi cấu hình thành lỗ chuyển tiếp.
		log.Printf("keenrig-box: could not parse HTTP address %q (%v) — the catch-all will return 404", addr, err)
		return proxy.Upstream{}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		log.Printf("keenrig-box: invalid HTTP port %q — the catch-all will return 404", portStr)
		return proxy.Upstream{}
	}
	// "0.0.0.0" và "::" cũng quy về loopback: gateway ở cùng máy, và đi vòng ra
	// địa chỉ ngoài chỉ thêm một chặng mạng có thể bị chặn bởi chính firewall.
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return proxy.Upstream{Host: host, Port: port}
}

// selfIPs liệt kê địa chỉ IP của chính máy, để gateway cấp cert tự ký cho
// truy cập bằng IP (PX-03).
//
// BỎ loopback và link-local: cert cho 127.0.0.1 chỉ dùng được từ chính máy đó,
// và người vận hành gõ IP là đang gõ từ máy khác. Bỏ cả IPv6 link-local vì nó
// mang %zone và không phải thứ ai gõ vào thanh địa chỉ.
//
// Lỗi đọc interface trả về DANH SÁCH RỖNG, và driver hiểu rỗng là "chưa biết"
// nên để nguyên cấu hình TLS. Trả về danh sách cụt sẽ làm cert của những địa
// chỉ còn lại bị gỡ — biến một sự cố tạm thời thành mất HTTPS.
func selfIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("keenrig-box: could not read interface addresses (%v) — "+
			"keeping the current TLS configuration", err)
		return nil
	}
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(n.IP.String())
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

// version/processName — ba binary phía instance dùng CÙNG chuỗi version vì
// chúng ship cùng nhau và sync protocol là hợp đồng chung (V2-DELTA §6).
// envCatalogDir — thư mục danh mục RIÊNG của người vận hành, chồng lên bản
// nhúng. Không đặt thì chỉ có bản nhúng, và đó là trường hợp thường gặp.
const envCatalogDir = "KEENRIG_CATALOG_DIR"

// envParentDomain — tên miền gốc của instance: app ở `<app>.<parent>`, Admin ở
// `admin.<parent>`. `get.sh --domain` ghi biến này.
//
// Trước 2026-09-06 nó được GHI RA mà không dòng mã nào đọc — nghĩa là cờ
// `--domain` trong `--help` của trình cài không làm gì cả, và Admin UI không
// biết instance thuộc tên miền nào nên bắt người dùng gõ cả FQDN cho từng app.
// Đây là lần THỨ HAI cùng một cái bẫy: `KEENRIG_JOIN_TOKEN` từng y hệt.
const envParentDomain = "KEENRIG_DOMAIN"

// envLicensePubkeys — "id=base64,..." các khoá công verify license. Bản phát
// hành nhúng khoá lúc build:
//
//	go build -ldflags "-X main.embeddedLicenseKeys=active=<b64>" ./cmd/keenrig-box
//
// Env chỉ dùng được khi bản build KHÔNG nhúng khoá (dev/test). Xoay khoá ở bản
// phát hành = phát hành binary mới qua OTA.
const envLicensePubkeys = "KEENRIG_LICENSE_PUBKEYS"

// embeddedLicenseKeys — khoá công phát hành, nhúng qua -ldflags. Rỗng ở bản
// build dev: khi đó mọi thứ chạy ở sàn starter trừ khi env khai khoá.
var embeddedLicenseKeys string

// envOIDCIssuer — địa chỉ CÔNG KHAI của box, ví dụ https://box.example.com.
//
// Không có mặc định có chủ đích: xem chỗ dùng trong run().
const envOIDCIssuer = "KEENRIG_OIDC_ISSUER"

// version — xem internal/buildinfo: một chuỗi cho cả ba binary, nạp lúc build.
var version = buildinfo.Version

const processName = "keenrig-box"

// supervisedShutdownTimeout — nới hơn waitRunningTimeout (60s) của driver docker
// là không thực tế; 35s đủ cho phần lớn trường hợp, quá hạn thì đóng bất chấp.
const supervisedShutdownTimeout = 35 * time.Second

func waitSupervised(done <-chan struct{}, timeout time.Duration) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(timeout):
		log.Printf("keenrig-box: reconciler did not exit after %s — closing the store anyway", timeout)
	}
}
