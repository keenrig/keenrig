package nodeapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
)

// Listen mở node API.
//
// # Nấc 0: unix socket, quyền là hàng rào
//
// Socket đặt 0660 và nằm trong RunDir. Ai mở được socket là gọi được MỌI
// endpoint, kể cả /drain — nên quyền file CHÍNH LÀ cơ chế xác thực ở nấc này
// (ND-04). Không có token nào cả, và đó là chủ đích: agent/ota chạy cùng máy,
// cùng nhóm, và một token nằm sẵn trên đĩa cạnh socket không thêm được gì.
//
// Nói thẳng giới hạn: 0660 chặn được người dùng khác trên máy, KHÔNG chặn được
// một tiến trình khác chạy dưới cùng UID. Muốn chặt hơn phải đọc SO_PEERCRED và
// đối chiếu whitelist — đó là việc còn nợ, ghi ở ND-04.
//
// # Windows
//
// Không có unix socket dùng được ổn định ở đây, nên rơi về TCP 127.0.0.1. Đây
// là đường DEV ONLY: loopback không có quyền file, tức là mọi tiến trình trên
// máy đều gọi được. Hàm trả kèm cảnh báo để chỗ gọi log ra, chứ không im lặng
// hạ chuẩn bảo mật.
const SocketPerm = 0o660

type Listener struct {
	srv      *http.Server
	ln       net.Listener
	Addr     string
	Insecure bool // true = đang chạy đường TCP dev-only
}

// Listen dựng listener theo layout. addr rỗng → unix socket theo paths.BoxSocket().
func Listen(layout paths.Layout, handler http.Handler) (*Listener, error) {
	if runtime.GOOS == "windows" {
		return listenTCP(handler)
	}
	return listenUnix(layout, handler)
}

func listenUnix(layout paths.Layout, handler http.Handler) (*Listener, error) {
	sock := layout.BoxSocket()
	if err := os.MkdirAll(filepath.Dir(sock), paths.DirPerm); err != nil {
		return nil, err
	}
	// Socket cũ còn lại sau một lần crash sẽ làm Listen báo "address already in
	// use" dù không ai nghe. Xoá trước là chuẩn của mọi daemon dùng unix socket.
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("nodeapi: removing the stale socket %s: %w", sock, err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("nodeapi: opening the socket %s: %w", sock, err)
	}
	// Chmod SAU khi Listen: umask của tiến trình có thể siết chặt hơn ta muốn,
	// và agent/ota (cùng nhóm) sẽ không mở được.
	if err := os.Chmod(sock, SocketPerm); err != nil {
		ln.Close()
		return nil, fmt.Errorf("nodeapi: setting socket permissions: %w", err)
	}
	return &Listener{srv: newHTTPServer(handler), ln: ln, Addr: sock}, nil
}

func listenTCP(handler http.Handler) (*Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &Listener{srv: newHTTPServer(handler), ln: ln, Addr: ln.Addr().String(), Insecure: true}, nil
}

func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		// KHÔNG đặt WriteTimeout: /apps/{id}/logs là stream dài, và một
		// WriteTimeout sẽ cắt ngang log đúng lúc người ta đang xem sự cố.
		IdleTimeout: 60 * time.Second,
	}
}

// Serve block tới khi Shutdown.
func (l *Listener) Serve() error {
	err := l.srv.Serve(l.ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown dừng server và dọn socket.
func (l *Listener) Shutdown(ctx context.Context) error {
	err := l.srv.Shutdown(ctx)
	if !l.Insecure {
		// Dọn file socket: để lại thì lần khởi động sau phải xoá, mà lúc đó ta
		// không phân biệt được "rác của mình" với "một box khác đang chạy".
		os.Remove(l.Addr)
	}
	return err
}
