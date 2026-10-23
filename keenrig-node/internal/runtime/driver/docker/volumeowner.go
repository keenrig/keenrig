package docker

// Chủ sở hữu của thư mục volume.
//
// # Lỗ này là gì
//
// mountsFor tạo `apps/<id>/volumes/<name>` bằng quyền của keenrig-box — tức là
// keenrig:keenrig 0755 (root:root khi chạy box bằng root). Image chạy bằng root không thấy gì khác thường. Image chạy
// bằng user thường (n8n: `USER node`, uid 1000) thì nhận một thư mục nó KHÔNG
// GHI ĐƯỢC, và chết ngay ở lần ghi đầu tiên. Đã kiểm trên Docker thật với n8n
// 2.41.6:
//
//	Error: EACCES: permission denied, open '/home/node/.n8n/config'
//
// Named volume của Docker không có lỗ này vì Docker chép quyền sở hữu từ thư
// mục tương ứng trong image sang volume lúc tạo. Bind mount thì không chép gì —
// và ta dùng bind mount có chủ đích (xem mountsFor: để `keenrig-box backup` gom
// được dữ liệu app). Nên phần việc Docker làm hộ named volume, ở đây ta tự làm.
//
// # Vì sao cần sudo
//
// Box chạy bằng user keenrig, không có CAP_CHOWN, nên os.Chown sang uid khác
// luôn EPERM trên box thật — đã kiểm trên VPS: n8n kẹt restart với đúng lỗi
// EACCES ở trên dù code này đã có trong binary. Khi gặp EPERM, ta đi đường
// đặc quyền `appdata.sh chown-volume` (privops.ChownAppVolume), script tự kiểm
// lại app-id, tên volume, realpath và "thư mục rỗng". os.Chown vẫn thử trước:
// box chạy bằng root (dev, test) không cần sudo.
//
// # Vì sao chỉ đụng thư mục RỖNG
//
// Thư mục rỗng nghĩa là app chưa từng ghi gì: đổi chủ nó không làm mất hay đổi
// nghĩa dữ liệu nào. Thư mục đã có dữ liệu thì quyền của nó là thứ app (hoặc
// người vận hành, sau một lần restore) đã sắp đặt — chown đè lên mỗi lần deploy
// là giành quyền quyết định đó, và chown đệ quy trên một kho vài chục GB thì
// biến mỗi lần cập nhật thành một lần quét đĩa.
//
// # Vì sao đọc user từ CONTAINER chứ không từ image
//
// Container vừa tạo mang đúng thứ sẽ chạy: Config.User của nó là của image,
// trừ khi về sau desired có trường ghi đè — lúc đó code này vẫn đúng mà không
// phải sửa. `/etc/passwd` cũng đọc từ container đó (CopyFromContainer chạy được
// trên container chưa start), nên tên user được phân giải theo đúng image chứ
// không theo máy chủ — uid 1000 trên máy chủ có thể là một người hoàn toàn khác.

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

// maxIdentityFileBytes — trần khi đọc /etc/passwd, /etc/group từ image. Image
// là đầu vào không tin cậy; một "passwd" vài GB không được làm cạn RAM của box.
const maxIdentityFileBytes = 1 << 20

// adoptVolumeOwnership đổi chủ các thư mục volume còn rỗng sang user mà
// container sẽ chạy. Gọi SAU ContainerCreate, TRƯỚC ContainerStart.
func (d *Driver) adoptVolumeOwnership(ctx context.Context, containerID string, spec runtime.AppSpec) error {
	// Chỉ Linux có uid/gid trên thư mục máy chủ đi thẳng vào container. Docker
	// Desktop (Windows/macOS) chuyển file qua một lớp chia sẻ tự ánh xạ quyền,
	// và os.Chown trên Windows thì không làm gì có nghĩa.
	if len(spec.Desired.Volumes) == 0 || goruntime.GOOS != "linux" {
		return nil
	}
	ins, err := d.cli.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("docker: inspect %s to resolve its user: %w", containerID, err)
	}
	user := ""
	if ins.Container.Config != nil {
		user = ins.Container.Config.User
	}
	if user == "" || user == "root" || user == "0" || user == "0:0" {
		return nil // thư mục đã thuộc root — không có gì để làm
	}

	passwd, err := d.readContainerFile(ctx, containerID, "/etc/passwd")
	if err != nil {
		return err
	}
	group, err := d.readContainerFile(ctx, containerID, "/etc/group")
	if err != nil {
		return err
	}
	uid, gid, err := resolveUser(user, passwd, group)
	if err != nil {
		return fmt.Errorf("docker: app %s: %w", spec.ID, err)
	}
	if uid == 0 && gid == 0 {
		return nil
	}

	for _, v := range spec.Desired.Volumes {
		if v.ReadOnly {
			continue // app không ghi vào đây — giữ nguyên chủ của nền tảng
		}
		host, err := d.layout.AppVolume(spec.ID, v.Name)
		if err != nil {
			return fmt.Errorf("docker: volume %q of app %s: %w", v.Name, spec.ID, err)
		}
		entries, err := os.ReadDir(host)
		if err != nil {
			return fmt.Errorf("docker: reading volume directory %s: %w", host, err)
		}
		if len(entries) > 0 {
			continue // đã có dữ liệu — xem godoc file
		}
		if err := d.giveVolume(ctx, spec.ID, v.Name, host, uid, gid); err != nil {
			return fmt.Errorf("docker: giving volume directory %s to %s (%d:%d): %w", host, user, uid, gid, err)
		}
	}
	return nil
}

// giveVolume đổi chủ một thư mục volume: os.Chown trước (box chạy bằng root),
// EPERM → đường đặc quyền (box thật chạy bằng keenrig, không có CAP_CHOWN).
// Tách riêng để test được trên mọi OS, không cần root lẫn Docker.
func (d *Driver) giveVolume(ctx context.Context, appID, volume, host string, uid, gid int) error {
	chown := d.chown
	if chown == nil {
		chown = os.Chown
	}
	err := chown(host, uid, gid)
	if !errors.Is(err, os.ErrPermission) {
		return err
	}
	if d.chownVolume == nil {
		return fmt.Errorf("%w (box has no CAP_CHOWN and no privileged fallback is wired)", err)
	}
	// Box không có CAP_CHOWN — xem godoc file, mục "Vì sao cần sudo".
	if perr := d.chownVolume(ctx, appID, volume, uid, gid); perr != nil {
		return fmt.Errorf("%v; privileged fallback: %w", err, perr)
	}
	return nil
}

// readContainerFile đọc một file nhỏ từ filesystem của container (chưa cần
// start). File không tồn tại → rỗng, KHÔNG phải lỗi: image distroless thường
// không có /etc/group, và user dạng số vẫn phân giải được mà không cần nó.
func (d *Driver) readContainerFile(ctx context.Context, containerID, p string) (string, error) {
	res, err := d.cli.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{SourcePath: p})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("docker: reading %s from %s: %w", p, containerID, err)
	}
	defer res.Content.Close()

	tr := tar.NewReader(res.Content)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("docker: reading %s from %s: %w", p, containerID, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue // symlink trong image: không theo — nó có thể trỏ ra ngoài
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxIdentityFileBytes+1))
		if err != nil {
			return "", fmt.Errorf("docker: reading %s from %s: %w", p, containerID, err)
		}
		if len(b) > maxIdentityFileBytes {
			return "", fmt.Errorf("docker: %s in %s is larger than %d bytes", p, containerID, maxIdentityFileBytes)
		}
		return string(b), nil
	}
}

// resolveUser dịch Config.User (`user`, `uid`, `user:group`, `uid:gid`) thành
// uid/gid số, theo đúng luật của Docker:
//
//   - không có phần group → gid chính của user trong passwd; uid số không có
//     trong passwd → gid 0
//   - tên (user hay group) không có trong file → LỖI. Docker cũng từ chối start
//     container đó, nhưng báo ở đây thì thông báo nói rõ là app nào, file nào.
func resolveUser(spec, passwd, group string) (uid, gid int, err error) {
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")

	primaryGID := -1
	if n, convErr := strconv.Atoi(userPart); convErr == nil {
		if n < 0 {
			return 0, 0, fmt.Errorf("container user %q: negative uid", spec)
		}
		uid = n
		if fields, ok := lookupByID(passwd, 2, n); ok {
			primaryGID, _ = strconv.Atoi(fields[3])
		}
	} else {
		fields, ok := lookupByName(passwd, userPart)
		if !ok {
			return 0, 0, fmt.Errorf("container user %q: %q is not in the image's /etc/passwd", spec, userPart)
		}
		if uid, err = strconv.Atoi(fields[2]); err != nil {
			return 0, 0, fmt.Errorf("container user %q: bad uid %q in /etc/passwd", spec, fields[2])
		}
		if primaryGID, err = strconv.Atoi(fields[3]); err != nil {
			return 0, 0, fmt.Errorf("container user %q: bad gid %q in /etc/passwd", spec, fields[3])
		}
	}

	if !hasGroup {
		if primaryGID < 0 {
			primaryGID = 0
		}
		return uid, primaryGID, nil
	}
	if n, convErr := strconv.Atoi(groupPart); convErr == nil && n >= 0 {
		return uid, n, nil
	}
	fields, ok := lookupByName(group, groupPart)
	if !ok {
		return 0, 0, fmt.Errorf("container user %q: group %q is not in the image's /etc/group", spec, groupPart)
	}
	if gid, err = strconv.Atoi(fields[2]); err != nil {
		return 0, 0, fmt.Errorf("container user %q: bad gid %q in /etc/group", spec, fields[2])
	}
	return uid, gid, nil
}

// lookupByName / lookupByID — tra một dòng trong file kiểu passwd/group
// (`name:x:id:...`). passwd cần đủ 4 trường, group đủ 3; dòng thiếu bị bỏ qua.
func lookupByName(file, name string) ([]string, bool) {
	return scanIdentity(file, func(f []string) bool { return f[0] == name })
}

func lookupByID(file string, col, id int) ([]string, bool) {
	want := strconv.Itoa(id)
	return scanIdentity(file, func(f []string) bool { return len(f) > col && f[col] == want })
}

func scanIdentity(file string, match func([]string) bool) ([]string, bool) {
	sc := bufio.NewScanner(strings.NewReader(file))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 {
			// group có 4 trường (name:x:gid:members), passwd có 7 — dưới 4 là
			// dòng hỏng, đọc tiếp sẽ đánh chỉ số ngoài mảng.
			continue
		}
		if match(f) {
			return f, true
		}
	}
	return nil, false
}
