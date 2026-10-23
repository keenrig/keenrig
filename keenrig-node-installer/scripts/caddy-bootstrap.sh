#!/bin/bash
# keenrig: dựng cấu hình GỐC cho Caddy rồi khởi động nó.
#
# "Gốc" nghĩa là ĐÚNG hai thứ: admin API nghe ở đâu, và một server rỗng tên
# `keenrig`. Mọi route, cert, policy đều do driver caddy đẩy qua admin API lúc
# chạy — file này KHÔNG được biết gì về app, domain hay upstream.
#
# # Vì sao là JSON chứ không phải Caddyfile
#
# Driver ghi cấu hình qua admin API, tức là bằng JSON. Nếu file gốc là Caddyfile
# thì cấu hình đang chạy có HAI nguồn với HAI cú pháp, và người vận hành sửa
# Caddyfile rồi `systemctl reload` sẽ thổi bay mọi route driver đã đẩy — không
# một dòng log nào nói ra.
#
# # Vì sao admin API trên UNIX SOCKET
#
# Admin API của Caddy KHÔNG có xác thực: ai gọi được là đổi được toàn bộ định
# tuyến của mọi app. Mặc định TCP nghĩa là mọi tiến trình trên máy — kể cả một
# container app bị chiếm — đổi được routing. Socket có quyền file, và quyền
# file là thứ nhân hệ điều hành thực thi giúp ta (PX-10).
#
# Đường dẫn socket PHẢI khớp mặc định của driver:
#   keenrig-node/internal/proxy/driver/caddy/caddy.go → adminSock
#   <base>/node/run/caddy-admin.sock
# Lệch nhau là lỗi cài đặt IM LẶNG: box khởi động bình thường, gateway chạy
# bình thường, và không request nào tới được app.

set -eu -o pipefail

readonly BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
readonly KEENRIG_USER="${KEENRIG_USER:-keenrig}"
readonly RUN_DIR="${BASE}/node/run"
readonly ADMIN_SOCK="${RUN_DIR}/caddy-admin.sock"
readonly CONFIG_DIR="${BASE}/node/proxy"
readonly CONFIG_FILE="${CONFIG_DIR}/caddy.json"

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

# --check: để sudoers và test kiểm được script tồn tại và chạy được, mà KHÔNG
# gây tác dụng phụ nào. Mọi script privops theo cùng quy ước này.
if [[ $# -ge 1 && "$1" == "--check" ]]; then
    echo "OK"
    exit 0
fi

command -v caddy >/dev/null 2>&1 || { echo "caddy is not installed" >&2; exit 1; }

mkdir -p "${RUN_DIR}" "${CONFIG_DIR}"
chown "${KEENRIG_USER}:${KEENRIG_USER}" "${RUN_DIR}" "${CONFIG_DIR}"

# Cấu hình gốc. Ba điều đáng nói, mỗi điều là một lỗi đã gặp:
#
#  1. `listen` có :80 VÀ :443. Thiếu :443 thì driver không mở được HTTPS và
#     `Apply` vẫn báo thành công.
#  2. `tls_connection_policies` PHẢI có. Automatic HTTPS của Caddy suy ra
#     "cổng này cần TLS" từ host matcher trong route; máy chưa có tên miền nào
#     thì không có matcher nào, và Caddy phục vụ HTTP TRẦN ở :443.
#  3. `routes` RỖNG. Driver là chủ sở hữu duy nhất của mảng này.
cat >"${CONFIG_FILE}" <<EOF
{
  "admin": {
    "listen": "unix/${ADMIN_SOCK}",
    "origins": ["localhost"]
  },
  "logging": {
    "logs": { "default": { "level": "INFO" } }
  },
  "apps": {
    "http": {
      "servers": {
        "keenrig": {
          "listen": [":80", ":443"],
          "routes": [],
          "tls_connection_policies": [{}]
        }
      }
    }
  }
}
EOF
chown "${KEENRIG_USER}:${KEENRIG_USER}" "${CONFIG_FILE}"

# Kiểm cú pháp TRƯỚC khi khởi động. `caddy run` với config hỏng sẽ chết ngay,
# và systemd sẽ restart vòng lặp — người vận hành thấy "caddy cứ restart" thay
# vì thấy "config sai ở dòng N".
caddy validate --config "${CONFIG_FILE}" >/dev/null

systemctl daemon-reload

# Gói `caddy` của Debian/Ubuntu tự BẬT unit riêng của nó (`caddy.service`, phục
# vụ /etc/caddy/Caddyfile) và unit đó chiếm :80 ngay lúc apt cài xong. Không tắt
# nó thì keenrig-caddy chết với "listen tcp :80: bind: address already in use",
# box lặp mãi "caddy-admin.sock: connection refused", và KHÔNG có gì nghe :443 —
# đo được trên VPS Ubuntu 24.04 sạch, 2026-10-02 (case 1). Gateway của máy này
# là keenrig-caddy; một Caddy thứ hai trên cùng cổng không bao giờ đúng.
if systemctl list-unit-files caddy.service >/dev/null 2>&1 &&
    systemctl list-unit-files caddy.service | grep -q '^caddy\.service'; then
    systemctl disable --now caddy.service >/dev/null 2>&1 || true
fi

systemctl enable --now keenrig-caddy.service

# Đợi socket XUẤT HIỆN, không phải đợi systemd báo "active".
#
# Type=notify của systemd nói tiến trình đã lên, KHÔNG nói admin API đã nghe.
# Trả về sớm ở đây nghĩa là lần Apply đầu tiên của box thất bại vì socket chưa
# có, reconciler backoff, và app đầu tiên lên chậm hơn cần thiết vài chục giây.
for _ in $(seq 30); do
    [[ -S "${ADMIN_SOCK}" ]] && break
    sleep 1
done
if [[ ! -S "${ADMIN_SOCK}" ]]; then
    echo "${ADMIN_SOCK} did not appear within 30s" >&2
    systemctl status --no-pager keenrig-caddy.service >&2 || true
    exit 1
fi

# Socket phải thuộc về user keenrig: box chạy dưới user đó và cần GHI vào đây.
# Caddy tạo socket với quyền của chính nó (root), nên phải sửa lại sau.
chown "${KEENRIG_USER}:${KEENRIG_USER}" "${ADMIN_SOCK}"
chmod 0660 "${ADMIN_SOCK}"

echo "caddy is up, admin API at ${ADMIN_SOCK}"
