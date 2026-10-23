#!/bin/bash
# keenrig: khởi động lại / nạp lại một dịch vụ hệ thống.
#
# Hợp đồng (privops.ScriptRestartService, guards_test.sh):
#   restartservice.sh --check   → in "OK", thoát 0, không tác dụng phụ
#   restartservice.sh <tên>     → tên phải nằm trong UNITS bên dưới
#   tham số sai / thiếu         → thoát 2, TRƯỚC khi chạm systemctl
#   không chạy bằng root        → thoát 1
#
# # Vì sao là DANH SÁCH TRẮNG chứ không phải `systemctl restart "$1"`
#
# sudoers cho phép chạy script này với BẤT KỲ tham số nào — nó không kiểm được
# đối số. Nếu script chuyển thẳng "$1" cho systemctl thì một lỗi bất kỳ trong
# control API biến thành quyền restart mọi dịch vụ trên máy, kể cả sshd và
# auditd. Danh sách trắng là chỗ DUY NHẤT chặn được điều đó, và nó phải nằm
# trong script chứ không nằm trong lời hứa của tầng gọi.

set -o errexit -o nounset -o pipefail

# tên gọi → "<unit systemd> <chế độ>"
#
#   prefer-reload  reload nếu unit đang chạy, ngược lại restart. Dùng cho proxy:
#                  reload giữ nguyên listener nên kết nối đang mở không đứt
#                  (PX-09). nginx KHÔNG được kiểm `nginx -t` ở đây — nginx-ctl.sh
#                  làm việc đó; hai chỗ cùng kiểm là hai chỗ trôi khỏi nhau.
#   reload         box tự xử lý SIGHUP; restart sẽ cắt ngang chính request đang
#                  gọi script này.
#   restart        docker: restart kéo theo viết lại iptables mất vài giây —
#                  không chờ, reconciler tự backoff tới khi dockerd trả lời.
declare -A UNITS=(
    [caddy]="keenrig-caddy.service prefer-reload"
    [nginx]="nginx.service prefer-reload"
    [docker]="docker.service restart"
    [box]="keenrig-box.service reload"
    [agent]="keenrig-agent.service restart"
)

usage() {
    echo "usage: restartservice.sh <caddy|nginx|docker|box|agent>" >&2
    exit 2
}

(( EUID == 0 )) || { echo "restartservice.sh: root required" >&2; exit 1; }

(( $# == 1 )) || usage
name="$1"

if [[ "${name}" == "--check" ]]; then
    echo "OK"
    exit 0
fi

# Regex TRƯỚC khi tra bảng: subscript của `-v UNITS[...]` bị expand (một tên
# như '$(whoami)' sẽ chạy lệnh), và `UNITS[*]`/`UNITS[@]` luôn "tồn tại".
if [[ ! "${name}" =~ ^[a-z]+$ || ! -v "UNITS[${name}]" ]]; then
    echo "restartservice.sh: '${name}' is not on the allow-list" >&2
    exit 2
fi

read -r unit mode <<< "${UNITS[${name}]}"

# --no-block ở mọi nhánh: script chạy bên trong một request của control API, và
# chờ systemd ở đây là giữ request đó mở suốt thời gian dịch vụ khởi động.
case "${mode}" in
prefer-reload)
    if systemctl --quiet is-active "${unit}"; then
        systemctl --no-block reload "${unit}"
    else
        systemctl --no-block restart "${unit}"
    fi
    ;;
reload)  systemctl --no-block reload "${unit}" ;;
restart) systemctl --no-block restart "${unit}" ;;
esac
