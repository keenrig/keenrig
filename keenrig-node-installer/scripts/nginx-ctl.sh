#!/bin/bash
# keenrig: kiểm cú pháp / nạp lại cấu hình nginx.
#
# # Vì sao driver KHÔNG gọi thẳng `nginx -s reload`
#
# Mặc định của driver là `nginx -s reload ;; nginx -t` (xem godoc package
# nginx). Cả hai lệnh đó cần root: master process của nginx chạy bằng root, và
# `-s reload` gửi tín hiệu cho nó. Box chạy dưới user `keenrig`, nên mặc định
# ấy chỉ đúng khi ai đó chạy box bằng root — tức là đúng ở chỗ ta cố tình
# không đứng.
#
# Vì vậy installer đặt DSN thành:
#
#	KEENRIG_PROXY_CONFIG="sudo <base>/scripts/nginx-ctl.sh reload ;; sudo <base>/scripts/nginx-ctl.sh test"
#
# # Vì sao TEST và RELOAD là hai động từ của MỘT script
#
# Driver cần chúng tách rời (kiểm trước, nạp sau). Nhưng cho chúng hai script
# nghĩa là hai dòng sudoers, hai chỗ kiểm tham số, và hai chỗ để quên. Một
# script hai động từ giữ bề mặt đặc quyền ở đúng một chỗ đọc được.

set -eu -o pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

if [[ $# -ge 1 && "$1" == "--check" ]]; then
    echo "OK"
    exit 0
fi

if [[ $# -ne 1 ]]; then
    echo "usage: nginx-ctl.sh <test|reload>" >&2
    exit 2
fi

command -v nginx >/dev/null 2>&1 || { echo "nginx is not installed" >&2; exit 1; }

# --- reload là BẤT ĐỒNG BỘ, và đó là một khác biệt hành vi thật ------------------
#
# `nginx -s reload` gửi SIGHUP rồi TRẢ VỀ NGAY. Master mới đọc lại config và
# sinh worker mới sau đó; trong khoảng giữa, worker CŨ vẫn phục vụ config cũ.
# Đo được: ngay sau reload → route cũ; sau ~2 giây → route mới.
#
# Đây là chỗ nginx khác Caddy về BẢN CHẤT, không phải về chi tiết. Admin API
# của Caddy đồng bộ: `PATCH` trả về nghĩa là cấu hình đã sống. Nếu script này
# cũng trả về ngay thì `Apply` của driver nginx báo "xong" trong khi route chưa
# có hiệu lực — reconciler ghi `applied_rev`, và người dùng thấy 404 trên một
# app mà hệ thống khẳng định đã deploy.
#
# Vì vậy ranh giới đồng bộ hoá đặt Ở ĐÂY: script chỉ trả về khi worker đã được
# thay. Nhờ đó hợp đồng "Apply trả về = cấu hình đã sống" giữ nguyên qua mọi
# gateway — đó chính là điều seam sinh ra để bảo đảm.

# worker_pids liệt kê PID các worker (con của master nginx).
#
# Đọc thẳng /proc thay vì dùng pgrep: procps KHÔNG có sẵn trong nhiều image
# tối giản, và một phụ thuộc thêm ở đường nóng của reload là một chỗ nữa để
# hỏng trên máy khách.
#
# CẢNH BÁO khi sửa hàm này: nó chạy dưới `set -e -o pipefail`. Bản đầu kết
# thúc vòng lặp bằng `[[ … ]] && echo …` rồi nối vào `| sort`. Lần lặp CUỐI
# CÙNG mà điều kiện sai làm vòng lặp trả non-zero, pipefail lan nó ra cả
# pipeline, và `before="$(worker_pids)"` giết cả script — TRƯỚC KHI gửi tín
# hiệu reload. Triệu chứng: `nginx-ctl.sh reload` thoát 0 mà chẳng nạp gì.
#
# Vì vậy hàm này gom vào biến rồi mới in một lần, và luôn `return 0`.
worker_pids() {
    local master pid ppid stat out=""
    master="$(cat "${KEENRIG_BASE:-/var/lib/keenrig}/node/run/nginx.pid" 2>/dev/null || true)"
    if [[ -z "${master}" ]]; then
        echo ""
        return 0
    fi
    for pid in /proc/[0-9]*; do
        pid="${pid#/proc/}"
        stat="$(cat "/proc/${pid}/stat" 2>/dev/null || true)"
        if [[ -z "${stat}" ]]; then
            continue
        fi
        # /proc/<pid>/stat: `pid (comm) state ppid …`. comm CÓ THỂ chứa khoảng
        # trắng và dấu ngoặc, nên định vị từ dấu ')' CUỐI CÙNG rồi đếm tiếp:
        # +1 là state, +2 là ppid.
        ppid="$(awk '{ for (i=NF; i>0; i--) if ($i ~ /\)$/) { print $(i+2); exit } }' <<<"${stat}" || true)"
        if [[ "${ppid}" == "${master}" ]]; then
            out="${out}${pid} "
        fi
    done
    echo "${out}"
    return 0
}

# wait_reload đợi tập worker ĐỔI so với trước khi gửi tín hiệu.
#
# Quá hạn thì CẢNH BÁO chứ không lỗi: reload đã được gửi và gần như chắc chắn
# sẽ có hiệu lực; trả lỗi ở đây sẽ làm reconciler backoff và thử lại một việc
# đã thành công.
wait_reload() {
    local before="$1" now i
    for i in $(seq 100); do   # tối đa ~10 giây
        now="$(worker_pids)"
        if [[ -n "${now}" && "${now}" != "${before}" ]]; then
            return 0
        fi
        sleep 0.1
    done
    echo "WARNING: no nginx worker was replaced within 10s - the new configuration may not be live" >&2
    return 0
}

case "$1" in
test)
    # `nginx -t` in ra stderr kể cả khi THÀNH CÔNG. Không gộp về stdout thì
    # driver thấy đầu ra rỗng và không có gì để hiện khi config sai.
    nginx -t 2>&1
    ;;
reload)
    # Kiểm TRƯỚC khi nạp, luôn luôn — kể cả khi driver đã tự gọi `test`.
    #
    # Giữa lần driver kiểm và lần này, file trên đĩa có thể đã đổi (một Apply
    # khác, hoặc người vận hành sửa tay). `nginx -s reload` với config hỏng làm
    # master process TỪ CHỐI nạp và giữ config cũ — không sập, nhưng route mới
    # im lặng không có hiệu lực, và đó là kiểu hỏng không ai truy ra.
    if ! nginx -t 2>&1; then
        echo "REFUSING to reload: the nginx configuration is invalid" >&2
        exit 1
    fi
    # Ghi lại tập worker TRƯỚC khi nạp, để biết lúc nào nạp xong. Xem wait_reload.
    before="$(worker_pids)"

    if systemctl -q is-active nginx 2>/dev/null; then
        systemctl reload nginx
    else
        # Không có systemd (container) → gửi tín hiệu thẳng.
        nginx -s reload
    fi
    wait_reload "${before}"
    ;;
*)
    echo "invalid verb: $1 (expected test|reload)" >&2
    exit 2
    ;;
esac
