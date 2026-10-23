#!/bin/bash
# keenrig: dựng cấu hình GỐC cho nginx (và biến thể WAF) rồi khởi động nó.
#
#	nginx-bootstrap.sh              nginx thường
#	nginx-bootstrap.sh --waf        nginx + ModSecurity nạp OWASP CRS
#
# Đối xứng với caddy-bootstrap.sh: "gốc" nghĩa là ĐÚNG những gì driver không
# đẩy được qua đường của nó. Mọi vhost của app do driver render vào
# <base>/node/proxy/sites/keenrig-*.conf — file này KHÔNG được biết gì về app.
#
# # Khác Caddy ở đâu, và vì sao khác
#
# Caddy nhận config qua admin API nên "gốc" chỉ cần nói admin API nghe ở đâu.
# nginx đọc config TỪ ĐĨA, nên gốc phải dựng cả bộ khung: nginx.conf, include
# thư mục sites, cert cho truy cập bằng IP, và một default_server.
#
# Hệ quả trực tiếp: với nginx, cấu hình đang chạy có HAI nguồn (file ta sinh +
# file người vận hành có thể sửa). Đó là lý do mọi file ta sinh mang tiền tố
# `keenrig-` và ta KHÔNG BAO GIỜ đụng file khác — cùng nguyên tắc "danh tính là
# nhãn" của seam proxy.
#
# # PX-03 với nginx
#
# Caddy tự cấp chứng chỉ nội bộ cho IP. nginx thì không có gì tương đương, nên
# ta tự sinh một cert tự ký cho các IP của máy. Không có nó thì `listen 443
# ssl` không dựng được và nginx TỪ CHỐI khởi động — hỏng nặng hơn nhiều so với
# việc thiếu HTTPS trên IP.

set -eu -o pipefail

readonly BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
readonly KEENRIG_USER="${KEENRIG_USER:-keenrig}"
readonly PROXY_DIR="${BASE}/node/proxy"
readonly SITES_DIR="${PROXY_DIR}/sites"
readonly CERT_DIR="${PROXY_DIR}/cert"
readonly SELF_CERT="${CERT_DIR}/keenrig-self-signed.crt"
readonly SELF_KEY="${CERT_DIR}/keenrig-self-signed.key"
readonly ADMIN_UPSTREAM="${KEENRIG_ADMIN_UPSTREAM:-127.0.0.1:8080}"

WAF=0
CHECK=0
while [[ $# -gt 0 ]]; do
    case "$1" in
    --waf) WAF=1; shift ;;
    --check) CHECK=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi
if [[ ${CHECK} -eq 1 ]]; then
    echo "OK"
    exit 0
fi

if [[ "${BASE}" != /* || "${BASE}" == "/" ]]; then
    echo "REFUSED: KEENRIG_BASE must be absolute and not '/': ${BASE}" >&2
    exit 3
fi
command -v nginx >/dev/null 2>&1 || { echo "nginx is not installed" >&2; exit 1; }

mkdir -p "${SITES_DIR}" "${CERT_DIR}"
# sites/ phải GHI ĐƯỢC bởi user keenrig: driver render vhost vào đây mỗi lần
# Apply. cert/ cũng vậy — module certs cấp cert xuống đó khi gateway không có
# năng lực `acme` (đúng trường hợp nginx).
chown -R "${KEENRIG_USER}:${KEENRIG_USER}" "${SITES_DIR}" "${CERT_DIR}"
chmod 0750 "${SITES_DIR}" "${CERT_DIR}"

# --- WAF: chỉ bật khi module THẬT SỰ có ------------------------------------------
#
# Driver khai `CapWAF` dựa vào cờ này. Khai mà module chưa nạp là nói dối tầng
# admission: người dùng bật WAF, admission cho qua, và app không được bảo vệ.
MODSEC_LOAD=""
if [[ ${WAF} -eq 1 ]]; then
    modsec_so=""
    for p in /usr/lib/nginx/modules/ngx_http_modsecurity_module.so \
             /usr/share/nginx/modules/ngx_http_modsecurity_module.so \
             /etc/nginx/modules/ngx_http_modsecurity_module.so; do
        [[ -f "$p" ]] && { modsec_so="$p"; break; }
    done
    if [[ -z "${modsec_so}" ]]; then
        echo "REFUSING --waf: ngx_http_modsecurity_module.so was not found." >&2
        echo "  Install an nginx build with ModSecurity and re-run, or drop --waf." >&2
        echo "  Setting the WAF flag while the module is not loaded means admission" >&2
        echo "  accepts a configuration that does nothing, and users believe their" >&2
        echo "  apps are protected when they are not." >&2
        exit 1
    fi
    crs_setup=""
    for p in /etc/nginx/modsec/main.conf /etc/modsecurity/modsecurity.conf; do
        [[ -f "$p" ]] && { crs_setup="$p"; break; }
    done
    if [[ -z "${crs_setup}" ]]; then
        echo "REFUSING --waf: the module is present but the OWASP CRS configuration was not found." >&2
        exit 1
    fi
    MODSEC_LOAD="load_module ${modsec_so};"
    echo "==> WAF: ${modsec_so} + ${crs_setup}"
fi

# --- cert tự ký cho truy cập bằng IP (PX-03) --------------------------------------
#
# Sinh lại khi thiếu hoặc sắp hết hạn. KHÔNG sinh lại mỗi lần chạy: mỗi cert
# mới là một cảnh báo mới trên trình duyệt của người vận hành, và họ sẽ học
# cách bấm qua cảnh báo — đúng thói quen ta không muốn tạo.
need_cert=1
if [[ -f "${SELF_CERT}" ]] && openssl x509 -checkend $((30 * 86400)) -noout -in "${SELF_CERT}" >/dev/null 2>&1; then
    need_cert=0
fi
if [[ ${need_cert} -eq 1 ]]; then
    echo "==> generating a self-signed certificate for access by IP"
    # SAN gồm mọi IP không phải loopback + localhost. Cert KHÔNG có SAN thì
    # trình duyệt hiện đại từ chối hẳn, không chỉ cảnh báo.
    sans="DNS:localhost,IP:127.0.0.1"
    while read -r ip; do
        [[ -n "$ip" ]] && sans="${sans},IP:${ip}"
    done < <(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)

    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "${SELF_KEY}" -out "${SELF_CERT}" \
        -subj "/CN=keenrig-self-signed" \
        -addext "subjectAltName=${sans}" >/dev/null 2>&1
    chown "${KEENRIG_USER}:${KEENRIG_USER}" "${SELF_CERT}" "${SELF_KEY}"
    # Khoá riêng 0600: nó nằm trong một thư mục mà user keenrig ghi được, và
    # để nó 0644 nghĩa là mọi tiến trình trên máy đọc được khoá TLS.
    chmod 0600 "${SELF_KEY}"
    chmod 0644 "${SELF_CERT}"
fi

# --- cấu hình gốc -----------------------------------------------------------------

cat >"${PROXY_DIR}/nginx.conf" <<EOF
# SINH TỰ ĐỘNG bởi keenrig nginx-bootstrap.sh — ĐỪNG SỬA TAY.
#
# Vhost của app nằm ở ${SITES_DIR}/keenrig-*.conf, do keenrig-box render.
# Muốn thêm vhost riêng: đặt file KHÔNG mang tiền tố keenrig- vào cùng thư mục;
# keenrig sẽ giữ nguyên nó (Report.Ignored).
${MODSEC_LOAD}

user  ${KEENRIG_USER};
worker_processes  auto;
pid  ${BASE}/node/run/nginx.pid;

events {
    # Gateway giữ nhiều kết nối đồng thời; 1024 chạm trần ở vài trăm khách và
    # triệu chứng là "thỉnh thoảng site không vào được".
    worker_connections  4096;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log  ${BASE}/node/logs/nginx-access.log;
    error_log   ${BASE}/node/logs/nginx-error.log;

    sendfile        on;
    keepalive_timeout  65;
    # Không lộ phiên bản nginx trong header/trang lỗi.
    server_tokens   off;

    # WebSocket (terminal) + SSE (logs) — PX-06.
    #
    # proxy_buffering off là điều kiện CẦN cho SSE: bật buffering thì nginx gom
    # response và log "streaming" chỉ hiện ra khi kết nối đóng. Triệu chứng
    # không giống lỗi cấu hình — app chạy đúng, nginx không báo gì.
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ''      close;
    }
    proxy_http_version 1.1;
    proxy_set_header Upgrade    \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host       \$host;
    proxy_set_header X-Real-IP  \$remote_addr;
    proxy_buffering off;
    proxy_read_timeout 3600s;

    # PX-03 — request KHÔNG khớp server_name nào (gõ thẳng IP, hoặc một tên
    # miền lạ trỏ về đây) đi tới Admin UI.
    #
    # default_server phải nằm TRƯỚC include: nginx chọn default_server là block
    # đầu tiên khai cờ đó trên mỗi cổng, và một vhost của app khai nhầm sẽ
    # nuốt mất mọi request chưa có chủ.
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        location / { proxy_pass http://${ADMIN_UPSTREAM}; }
    }
    server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        server_name _;
        ssl_certificate     ${SELF_CERT};
        ssl_certificate_key ${SELF_KEY};
        location / { proxy_pass http://${ADMIN_UPSTREAM}; }
    }

    # Vhost do keenrig-box render. Include SAU default_server.
    include ${SITES_DIR}/*.conf;
}
EOF
chown "${KEENRIG_USER}:${KEENRIG_USER}" "${PROXY_DIR}/nginx.conf"
mkdir -p "${BASE}/node/logs" "${BASE}/node/run"
chown "${KEENRIG_USER}:${KEENRIG_USER}" "${BASE}/node/logs" "${BASE}/node/run"

# Trỏ nginx hệ thống vào cấu hình của ta.
#
# Ghi đè /etc/nginx/nginx.conf bằng một `include` thay vì thay hẳn file: bản
# phân phối đặt nhiều thứ ở đó (snippets, conf.d của gói khác), và thay hẳn là
# lấy mất cấu hình của người vận hành mà không nói.
if [[ -f /etc/nginx/nginx.conf ]] && [[ ! -f /etc/nginx/nginx.conf.keenrig-backup ]]; then
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.keenrig-backup
    echo "==> backed up /etc/nginx/nginx.conf -> .keenrig-backup"
fi
ln -sf "${PROXY_DIR}/nginx.conf" /etc/nginx/nginx.conf

# Kiểm cú pháp TRƯỚC khi khởi động. `nginx -t` hỏng ở đây là lỗi của CHÍNH
# script này, và nó phải nổ ngay chứ không biến thành "nginx cứ restart".
if ! nginx -t 2>&1; then
    echo "the base configuration this script generated is INVALID - not starting nginx" >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now nginx
    systemctl reload nginx 2>/dev/null || true
fi

if [[ ${WAF} -eq 1 ]]; then
    echo "nginx (WAF) is up; vhosts are read from ${SITES_DIR}"
else
    echo "nginx is up; vhosts are read from ${SITES_DIR}"
fi
