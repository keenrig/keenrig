#!/bin/bash
# Test nginx-bootstrap.sh + nginx-ctl.sh trên NGINX THẬT.
#
#	docker run --rm -v <scripts>:/scripts:ro debian:12-slim bash /scripts/nginx_test.sh
#
# # Nó kiểm gì mà `nginx -t` không kiểm được
#
# `nginx -t` chỉ nói cú pháp đúng. Nó KHÔNG nói request đi đúng chỗ. Ba câu chỉ
# request thật trả lời được:
#
#	gõ thẳng IP        → Admin UI, KHÔNG phải app đầu tiên (PX-03 + PX-09)
#	tên miền đã cấu hình → app
#	config hỏng        → TỪ CHỐI nạp, và app cũ vẫn phục vụ
#
# # Bài học từ lần viết test này
#
# Bản đầu gọi curl qua `$(curl -H \"Host: x\" …)` lồng trong một chuỗi
# `bash -c '...'`. Dấu nháy escape bị đẩy VÀO CHÍNH header, nginx không đọc ra
# Host, và mọi request rơi vào default_server. Test đỏ, và nó trông y hệt "vhost
# không có hiệu lực" — tôi suýt đi sửa sản phẩm.
#
# Vì vậy file này là MỘT SCRIPT RIÊNG, không phải chuỗi truyền cho bash -c.

set -u -o pipefail

readonly SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export KEENRIG_BASE=/var/lib/keenrig
export KEENRIG_USER=keenrig

pass=0
fail=0
ok()  { echo "  ✓ $1"; pass=$((pass + 1)); }
bad() { echo "  ✗ $1"; fail=$((fail + 1)); }

need() {
    command -v "$1" >/dev/null 2>&1 && return 0
    echo "$1 is missing - install it: apt-get install -y $2" >&2
    exit 127
}
need nginx nginx
need curl curl
need openssl openssl
need python3 python3

id -u keenrig >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin keenrig

# --- upstream giả -----------------------------------------------------------------
mkdir -p "$KEENRIG_BASE" /tmp/admin /tmp/app
echo "KEENRIG-ADMIN-UI"   > /tmp/admin/index.html
echo "APP-CUA-NGUOI-DUNG" > /tmp/app/index.html
( cd /tmp/admin && exec python3 -m http.server 8080 ) >/dev/null 2>&1 &
( cd /tmp/app   && exec python3 -m http.server 9090 ) >/dev/null 2>&1 &
sleep 2

# Khẳng định upstream SỐNG trước đã. Không có bước này thì mọi thất bại bên
# dưới đều mơ hồ giữa "nginx định tuyến sai" và "chẳng có gì để định tuyến tới".
[[ "$(curl -s http://127.0.0.1:8080/)" == "KEENRIG-ADMIN-UI" ]] || { echo "the admin upstream is dead"; exit 1; }
[[ "$(curl -s http://127.0.0.1:9090/)" == "APP-CUA-NGUOI-DUNG" ]] || { echo "the app upstream is dead"; exit 1; }

# get <host> — GET qua gateway với header Host cho trước.
# Tương đương một dòng /etc/hosts, không đụng cấu hình máy.
get()      { curl -s --max-time 5 -H "Host: $1" http://127.0.0.1/ | head -1; }
get_https() { curl -sk --max-time 5 https://127.0.0.1/ | head -1; }
get_ip()   { curl -s --max-time 5 http://127.0.0.1/ | head -1; }

echo "== bootstrap"
if "${SCRIPTS}/nginx-bootstrap.sh" >/dev/null 2>&1; then ok "it ran"; else bad "it failed"; fi
if nginx -t >/dev/null 2>&1; then ok "nginx -t is green"; else bad "nginx -t is red"; fi

# Quyền: box chạy dưới user keenrig và phải GHI được vào sites/ mỗi lần Apply.
sites="$KEENRIG_BASE/node/proxy/sites"
if sudo -u keenrig test -w "$sites" 2>/dev/null || [[ "$(stat -c '%U' "$sites")" == "keenrig" ]]; then
    ok "sites/ is writable by the keenrig user"
else
    bad "sites/ is NOT writable by keenrig - the driver cannot render vhosts"
fi
key="$KEENRIG_BASE/node/proxy/cert/keenrig-self-signed.key"
if [[ "$(stat -c '%a' "$key")" == "600" ]]; then
    ok "the TLS key is 0600"
else
    bad "the TLS key is mode $(stat -c '%a' "$key") - every process on the box can read it"
fi

nginx
sleep 1

echo
echo "== PX-03: by IP / an unknown domain -> the Admin UI"
[[ "$(get_ip)" == "KEENRIG-ADMIN-UI" ]]              && ok "bare IP -> Admin UI"       || bad "bare IP -> $(get_ip)"
[[ "$(get khong-ai-biet.example)" == "KEENRIG-ADMIN-UI" ]] && ok "unknown domain -> Admin UI" || bad "unknown domain -> $(get khong-ai-biet.example)"
[[ "$(get_https)" == "KEENRIG-ADMIN-UI" ]]           && ok "HTTPS by IP (self-signed cert)" || bad "HTTPS by IP -> $(get_https)"

echo
echo "== PX-01: the driver renders a vhost -> it takes effect after a reload"
cat > "$sites/keenrig-app.example.conf" <<'CONF'
server {
    listen 80;
    server_name app.example.test;
    location / { proxy_pass http://127.0.0.1:9090; }
}
CONF
if "${SCRIPTS}/nginx-ctl.sh" reload >/dev/null 2>&1; then ok "nginx-ctl reload"; else bad "nginx-ctl reload failed"; fi
[[ "$(get app.example.test)" == "APP-CUA-NGUOI-DUNG" ]] && ok "a configured domain -> the app" \
    || bad "a configured domain -> $(get app.example.test)"

# PX-09 — đây là vế PHẢI ĐÚNG cùng lúc với PX-03: catch-all đi tới Admin UI,
# KHÔNG tới app của người dùng. Thiếu vế này thì ai biết IP là vào được app mà
# chẳng cần biết tên miền.
[[ "$(get_ip)" == "KEENRIG-ADMIN-UI" ]] && ok "the IP does NOT land on the app (PX-09)" \
    || bad "the IP landed on the app: $(get_ip)"

echo
echo "== nginx-ctl: a broken config is REFUSED and service is not interrupted"
echo "server { missing closing brace" > "$sites/keenrig-broken.conf"
if "${SCRIPTS}/nginx-ctl.sh" reload >/dev/null 2>&1; then
    bad "THE BROKEN CONFIG WAS LOADED"
else
    ok "refused to load the broken config"
fi
[[ "$(get app.example.test)" == "APP-CUA-NGUOI-DUNG" ]] && ok "the app still serves after the refusal" \
    || bad "the app broke after the broken config was refused"
rm -f "$sites/keenrig-broken.conf"

echo
echo "== nginx-ctl: a verb outside the list is refused"
for verb in "restart" "stop" "" "reload;rm -rf /" "-s"; do
    "${SCRIPTS}/nginx-ctl.sh" "$verb" >/dev/null 2>&1
    [[ $? -eq 2 ]] && ok "verb '${verb}' refused" || bad "verb '${verb}' was NOT refused"
done

echo
echo "== --waf is REFUSED while the ModSecurity module is not loaded"
# Khai CapWAF mà module không có là nói dối tầng admission: người dùng bật WAF,
# admission cho qua, và app không được bảo vệ.
if "${SCRIPTS}/nginx-bootstrap.sh" --waf >/dev/null 2>&1; then
    bad "--waf was accepted without ngx_http_modsecurity_module.so"
else
    ok "--waf refused while the module is missing"
fi

echo
echo "== idempotent: a second run does not break the live configuration"
"${SCRIPTS}/nginx-bootstrap.sh" >/dev/null 2>&1
"${SCRIPTS}/nginx-ctl.sh" reload >/dev/null 2>&1
[[ "$(get app.example.test)" == "APP-CUA-NGUOI-DUNG" ]] && ok "the vhost survived the second bootstrap" \
    || bad "the second bootstrap lost the vhost"

echo
echo "== summary: ${pass} passed, ${fail} failed"
[[ ${fail} -eq 0 ]]
