#!/bin/bash
# Test HÀNG RÀO của bộ script đặc quyền.
#
# Chạy TRONG một container Linux, bằng root, trên một cây thư mục giả. Lý do
# phải là container: script chạy `rm -rf` và `chown`, và một test chạy sai chỗ
# là một test xoá máy của người chạy nó.
#
#	docker run --rm -v <scripts>:/scripts:ro debian:12-slim /scripts/guards_test.sh
#
# Cái nó kiểm KHÔNG phải "script làm đúng việc" — phần đó cần systemd và Caddy.
# Nó kiểm điều quan trọng hơn: script TỪ CHỐI đúng thứ phải từ chối. Một script
# `rm -rf` mà thiếu hàng rào thì "làm đúng việc" chẳng an ủi được ai.

set -u -o pipefail

readonly SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export KEENRIG_BASE=/tmp/keenrig-test
export KEENRIG_USER=root # trong container test không có user keenrig

pass=0
fail=0

ok()   { echo "  ✓ $1"; pass=$((pass + 1)); }
bad()  { echo "  ✗ $1"; fail=$((fail + 1)); }

# expect_fail <mô tả> <lệnh...> — lệnh PHẢI thất bại.
expect_fail() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        bad "${desc} - ACCEPTED (it must be refused)"
    else
        ok "${desc}"
    fi
}

expect_ok() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        ok "${desc}"
    else
        bad "${desc} - refused (it must be accepted)"
    fi
}

reset_tree() {
    rm -rf "${KEENRIG_BASE}"
    mkdir -p "${KEENRIG_BASE}/apps"
}

echo "== --check runs and has NO side effects"
reset_tree
for s in caddy-bootstrap.sh restartservice.sh appdata.sh du.sh reboot.sh pair.sh; do
    out="$("${SCRIPTS}/${s}" --check 2>&1)"
    if [[ "${out}" == "OK" ]]; then
        ok "${s} --check"
    else
        bad "${s} --check printed '${out}', want OK"
    fi
done
# --check không được tạo/xoá gì.
if [[ -z "$(ls -A "${KEENRIG_BASE}/apps")" ]]; then
    ok "--check left no side effects"
else
    bad "--check touched the disk"
fi

echo
echo "== appdata.sh: a hostile app-id is REFUSED"
reset_tree
# Mỗi chuỗi dưới đây là một cách khác nhau để thoát khỏi apps.
for id in ".." "." "" "a" "../../etc" "app/../../root" "/etc" "app;rm -rf /" \
          "app id" "APP" "app_name" "-x" "x-" '$(whoami)' 'app`id`'; do
    expect_fail "create ${id@Q}" "${SCRIPTS}/appdata.sh" create "${id}"
    expect_fail "remove ${id@Q}" "${SCRIPTS}/appdata.sh" remove "${id}"
done

echo
echo "== appdata.sh: the legitimate lifecycle"
reset_tree
expect_ok   "create app-hop-le"        "${SCRIPTS}/appdata.sh" create "app-hop-le"
if [[ -d "${KEENRIG_BASE}/apps/app-hop-le" ]]; then
    ok "the directory was created"
else
    bad "the directory was NOT created"
fi
perm="$(stat -c '%a' "${KEENRIG_BASE}/apps/app-hop-le")"
if [[ "${perm}" == "750" ]]; then
    ok "mode 0750 (no read for 'others' on app data)"
else
    bad "mode = ${perm}, want 750"
fi
expect_ok "chown numeric"  "${SCRIPTS}/appdata.sh" chown "app-hop-le" "1000:1000"
expect_fail "chown by NAME""${SCRIPTS}/appdata.sh" chown "app-hop-le" "root:root"
expect_fail "chown empty"  "${SCRIPTS}/appdata.sh" chown "app-hop-le" ""
expect_ok "remove"         "${SCRIPTS}/appdata.sh" remove "app-hop-le"
if [[ ! -d "${KEENRIG_BASE}/apps/app-hop-le" ]]; then
    ok "the directory was removed"
else
    bad "the directory is still there"
fi
expect_ok "a second remove is a no-op" "${SCRIPTS}/appdata.sh" remove "app-hop-le"

echo
echo "== appdata.sh: a symlink does NOT drag in anything outside"
reset_tree
mkdir -p /tmp/muc-tieu-ngoai
touch /tmp/muc-tieu-ngoai/file-quan-trong
# app-id hợp lệ, NHƯNG thư mục là symlink trỏ ra ngoài.
#
# Nói thẳng phạm vi: `rm -rf <symlink>` vốn chỉ xoá chính symlink, nên test này
# xanh kể cả khi không có lớp realpath. Nó KHÔNG chứng minh lớp realpath hoạt
# động — nó chứng minh ta không vô tình viết một dạng lệnh ĐI THEO symlink
# (trailing slash, hay `chown -R` không có -h). Đó là thứ dễ thêm vào lúc sửa
# code sau này, và test này là chỗ nó bị bắt.
ln -s /tmp/muc-tieu-ngoai "${KEENRIG_BASE}/apps/app-symlink"
"${SCRIPTS}/appdata.sh" remove "app-symlink" >/dev/null 2>&1
if [[ -f /tmp/muc-tieu-ngoai/file-quan-trong ]]; then
    ok "remove did not follow the symlink out"
else
    bad "THE SYMLINK DELETED A FILE OUTSIDE apps"
fi
reset_tree
ln -s /tmp/muc-tieu-ngoai "${KEENRIG_BASE}/apps/app-symlink2"
"${SCRIPTS}/appdata.sh" chown "app-symlink2" "1000:1000" >/dev/null 2>&1
owner="$(stat -c '%u' /tmp/muc-tieu-ngoai/file-quan-trong)"
if [[ "${owner}" == "0" ]]; then
    ok "chown did not follow the symlink out (-h)"
else
    bad "CHOWN CHANGED THE OWNER OF A FILE OUTSIDE apps (uid=${owner})"
fi

echo
echo "== KEENRIG_BASE comes from the CALLER (env_keep) - an absurd base is refused"
reset_tree
for b in "/" "khong-tuyet-doi" "../../.." ""; do
    if KEENRIG_BASE="${b}" "${SCRIPTS}/appdata.sh" remove "app-x" >/dev/null 2>&1; then
        # base rỗng rơi về mặc định /var/lib/keenrig — đó là hành vi ĐÚNG.
        if [[ -z "${b}" ]]; then
            ok "empty base -> the default is used"
        else
            bad "base ${b@Q} was accepted"
        fi
    else
        if [[ -z "${b}" ]]; then
            ok "empty base -> the default is used (nothing to remove)"
        else
            ok "base ${b@Q} refused"
        fi
    fi
done

echo
echo "== du.sh"
reset_tree
mkdir -p "${KEENRIG_BASE}/apps/app-do"
dd if=/dev/zero of="${KEENRIG_BASE}/apps/app-do/data" bs=1024 count=64 >/dev/null 2>&1
size="$("${SCRIPTS}/du.sh" app-do 2>/dev/null)"
if [[ "${size}" =~ ^[0-9]+$ ]] && [[ "${size}" -ge 65536 ]]; then
    ok "du returned ${size} bytes (>= 64KiB)"
else
    bad "du returned '${size}'"
fi
if [[ "$("${SCRIPTS}/du.sh" app-khong-ton-tai 2>/dev/null)" == "0" ]]; then
    ok "a missing app -> 0, not an error"
else
    bad "a missing app did not return 0"
fi
expect_fail "du with a hostile id" "${SCRIPTS}/du.sh" "../.."

echo
echo "== restartservice.sh: THE ALLOW-LIST"
# Dịch vụ ngoài danh sách phải bị chặn TRƯỚC khi chạm systemctl. Trong container
# không có systemd nên dịch vụ hợp lệ cũng lỗi — ta chỉ kiểm MÃ THOÁT 2 (từ
# chối vì tham số) khác với các mã khác.
for svc in "sshd" "auditd" "" "caddy;reboot" "../../bin/sh" "*"; do
    "${SCRIPTS}/restartservice.sh" "${svc}" >/dev/null 2>&1
    if [[ $? -eq 2 ]]; then
        ok "service ${svc@Q} refused"
    else
        bad "service ${svc@Q} was NOT refused by the argument check"
    fi
done
"${SCRIPTS}/restartservice.sh" "caddy" >/dev/null 2>&1
if [[ $? -ne 2 ]]; then
    ok "caddy passes the argument check"
else
    bad "caddy was refused by the argument check"
fi
"${SCRIPTS}/restartservice.sh" >/dev/null 2>&1
[[ $? -eq 2 ]] && ok "no argument -> refused" || bad "no argument was not refused"

echo
echo "== pair.sh: a malformed token or cloud URL is REFUSED before any request"
for tok in "" "abc" "$(printf 'g%.0s' {1..64})" "$(printf 'A%.0s' {1..64})" \
           "$(printf 'a%.0s' {1..63})" "$(printf 'a%.0s' {1..65})" '$(whoami)' \
           "$(printf 'a%.0s' {1..60})\",\"x"; do
    expect_fail "token ${tok@Q}" "${SCRIPTS}/pair.sh" "${tok}"
done
good_tok="$(printf 'a%.0s' {1..64})"
for url in "http://console.keenrig.com" "https://evil.com/x" "https://a.com;id" "file:///etc/passwd"; do
    KEENRIG_CLOUD_URL="${url}" "${SCRIPTS}/pair.sh" "${good_tok}" >/dev/null 2>&1
    [[ $? -eq 2 ]] && ok "cloud url ${url@Q} refused" || bad "cloud url ${url@Q} was not refused"
done
"${SCRIPTS}/pair.sh" >/dev/null 2>&1
[[ $? -eq 2 ]] && ok "pair.sh with no argument -> refused" || bad "pair.sh with no argument was not refused"

echo
echo "== summary: ${pass} passed, ${fail} failed"
rm -rf "${KEENRIG_BASE}" /tmp/muc-tieu-ngoai
[[ ${fail} -eq 0 ]]
