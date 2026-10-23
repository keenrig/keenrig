#!/bin/bash
# keenrig: ghép một node ĐÃ CÀI với Keenrig Console bằng join token.
#
# Đây là cùng việc `get.sh --join` làm ở bước join_cloud, tách ra để Admin UI
# gọi được: người dùng cài standalone, về sau mới muốn quản từ Console, và con
# đường tiện nhất là dán token vào trang Cloud Link — không SSH, không chạy lại
# installer.
#
# # Vì sao cần root
#
# Kết quả pair là API key của agent, nằm trong /etc/keenrig/agent.env — root,
# 0600, đúng như get.sh ghi. Box chạy dưới user keenrig nên KHÔNG được đọc file
# đó; nó chỉ được nhờ script này ghi hộ rồi restart agent.
#
# # Kiểm tra nằm Ở ĐÂY, không ở tầng gọi (xem sudoers/keenrig)
#
#  - token: đúng 64 ký tự hex, như NewPairingToken của cloud phát ra. Không
#    thì nó có thể chèn ký tự vào JSON body hay vào agent.env.
#  - cloud URL: chỉ lấy từ môi trường của box (10-local.conf do installer ghi,
#    root sở hữu), KHÔNG từ đối số — người gọi qua control API không được trỏ
#    agent sang một control plane khác. Phải là https://host[:port].

set -eu -o pipefail

readonly BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
readonly CLOUD="${KEENRIG_CLOUD_URL:-https://console.keenrig.com}"
readonly AGENT_ENV=/etc/keenrig/agent.env

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

if [[ $# -ge 1 && "$1" == "--check" ]]; then
    echo "OK"
    exit 0
fi

if [[ $# -ne 1 ]]; then
    echo "usage: pair.sh <join-token>" >&2
    exit 2
fi

readonly TOKEN="$1"
if [[ ! "${TOKEN}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "invalid join token: expected the 64-character token from the Console" >&2
    exit 2
fi
if [[ ! "${CLOUD}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; then
    echo "invalid KEENRIG_CLOUD_URL: ${CLOUD}" >&2
    exit 2
fi

ver="$("${BASE}/bin/keenrig-agent" --version 2>/dev/null | awk '{print $2}')" || true
host="$(hostname 2>/dev/null || uname -n)"
# host_id chỉ được chứa ký tự an toàn cho JSON: hostname hợp lệ vốn đã vậy, lọc
# thêm để một hostname lạ không làm hỏng body.
host="$(printf '%s' "${host}" | tr -cd 'A-Za-z0-9._-')"
body="{\"token\":\"${TOKEN}\",\"host_id\":\"${host}\",\"version\":\"${ver:-unknown}\"}"

# Không --retry: token bị tiêu ngay lần dùng đầu, retry chỉ làm mờ lỗi thật.
res="$(curl -sS --max-time 30 -H 'Content-Type: application/json' \
    -d "${body}" "${CLOUD}/agent/v1/pair" 2>&1)" || true

env_id="$(printf '%s' "${res}" | sed -n 's/.*"env_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
api_key="$(printf '%s' "${res}" | sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ -z "${env_id}" || -z "${api_key}" ]]; then
    # Thông điệp đi thẳng lên Admin UI: nói ĐIỀU người dùng làm được.
    echo "the Console did not accept this token (it is single-use and expires after 30 minutes) - issue a new one in the Console. Response: ${res:-<empty>}" >&2
    exit 1
fi
if [[ ! "${env_id}" =~ ^[A-Za-z0-9_-]+$ || ! "${api_key}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "unexpected pairing response from ${CLOUD}" >&2
    exit 1
fi

mkdir -p /etc/keenrig
tmp="$(mktemp /etc/keenrig/.agent.env.XXXXXX)"
chmod 0600 "${tmp}"
cat >"${tmp}" <<EOF
KEENRIG_CLOUD_URL=${CLOUD}
KEENRIG_AGENT_KEY=${api_key}
KEENRIG_ENV_ID=${env_id}
KEENRIG_DATA_DIR=${BASE}
EOF
chown root:root "${tmp}"
# rename: agent.env không bao giờ ở trạng thái viết dở.
mv -f "${tmp}" "${AGENT_ENV}"

systemctl restart --no-block keenrig-agent.service
echo "${env_id}"
