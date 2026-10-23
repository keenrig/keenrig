#!/bin/bash
# keenrig: dung lượng đĩa của thư mục dữ liệu một app.
#
# Cần root vì container ghi bằng UID của chính nó, và user `keenrig` không đọc
# được mọi thư mục con. Không có script này thì con số hiện lên UI là con số
# THIẾU — và thiếu một cách im lặng, vì `du` bỏ qua thứ nó không đọc được và
# vẫn trả về 0 exit code.

set -eu -o pipefail

readonly BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
readonly APPSDATA="${BASE}/apps"

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

# Cùng lý do với appdata.sh: KEENRIG_BASE do phía gọi đặt qua env_keep.
if [[ "${BASE}" != /* || "${BASE}" == "/" ]]; then
    echo "REFUSED: KEENRIG_BASE must be an absolute path and not '/': ${BASE}" >&2
    exit 3
fi

if [[ $# -ge 1 && "$1" == "--check" ]]; then
    echo "OK"
    exit 0
fi

if [[ $# -ne 1 ]]; then
    echo "usage: du.sh <app-id>" >&2
    exit 2
fi

if [[ ! "$1" =~ ^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$ ]]; then
    echo "invalid app-id: $1" >&2
    exit 2
fi

readonly TARGET="${APPSDATA}/$1"
[[ -d "${TARGET}" ]] || { echo "0"; exit 0; }

# -s tổng, -B1 theo BYTE, -x KHÔNG vượt filesystem.
#
# -x quan trọng: nếu người dùng mount một volume mạng vào trong thư mục app thì
# đếm cả nó là báo sai dung lượng ĐĨA của máy — con số dùng để quyết định có
# còn chỗ hay không.
du -sxB1 "${TARGET}" | cut -f1
