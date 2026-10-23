#!/bin/bash
# keenrig: vòng đời thư mục dữ liệu của một app — tạo, đổi chủ, XOÁ.
#
# # Vì sao script này nguy hiểm nhất trong bộ, và nó tự chặn thế nào
#
# Nó chạy `rm -rf`. Một tham số không được kiểm ở đây là `rm -rf /`.
#
# Ba lớp chặn, và cả ba đều cần thiết vì mỗi lớp bịt một cách vượt khác nhau:
#
#  1. appID phải khớp [a-z0-9-]{2,40}. Chặn "..", "/", ký tự shell.
#  2. Đường dẫn được DỰNG từ base cố định + appID, không bao giờ nhận nguyên
#     một đường dẫn từ tầng gọi. Tầng gọi không có cách nào nói "hãy xoá /etc".
#  3. Sau khi dựng, đường dẫn được PHÂN GIẢI THẬT (realpath) và phải vẫn nằm
#     trong apps. Lớp này bắt trường hợp appID hợp lệ nhưng thư mục là một
#     symlink trỏ ra ngoài — thứ mà lớp 1 và 2 không nhìn thấy.
#
# Lớp 3 là lớp người ta hay bỏ: hai lớp đầu kiểm CHUỖI, chỉ lớp thứ ba kiểm
# thứ thật sự nằm trên đĩa.

set -eu -o pipefail

readonly BASE="${KEENRIG_BASE:-/var/lib/keenrig}"
readonly KEENRIG_USER="${KEENRIG_USER:-keenrig}"
readonly APPSDATA="${BASE}/apps"

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

# Lớp 0 — kiểm chính KEENRIG_BASE.
#
# Biến này đến từ `env_keep` trong sudoers, nghĩa là PHÍA GỌI đặt được nó. Nếu
# box bị chiếm thì kẻ tấn công chọn được thư mục gốc, và mọi lớp kiểm bên dưới
# đều tính toán từ một gốc do họ đặt.
#
# Thiệt hại vẫn bị chặn ở `<base>/apps/<id-hợp-lệ>` nên nó không phải là
# `rm -rf /`. Nhưng "không phải thảm hoạ" chưa phải lý do để bỏ qua: một base
# tương đối hay `/` là dấu hiệu có gì đó rất sai, và dừng lại rẻ hơn nhiều so
# với việc đoán xem lần này có hại hay không.
if [[ "${BASE}" != /* || "${BASE}" == "/" ]]; then
    echo "REFUSED: KEENRIG_BASE must be an absolute path and not '/': ${BASE}" >&2
    exit 3
fi

if [[ $# -ge 1 && "$1" == "--check" ]]; then
    echo "OK"
    exit 0
fi

if [[ $# -lt 2 ]]; then
    echo "usage: appdata.sh <create|remove|chown|chown-volume> <app-id> [volume] [uid:gid]" >&2
    exit 2
fi

readonly ACTION="$1"
readonly APP_ID="$2"

# Lớp 1 — hình dạng appID. Cùng luật với apps.NormalizeSlug ở tầng Go; trùng
# lặp có chủ đích, vì script này phải đứng vững kể cả khi bị gọi từ chỗ khác.
if [[ ! "${APP_ID}" =~ ^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$ ]]; then
    echo "invalid app-id: ${APP_ID}" >&2
    exit 2
fi

# Lớp 2 — đường dẫn do TA dựng.
readonly TARGET="${APPSDATA}/${APP_ID}"

# Lớp 3 — phân giải thật rồi kiểm lại. Chỉ áp cho thư mục đã tồn tại; với
# `create` thì chưa có gì để phân giải.
assert_inside_apps() {
    local real_base real_target
    real_base="$(realpath -m "${APPSDATA}")"
    real_target="$(realpath -m "$1")"
    if [[ "${real_target}" != "${real_base}/"* ]]; then
        echo "REFUSED: ${1} resolves to ${real_target}, which is OUTSIDE ${real_base}" >&2
        exit 3
    fi
}

case "${ACTION}" in
create)
    assert_inside_apps "${TARGET}"
    mkdir -p "${TARGET}"
    # 0750 chứ không 0755: dữ liệu app không có lý do gì để mọi user trên máy
    # đọc được. Container truy cập qua bind mount, không qua quyền "others".
    chmod 0750 "${TARGET}"
    chown "${KEENRIG_USER}:${KEENRIG_USER}" "${TARGET}"
    echo "${TARGET}"
    ;;
chown)
    if [[ $# -ne 3 ]]; then
        echo "usage: appdata.sh chown <app-id> <uid:gid>" >&2
        exit 2
    fi
    # uid:gid phải là SỐ. Cho phép tên là mở đường cho "root" và cho cả những
    # tên chứa ký tự lạ mà chown diễn giải khác ta nghĩ.
    if [[ ! "$3" =~ ^[0-9]+:[0-9]+$ ]]; then
        echo "uid:gid must be numeric, got: $3" >&2
        exit 2
    fi
    [[ -d "${TARGET}" ]] || { echo "no such directory: ${TARGET}" >&2; exit 1; }
    assert_inside_apps "${TARGET}"
    # KHÔNG dùng -R với --dereference mặc định: một symlink bên trong trỏ ra
    # /etc sẽ làm chown đổi chủ file hệ thống. -h giữ nguyên symlink.
    chown -Rh "$3" "${TARGET}"
    ;;
chown-volume)
    # Đổi chủ ĐÚNG MỘT thư mục volume `apps/<id>/volumes/<name>` — không đệ
    # quy, không đụng apps/<id> hay volumes/. Box (user keenrig, không có
    # CAP_CHOWN) gọi cái này khi image chạy bằng user thường (n8n: uid 1000):
    # os.Chown từ box bị EPERM. `chown` ở trên đổi cả cây apps/<id>, nên sau
    # đó box không mkdir thêm volume nào được nữa — vì vậy có action riêng.
    if [[ $# -ne 4 ]]; then
        echo "usage: appdata.sh chown-volume <app-id> <volume> <uid:gid>" >&2
        exit 2
    fi
    readonly VOLUME="$3"
    # Cùng luật với VolumeMount.Name ở keenrig-contracts: [a-z0-9-], không
    # bắt đầu/kết thúc bằng '-'. Chặn "..", "/", ký tự shell.
    if [[ ! "${VOLUME}" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]]; then
        echo "invalid volume name: ${VOLUME}" >&2
        exit 2
    fi
    if [[ ! "$4" =~ ^[0-9]+:[0-9]+$ ]]; then
        echo "uid:gid must be numeric, got: $4" >&2
        exit 2
    fi
    readonly VOLDIR="${TARGET}/volumes/${VOLUME}"
    # -L: symlink không được tính là thư mục volume — chown -h lên nó vô hại
    # nhưng nó là dấu hiệu có ai đã sắp đặt lại cây thư mục.
    [[ -d "${VOLDIR}" && ! -L "${VOLDIR}" ]] || { echo "no such volume directory: ${VOLDIR}" >&2; exit 1; }
    assert_inside_apps "${VOLDIR}"
    # Chỉ thư mục RỖNG — cùng luật với volumeowner.go: thư mục đã có dữ liệu
    # thì quyền của nó là thứ app hoặc người vận hành đã sắp đặt.
    if [[ -n "$(ls -A "${VOLDIR}")" ]]; then
        echo "volume directory is not empty, leaving its owner alone: ${VOLDIR}" >&2
        exit 0
    fi
    chown -h "$4" "${VOLDIR}"
    ;;
remove)
    # Không có thì coi như đã xong — xoá hai lần không phải lỗi, và reconciler
    # gọi lại sau mỗi lần restart giữa chừng.
    [[ -d "${TARGET}" ]] || exit 0
    assert_inside_apps "${TARGET}"
    # --one-file-system: nếu ai đó mount một filesystem khác vào trong thư mục
    # app (volume NFS chẳng hạn), rm sẽ DỪNG ở ranh giới đó thay vì xoá sạch
    # nội dung của volume đó.
    rm -rf --one-file-system "${TARGET}"
    ;;
*)
    echo "invalid action: ${ACTION}" >&2
    exit 2
    ;;
esac
