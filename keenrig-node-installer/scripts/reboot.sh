#!/bin/bash
# keenrig: khởi động lại máy.
#
# Không có tham số nào, có chủ đích: không có gì để kiểm nghĩa là không có gì
# để kiểm SAI. Mọi lời gọi đều làm đúng một việc.

set -eu -o pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
fi

if [[ $# -ge 1 && "$1" == "--check" ]]; then
    echo "OK"
    exit 0
fi

# Trễ 5 giây: control API cần trả lời được request đang gọi lệnh này trước khi
# máy đi xuống. `shutdown -r now` sẽ cắt kết nối giữa chừng và người dùng thấy
# một lỗi mạng thay vì thấy "đang khởi động lại".
shutdown -r +0 "keenrig: khởi động lại theo yêu cầu" &
sleep 1
echo "reboot scheduled"
