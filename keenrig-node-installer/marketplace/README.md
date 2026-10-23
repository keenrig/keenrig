# Marketplace 1-click — Vultr, DigitalOcean, Akamai/Linode

Mục tiêu: người không rành kỹ thuật bấm một nút lúc tạo máy, không phải chạy `curl | sudo sh`.

| Tệp | Là gì |
|---|---|
| [`keenrig.pkr.hcl`](keenrig.pkr.hcl) | Packer: dựng snapshot cho **Vultr** và **DigitalOcean** |
| [`cleanup.sh`](cleanup.sh) | Dọn máy dựng trước khi chụp — xoá mọi thứ thuộc về MỘT máy |
| [`../scripts/firstboot.sh`](../scripts/firstboot.sh) | Chạy ở lần boot đầu của máy khách: chờ box, ghi địa chỉ + token, lời chào khi đăng nhập, một ping nguồn cài |
| [`linode-stackscript.sh`](linode-stackscript.sh) | StackScript cho **Linode** — chạy `get.sh` lúc tạo máy, không có snapshot |

## Luật số một: image không được mang danh tính

Image marketplace được nhân bản công khai. Còn sót `instance/master.key` trong snapshot thì **mọi máy khách
dùng chung một khoá** bọc secret. `cleanup.sh` xoá `instance/`, SSH host key, `machine-id`, `authorized_keys`,
log; `keenrig-box`, systemd và cloud-init sinh lại ở máy khách. `cleanup.sh` từ chối chạy nếu máy có
container — image chỉ dựng từ bản cài sạch.

**Kiểm tra bắt buộc mỗi lần dựng (T6):** tạo HAI máy từ cùng snapshot, rồi trên mỗi máy:

```sh
sha256sum /var/lib/keenrig/instance/master.key   # hai máy phải KHÁC nhau
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub  # khác nhau
cat /root/keenrig-setup.txt                       # có địa chỉ, có token, token khác nhau
curl -s http://127.0.0.1:8080/api/v1/auth/setup   # {"needs_setup":true}
```

Mở `http://<IP>/` → tạo chủ → cài một app → app Running. Chỉ khi cả hai máy qua hết mới nộp.

## Dựng image

```sh
cd keenrig-node-installer/marketplace
packer init .
VULTR_API_KEY=... DIGITALOCEAN_TOKEN=... packer build -var version=0.4.0 .
packer build -only='vultr.keenrig' -var version=0.4.0 .   # một nơi
```

Trước khi dựng: bản phát hành phải có sẵn ở `get.keenrig.com/dl/stable/` —
Packer cài từ kênh, không cài từ máy mình. Dựng lại mỗi bản lớn.

## Nộp từng nơi

| Nơi | Bước | Ghi chú |
|---|---|---|
| **Vultr** | Portal → Marketplace → Get Started → đồng ý Publisher Agreement → Vendor Settings → tạo app từ snapshot | Tự phục vụ. Tài liệu: docs.vultr.com/platform/marketplace-vendor |
| **DigitalOcean** | Vendor Portal (marketplace.digitalocean.com/vendors) → nộp snapshot đã qua `99-img_check.sh` | Có duyệt. Packer đã chạy `90-cleanup.sh` + `99-img_check.sh` — img_check không được có FAIL |
| **Linode** | Điền form "Register Your App" → đội Linode liên hệ → nộp StackScript lên GitHub | Họ có thể yêu cầu bọc lại theo layout Ansible của repo marketplace-apps |
| Hetzner | — | Hiện không nhận app mới (hetznercloud/apps) |

**Hồ sơ niêm yết** — viết theo nhu cầu, không theo kỹ thuật; ghi đúng giấy phép: Keenrig là **freemium**
(Starter miễn phí: 1 máy · 3 app · 3 domain), **các app nó cài** là mã nguồn mở. Không ghi Keenrig là open source.
Cấu hình khuyên dùng: Ubuntu 24.04, ≥ 2 GB RAM. Hỗ trợ: `hello@keenrig.com` (phải nhận thư được trước khi nộp).

## Đo

Mỗi máy marketplace gửi đúng một `GET https://get.keenrig.com/ping?src=<vultr|digitalocean|linode>&v=<version>`
ở lần boot đầu (công bố ở keenrig.com/privacy; bỏ qua bằng tệp `/etc/keenrig/no-ping`). nginx ghi riêng vào
`/var/log/nginx/keenrig-ping.log`:

```sh
awk -F'src=' '/GET \/ping/ {split($2,a,/[& ]/); n[a[1]]++} END {for (s in n) print s, n[s]}' /var/log/nginx/keenrig-ping.log
```

## Chưa giải quyết — chặn trước khi nộp

`POST /api/v1/auth/setup` (tạo chủ) **không đòi setup token**: khi chưa có chủ, ai mở `http://<IP>/` trước thì
chiếm máy. Với image marketplace, máy lên mạng công khai ngay khi boot, và máy quét IP tìm tới trong vài phút.
`firstboot.sh` chỉ cảnh báo người dùng tạo chủ ngay — đó không phải bản sửa. Xem
`PLAN-campaign-additions.md` mục C6.2.
