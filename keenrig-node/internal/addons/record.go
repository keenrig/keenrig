package addons

// Bản ghi cấp phát, và việc buộc nó vào `addon.schema.json` (AD-03).
//
// # Vì sao cần thêm một kiểu nữa cạnh Creds
//
// `Creds` là thứ driver TRẢ VỀ; `Record` là thứ hợp đồng NÓI TỚI. Hai cái khác
// nhau ở chỗ Record biết nó thuộc app nào và addon nào — driver không cần biết
// để làm việc của nó, nhưng schema thì bắt buộc phải có (`required: app_id,
// addon, env`), vì một bộ biến không gắn với app là thứ không kiểm chứng được.
//
// # Vì sao validate ở đây chứ không chỉ trong test
//
// `ValidateEnv` kiểm được tên biến, nhưng không kiểm được ba điều mà schema
// kiểm:
//
//   - `addon` phải nằm trong enum. Một driver thứ ba tự Register kind "mysql" mà
//     quên cập nhật schema sẽ chạy được cho tới lúc ai đó cố validate — và lúc
//     đó thứ hỏng là bản ghi đã nằm trong DB, không phải bản vừa sinh ra.
//   - `additionalProperties: false`. Đây là điều đáng giá nhất: thêm một trường
//     `password` vào bản ghi này là cách rò rỉ credential dễ xảy ra nhất, và
//     schema từ chối nó thay vì tin người viết sẽ nhớ.
//   - `secret_ref` khi có mặt phải KHÁC RỖNG. Một secret_ref rỗng là con trỏ
//     null được ghi như thể nó trỏ tới đâu đó.
//
// Giá phải trả: một lần marshal + validate cho mỗi lần cấp phát. Ở nhịp 1 giây
// với 50 app đó là 50 lần marshal một map bốn phần tử mỗi giây — không đáng để
// đánh đổi bằng việc tin driver.
//
// # Vì sao provisioned_at KHÔNG được điền ở đây
//
// Nó là `format: date-time`, và một mốc thời gian sinh ra lúc validate là mốc
// của lần cấp phát GẦN NHẤT, không phải lần đầu. Setup idempotent nên nó chạy
// lại mỗi tick; ghi mốc mới mỗi tick nghĩa là cột đó nói "vừa cấp phát" mãi mãi
// và không ai truy được bao giờ DB này thực sự được tạo. Ai cần mốc thật thì lấy
// từ `app_addons.created_at`.

import (
	"encoding/json"
	"fmt"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// Record — bản ghi cấp phát addon cho MỘT app. Khớp addon.schema.json.
//
// Không có trường nào cho mật khẩu, và đó là chủ đích: phần nhạy cảm nằm trong
// bảng `secrets`, ở đây chỉ có khoá tra cứu. `additionalProperties: false` của
// schema biến điều đó thành một khẳng định kiểm được thay vì một quy ước.
type Record struct {
	AppID     string            `json:"app_id"`
	Addon     Kind              `json:"addon"`
	Env       map[string]string `json:"env"`
	SecretRef string            `json:"secret_ref,omitempty"`
}

// Record dựng bản ghi từ credential driver trả về.
func (c Creds) Record(kind Kind, appID string) Record {
	return Record{AppID: appID, Addon: kind, Env: c.Env, SecretRef: c.SecretRef}
}

// Validate kiểm bản ghi khớp addon.schema.json (AD-03).
//
// Đi qua JSON thật chứ không kiểm trên struct: schema nói về hình dạng dữ liệu
// TRÊN ĐƯỜNG TRUYỀN, và một struct Go hợp lệ vẫn có thể marshal ra thứ schema từ
// chối — `Env` nil ra `null` thay vì `{}` là ví dụ gần nhất.
func (r Record) Validate() error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("addons: building record %s/%s: %w", r.Addon, r.AppID, err)
	}
	if err := contracts.ValidateAddonConfig(raw); err != nil {
		return fmt.Errorf("addons: record %s/%s does not match addon.schema.json: %w",
			r.Addon, r.AppID, err)
	}
	return nil
}
