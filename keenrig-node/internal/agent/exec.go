package agent

// exec.go — executor mặc định của agent: dịch một lệnh từ cloud thành một lời
// gọi node API trên box.
//
// # Vì sao lệnh không tự chạy được gì
//
// Agent KHÔNG có quyền nào trên app, container hay DB. Mọi tác động lên máy đi
// qua node API của box, nên executor này chỉ là một bảng dịch: kind → endpoint.
// Nhờ vậy "agent bị chiếm" không mạnh hơn "ai đó mở được box.sock".
//
// # Kind chưa hiện thực trả LỖI CÓ TÊN, không im lặng
//
// `CON-14`: một lệnh hỏng phải giữ lý do trên Console. Kind lạ rơi vào default
// bên dưới và người dùng đọc được đúng chữ "chưa hiện thực trên bản này" kèm
// tên kind — thay vì một lệnh đứng ở `delivered` cho tới lúc hết hạn.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

// AdminTicketSink — thứ executor cần để làm xong `mint_admin_token`.
//
// Interface chứ không phải *NodeClient: test kiểm được luật của executor mà
// không phải dựng một box thật, và một transport khác (mTLS ở nấc sau) cắm vào
// đây mà không sửa gì.
type AdminTicketSink interface {
	AcceptAdminTicket(ctx context.Context, hash string, expiresAt time.Time) error
}

// AppInstaller — thứ executor cần để làm xong `app.install` (CON-09).
type AppInstaller interface {
	InstallApp(ctx context.Context, catalogID, slug string, domains []string) error
}

// Exec — executor mặc định. Node/Apps nil → lệnh cần box trả lỗi có tên.
type Exec struct {
	Node AdminTicketSink
	Apps AppInstaller
}

// NewExec dựng executor cho một node client.
//
// Nhận AdminTicketSink để test cũ chỉ cần một vé vẫn dựng được executor; nếu
// thứ truyền vào cũng cài được app (như *NodeClient) thì `app.install` dùng nó.
func NewExec(node AdminTicketSink) *Exec {
	e := &Exec{Node: node}
	if a, ok := node.(AppInstaller); ok {
		e.Apps = a
	}
	return e
}

// Execute — cài agent.Executor.
func (e *Exec) Execute(ctx context.Context, cmd Command) error {
	switch cmd.Kind {
	case contracts.CommandKindMintAdminToken:
		return e.mintAdminToken(ctx, cmd)
	case contracts.CommandKindAppInstall:
		return e.installApp(ctx, cmd)
	default:
		return fmt.Errorf(
			"this version of the agent does not implement command kind %q yet", cmd.Kind)
	}
}

// mintAdminToken giao hash vé cho box (CON-13).
//
// Hạn lấy từ CHÍNH hàng lệnh: `SEC-06` nói vé sống 10 phút, và con số đó là
// `expires_at` trong DB của cloud. Agent không tự đặt một hạn nào — làm thế là
// dựng một sự thật thứ hai, và hai sự thật về hạn của một bí mật thì cái rộng
// hơn luôn thắng.
func (e *Exec) mintAdminToken(ctx context.Context, cmd Command) error {
	if e.Node == nil {
		return errors.New("this agent cannot reach the box node API, so it cannot mint an admin session")
	}
	var p struct {
		TokenHash string `json:"token_hash"`
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		return fmt.Errorf("the payload of this command is not valid JSON: %w", err)
	}
	if p.TokenHash == "" {
		return errors.New("the payload of this command has no token_hash")
	}
	var expires time.Time
	if cmd.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, cmd.ExpiresAt)
		if err != nil {
			return fmt.Errorf("the expiry of this command is not RFC3339: %q", cmd.ExpiresAt)
		}
		expires = t
	}
	return e.Node.AcceptAdminTicket(ctx, p.TokenHash, expires)
}

// installApp giao lệnh cài cho box (CON-09).
//
// Payload do Console dựng (`consoleapi.installApp`): app_id là id trong
// catalog, subdomain là slug của app trên box, fqdn là tên đầy đủ đã ghép ở
// cloud bằng tên miền gốc CỦA CLOUD — box không tự ghép lại, vì tên miền là thứ
// cloud quyết định (luật 2026-09-07).
func (e *Exec) installApp(ctx context.Context, cmd Command) error {
	if e.Apps == nil {
		return errors.New("this agent cannot reach the box node API, so it cannot install apps")
	}
	var p struct {
		AppID     string `json:"app_id"`
		Subdomain string `json:"subdomain"`
		FQDN      string `json:"fqdn"`
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		return fmt.Errorf("the payload of this command is not valid JSON: %w", err)
	}
	if p.AppID == "" {
		return errors.New("the payload of this command has no app_id")
	}
	var domains []string
	if p.FQDN != "" {
		domains = []string{p.FQDN}
	}
	return e.Apps.InstallApp(ctx, p.AppID, p.Subdomain, domains)
}
