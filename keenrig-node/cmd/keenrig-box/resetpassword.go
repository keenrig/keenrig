package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// defaultInstallBase — nơi get.sh cài box (xem systemd/keenrig-box.service).
const defaultInstallBase = "/var/lib/keenrig"

// `keenrig-box reset-password` — đường cứu hộ khi chủ instance quên mật khẩu.
//
// Chạy trên chính máy, bằng user đọc được instance/ (0700, tức là root): đó
// là toàn bộ cơ chế xác thực của lệnh này. Không có bản HTTP — một "quên mật
// khẩu" qua mạng cần email, và box không có kênh gửi mail đáng tin.
//
// Chạy được khi box ĐANG chạy: store mở WAL + busy_timeout như `backup`, và
// identity đọc user từ DB mỗi lần đăng nhập nên không cần restart.
func newResetPasswordCmd(dataDir *string) *cobra.Command {
	var (
		user        string
		password    string
		disableTOTP bool
	)
	cmd := &cobra.Command{
		Use:   "reset-password",
		Short: "Set a new password for a user without the old one (run as root on the box)",
		Long: "Sets a new password, re-enables the account, clears login lockouts and revokes " +
			"every session of that user. Without --password a random one is generated and printed once.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := *dataDir
			// Người chạy lệnh này đang bối rối sẵn rồi: mặc định ./data của các
			// lệnh khác sẽ chỉ cho họ thêm một lỗi. Không đặt --data → dùng chỗ
			// cài thật (cùng biến KEENRIG_BASE mà unit systemd đặt).
			if !cmd.Flags().Changed("data") {
				dir = defaultInstallBase
				if env := os.Getenv("KEENRIG_BASE"); env != "" {
					dir = env
				}
			}
			return runResetPassword(cmd.Context(), dir, user, password, disableTOTP)
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "username to reset (case-insensitive)")
	cmd.Flags().StringVar(&password, "password", "",
		"new password, at least 12 characters (default: generate one — avoids leaving it in shell history)")
	cmd.Flags().BoolVar(&disableTOTP, "disable-2fa", false, "also turn off TOTP 2FA (lost authenticator device)")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func runResetPassword(ctx context.Context, dataDir, user, password string, disableTOTP bool) error {
	layout := paths.New(dataDir)
	// Như `backup`: KHÔNG để store.Open tạo một platform.db rỗng khi --data sai.
	if _, err := os.Stat(layout.DB()); err != nil {
		return fmt.Errorf("no instance database at %s — check --data, and run as root", layout.DB())
	}
	st, err := store.Open(layout.DB(), layout.MasterKey())
	if err != nil {
		return fmt.Errorf("opening the instance database: %w", err)
	}
	defer st.Close()

	generated := password == ""
	if generated {
		password = rand.Text() // 26 ký tự base32, 130 bit
	}

	u, err := identity.New(st, identity.Options{}).ResetPassword(ctx, user, password, disableTOTP)
	if errors.Is(err, store.ErrNotFound) {
		if owner, oerr := st.OwnerUser(ctx); oerr == nil {
			return fmt.Errorf("no user %q on this instance (the owner is %q)", user, owner.Username)
		}
		return fmt.Errorf("no user %q on this instance", user)
	}
	if err != nil {
		return err
	}

	fmt.Printf("Password for %q has been reset. All of its sessions were signed out.\n", u.Username)
	if generated {
		fmt.Printf("New password (shown only once): %s\n", password)
	}
	if disableTOTP {
		fmt.Println("2FA is now off — turn it back on from the Admin UI after you sign in.")
	}
	return nil
}
