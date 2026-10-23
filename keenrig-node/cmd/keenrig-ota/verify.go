package main

// `keenrig-ota verify` — cổng UP-01, tách thành một lệnh riêng có chủ đích.
//
// Lệnh này chạy được ĐỘC LẬP với luồng cập nhật: người vận hành nghi một bản
// tải về bị sửa thì kiểm được ngay, không phải khởi động cả quá trình update
// để biết. Và CI của bên phát hành gọi được chính đoạn mã mà instance sẽ chạy —
// nếu bên phát hành ký sai, họ phát hiện trước khi người dùng phát hiện.

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/keenrig/keenrig/keenrig-node/internal/release"
)

func verifyCmd() *cobra.Command {
	var (
		manifestPath string
		sigPath      string
		artifactPath string
		currentVer   string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the signature of a release (UP-01) — installs NOTHING",
		Long: "Checks the Ed25519 signature of the manifest, then (with --artifact) checks\n" +
			"the size and sha256 of the binary. Does not touch bin/, does not call the box.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(manifestPath, sigPath, artifactPath, currentVer)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "path to manifest.json (required)")
	cmd.Flags().StringVar(&sigPath, "signature", "", "path to manifest.json.sig (default: <manifest>.sig)")
	cmd.Flags().StringVar(&artifactPath, "artifact", "", "binary to checksum (optional)")
	cmd.Flags().StringVar(&currentVer, "current", version, "currently running version, used to check min_upgradable_from")
	_ = cmd.MarkFlagRequired("manifest")
	return cmd
}

func runVerify(manifestPath, sigPath, artifactPath, currentVer string) error {
	if sigPath == "" {
		sigPath = manifestPath + ".sig"
	}

	// Đọc NGUYÊN VĂN. Không parse, không chuẩn hoá — chữ ký phủ đúng dãy byte
	// này, và mọi bước biến đổi ở giữa là một khe hở giữa "cái được ký" và
	// "cái được kiểm".
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading the manifest: %w", err)
	}
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("reading the signature: %w (a signature is REQUIRED, not optional)", err)
	}

	ring, err := keyring()
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	if len(ring) == 0 {
		// Nói thẳng vì sao từ chối: không có khoá nào được nhúng lúc build.
		// Im lặng trả "chữ ký sai" ở đây sẽ khiến người vận hành đi tìm kẻ tấn
		// công trong khi vấn đề nằm ở quy trình dựng bản phát hành.
		return errors.New("this binary was built with NO release key — " +
			"there is nothing to trust, so every release is rejected (rebuild with -ldflags -X main.releaseKeyB64=…)")
	}

	m, err := release.Verify(manifestBytes, string(sigBytes), ring)
	if err != nil {
		return fmt.Errorf("REJECTED: %w", err)
	}
	fmt.Printf("signature VALID — %s %s (key_id=%s)\n", m.Channel, m.Version, m.KeyID)

	if err := m.CheckUpgradePath(currentVer); err != nil {
		return fmt.Errorf("REJECTED: %w", err)
	}

	a, err := m.ArtifactFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("REJECTED: %w", err)
	}
	fmt.Printf("artifact %s/%s: %s (%d byte)\n", a.OS, a.Arch, a.URL, a.Size)

	if artifactPath == "" {
		fmt.Println("skipping the checksum check (--artifact not given)")
		return nil
	}
	f, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("opening the artifact: %w", err)
	}
	defer f.Close()
	// w = nil: chỉ kiểm, không ghi đi đâu cả. Lệnh này KHÔNG cài gì.
	if err := release.VerifyArtifact(f, a, nil); err != nil {
		return fmt.Errorf("REJECTED: %w", err)
	}
	fmt.Println("artifact checksum MATCHES — the release is trustworthy")
	return nil
}
