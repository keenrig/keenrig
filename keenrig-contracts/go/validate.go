package contracts

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	schemafs "github.com/keenrig/keenrig/keenrig-contracts/jsonschema"
	jsv "github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaBase = "https://keenrig.com/schemas/"

type compiledSchemas struct {
	desired      *jsv.Schema
	syncRequest  *jsv.Schema
	syncResponse *jsv.Schema
	manifest     *jsv.Schema
	license      *jsv.Schema
	addonConfig  *jsv.Schema
	infra        *jsv.Schema
}

var getSchemas = sync.OnceValues(func() (*compiledSchemas, error) {
	c := jsv.NewCompiler()
	c.AssertFormat()
	for _, name := range []string{
		"desired.schema.json",
		"sync.schema.json",
		"manifest.schema.json",
		"license.schema.json",
		"addon.schema.json",
		"infra.schema.json",
	} {
		raw, err := schemafs.FS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("contracts: read %s: %w", name, err)
		}
		// jsonschema v6: phải UnmarshalJSON trước rồi mới AddResource.
		doc, err := jsv.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("contracts: parse %s: %w", name, err)
		}
		if err := c.AddResource(schemaBase+name, doc); err != nil {
			return nil, fmt.Errorf("contracts: add %s: %w", name, err)
		}
	}

	var (
		cs  compiledSchemas
		err error
	)
	if cs.desired, err = c.Compile(schemaBase + "desired.schema.json"); err != nil {
		return nil, err
	}
	if cs.syncRequest, err = c.Compile(schemaBase + "sync.schema.json#/$defs/SyncRequest"); err != nil {
		return nil, err
	}
	if cs.syncResponse, err = c.Compile(schemaBase + "sync.schema.json#/$defs/SyncResponse"); err != nil {
		return nil, err
	}
	if cs.manifest, err = c.Compile(schemaBase + "manifest.schema.json"); err != nil {
		return nil, err
	}
	if cs.license, err = c.Compile(schemaBase + "license.schema.json"); err != nil {
		return nil, err
	}
	if cs.addonConfig, err = c.Compile(schemaBase + "addon.schema.json"); err != nil {
		return nil, err
	}
	if cs.infra, err = c.Compile(schemaBase + "infra.schema.json"); err != nil {
		return nil, err
	}
	return &cs, nil
})

func validateWith(pick func(*compiledSchemas) *jsv.Schema, data []byte) error {
	cs, err := getSchemas()
	if err != nil {
		return err
	}
	inst, err := jsv.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return pick(cs).Validate(inst)
}

func ValidateDesired(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.desired }, data)
}

func ValidateSyncRequest(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.syncRequest }, data)
}

func ValidateSyncResponse(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.syncResponse }, data)
}

func ValidateManifest(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.manifest }, data)
}

func ValidateLicense(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.license }, data)
}

// ValidateAddonConfig kiểm bản ghi credential addon cấp cho một app — đặc biệt
// là namespace biến môi trường KEENRIG_*, thứ image app phụ thuộc vào.
func ValidateAddonConfig(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.addonConfig }, data)
}

// ValidateInfra kiểm file pin digest image hạ tầng (node/INFRA_VERSION).
func ValidateInfra(data []byte) error {
	return validateWith(func(cs *compiledSchemas) *jsv.Schema { return cs.infra }, data)
}

// --- luật cho volumes mà JSON Schema không diễn đạt được -----------------------

// ErrBadVolume — khai báo volume vi phạm luật.
var ErrBadVolume = errors.New("contracts: invalid volume declaration")

// Đường dẫn trong container mà mount đè lên sẽ làm container hỏng theo cách khó
// hiểu. Không phải lỗ hổng máy chủ — phía máy chủ luôn nằm dưới
// `apps/<id>/volumes/` — nhưng một app xin mount lên `/proc` là một app cấu
// hình sai, và nói ra lúc tạo rẻ hơn nhiều so với để nó khởi động rồi chết.
var forbiddenMountPaths = []string{"/", "/proc", "/sys", "/dev"}

// ValidateVolumes ép ba luật mà schema không nói được:
//
//	trùng Name    hai volume cùng tên → cùng MỘT thư mục máy chủ, và app thấy
//	              cùng dữ liệu ở hai nơi mà không hiểu vì sao
//	trùng Path    Docker nhận cả hai rồi cái sau che cái trước — dữ liệu ghi vào
//	              volume bị che nằm lại trên đĩa mà không ai đọc được nữa
//	Path nguy hiểm  xem forbiddenMountPaths
//
// Luật về HÌNH DẠNG của Name (chỉ [a-z0-9-]) nằm ở schema, không lặp lại ở đây.
// Nhưng nó là ranh giới an ninh, nên tầng dựng mount PHẢI kiểm lại lần nữa —
// xem paths.AppVolume.
func ValidateVolumes(vols []VolumeMount) error {
	byName := make(map[string]bool, len(vols))
	byPath := make(map[string]bool, len(vols))
	for i, v := range vols {
		if byName[v.Name] {
			return fmt.Errorf("%w: volume %d: name %q is declared twice", ErrBadVolume, i, v.Name)
		}
		byName[v.Name] = true

		clean := path.Clean(v.Path)
		if !path.IsAbs(clean) {
			return fmt.Errorf("%w: volume %q: path %q is not absolute", ErrBadVolume, v.Name, v.Path)
		}
		if clean != v.Path {
			// `/data/../etc` hợp lệ với schema nhưng nói một đằng làm một nẻo.
			return fmt.Errorf("%w: volume %q: path %q is not in canonical form (did you mean %q?)",
				ErrBadVolume, v.Name, v.Path, clean)
		}
		for _, bad := range forbiddenMountPaths {
			if clean == bad || strings.HasPrefix(clean, bad+"/") {
				return fmt.Errorf("%w: volume %q: mounting over %q breaks the container", ErrBadVolume, v.Name, clean)
			}
		}
		if byPath[clean] {
			return fmt.Errorf("%w: volume %q: path %q is already used by another volume", ErrBadVolume, v.Name, clean)
		}
		byPath[clean] = true
	}
	return nil
}
