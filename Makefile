PKGS := ./keenrig-catalog/... ./keenrig-contracts/... ./keenrig-node/...

.PHONY: build build-oss test test-short lint ui

build:
	go build $(PKGS)

# Binary chỉ gồm mã AGPL — không có keenrig-node/proprietary/.
build-oss:
	go build -tags oss $(PKGS)

test:
	go test $(PKGS)

test-short:
	go test -short $(PKGS)

lint:
	go vet $(PKGS)

# Chạy TRƯỚC `make build` trên checkout sạch: Admin UI được nhúng vào keenrig-box.
ui:
	cd keenrig-node/ui && npm ci && npm run build
