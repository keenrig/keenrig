package contracts_test

// OB-06 — `metrics_summary` là HỢP ĐỒNG, không phải bao đựng.
//
// Trước phiên bản này nó là `{"type":"object"}`: nhận mọi thứ, không khoá nào
// được đặt tên, trong khi Console đã vẽ ba ô CPU/RAM/Disk từ những cái tên UI
// tự đoán. Bộ này đo đúng hai mặt của hợp đồng:
//
//  1. Khoá LẠ bị TỪ CHỐI — một khoá không có trong schema là một khoá không có
//     người đọc, và cho nó đi qua nghĩa là lần lệch tên tiếp theo lại im lặng.
//  2. Trường VẮNG là hợp lệ — OB-05(2): "không đo được" phải gửi được, và nó
//     gửi bằng cách KHÔNG gửi trường đó, không phải bằng số 0.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// syncDoc bọc một metrics_summary vào một SyncRequest tối thiểu hợp lệ — bộ
// validate chỉ có cửa vào ở tầng SyncRequest, đúng như trên dây.
func syncDoc(metrics string) []byte {
	return []byte(`{
		"env_id": "e1",
		"version": "0.1.0",
		"heartbeat": {"ts": "2026-08-16T07:00:00Z"},
		"metrics_summary": ` + metrics + `
	}`)
}

func TestMetricsSummarySchema(t *testing.T) {
	cases := []struct {
		name    string
		metrics string
		ok      bool
	}{
		// Đúng hình dạng ba ô S4 của wireframe: CPU 34% · RAM 2150/4096 MB · Disk 18/80 GB.
		{"đủ ba ô S4", `{"cpu_pct": 34, "mem_used_mb": 2150, "mem_total_mb": 4096,
			"disk_used_gb": 18, "disk_total_gb": 80}`, true},
		{"rỗng — chưa đo được gì", `{}`, true},
		{"chỉ một trường — các trường khác VẮNG chứ không 0", `{"cpu_pct": 0}`, true},
		{"backup đi kèm mốc thời gian", `{"last_backup_at": "2026-08-16T03:00:00Z",
			"last_backup_ok": true}`, true},
		{"mạng theo kbps", `{"net_rx_kbps": 12.5, "net_tx_kbps": 3}`, true},

		// Mặt từ chối — mỗi ca là một kiểu nói dối có hình dạng hợp lệ.
		{"khoá lạ (tên UI tự bịa thời chưa có hợp đồng)", `{"cpu": 34}`, false},
		{"khoá lạ ghép cạnh khoá đúng", `{"cpu_pct": 34, "vibe": "ok"}`, false},
		{"cpu quá 100 — ai đó gửi phần nghìn", `{"cpu_pct": 340}`, false},
		{"cpu âm", `{"cpu_pct": -1}`, false},
		{"tổng RAM bằng 0 — mẫu số của thanh %", `{"mem_total_mb": 0}`, false},
		{"tổng disk bằng 0", `{"disk_total_gb": 0}`, false},
		{"đơn vị sai kiểu — chuỗi thay vì số", `{"mem_used_mb": "2.1 GB"}`, false},
		{"last_backup_ok là chuỗi", `{"last_backup_ok": "yes"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := contracts.ValidateSyncRequest(syncDoc(c.metrics))
			if c.ok && err != nil {
				t.Fatalf("muốn hợp lệ, nhận: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("muốn lỗi, nhận hợp lệ")
			}
		})
	}
}

// Type Go và schema phải đọc được CÙNG tài liệu — và chiều nil phải sống sót
// qua marshal.
//
// Nếu một thẻ json lệch tên, `json.Unmarshal` bỏ qua im lặng và ô Console
// tương ứng trống vĩnh viễn dù agent gửi đúng. Nếu một trường thiếu
// `omitempty`, marshal ghi ra `"cpu_pct": null` — schema từ chối `null` cho
// number, và chỗ vỡ là vòng sync của agent thật.
func TestMetricsSummaryRoundTripsThroughGoTypes(t *testing.T) {
	doc := syncDoc(`{"cpu_pct": 34, "mem_used_mb": 2150, "mem_total_mb": 4096,
		"disk_used_gb": 18, "disk_total_gb": 80}`)
	if err := contracts.ValidateSyncRequest(doc); err != nil {
		t.Fatalf("tài liệu mẫu không hợp lệ: %v", err)
	}

	var req contracts.SyncRequest
	if err := json.Unmarshal(doc, &req); err != nil {
		t.Fatal(err)
	}
	m := req.MetricsSummary
	if m == nil {
		t.Fatal("metrics_summary biến mất khi unmarshal — thẻ json lệch khỏi schema")
	}
	switch {
	case m.CPUPct == nil || *m.CPUPct != 34:
		t.Errorf("cpu_pct = %v", m.CPUPct)
	case m.MemUsedMB == nil || *m.MemUsedMB != 2150:
		t.Errorf("mem_used_mb = %v", m.MemUsedMB)
	case m.DiskTotalGB == nil || *m.DiskTotalGB != 80:
		t.Errorf("disk_total_gb = %v", m.DiskTotalGB)
	case m.NetRxKbps != nil:
		t.Error("net_rx_kbps phải nil khi trên dây không có nó")
	}

	// Chiều "không đo được": marshal một summary chỉ có CPU — các trường nil
	// KHÔNG được xuất hiện trên dây, kể cả dưới dạng null.
	cpu := 7.5
	ts, err := time.Parse(time.RFC3339, "2026-08-16T07:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(contracts.SyncRequest{
		EnvID: "e1", Version: "0.1.0",
		Heartbeat:      contracts.Heartbeat{TS: ts},
		MetricsSummary: &contracts.MetricsSummary{CPUPct: &cpu},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "null") {
		t.Fatalf("trường nil bị marshal thành null — thiếu omitempty: %s", raw)
	}
	if err := contracts.ValidateSyncRequest(raw); err != nil {
		t.Fatalf("marshal từ type Go ra tài liệu không hợp lệ: %v", err)
	}
}
