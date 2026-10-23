package resources

// Năng lực THEO THIẾT KẾ của từng runtime — trần trên, biết được mà không cần
// nói chuyện với nền tảng.
//
// # Vì sao cần bảng tĩnh khi driver đã tự dò được
//
// Vì admission chạy ở tiến trình có thể CHƯA mở được driver. `keenrig-box` mở
// driver runtime bên trong goroutine được supervise, có chủ đích: dockerd chưa
// lên chỉ làm supervisor retry, /healthz vẫn 200. Nhưng `apps.Create` phải trả
// lời ngay lúc người dùng bấm nút. Bảng này là câu trả lời không cần mạng:
// `KEENRIG_RUNTIME=k8s` thì `io_write_mbps` là KHÔNG BAO GIỜ được, và biết điều
// đó không cần chạm tới cluster nào.
//
// # Vì sao bảng này KHÔNG phải câu trả lời cuối cùng
//
// Nó là trần trên, không phải sự thật của host. `docker` có `disk_quota` trong
// bảng vì Docker CÓ cơ chế đó — nhưng chỉ trên overlay2/xfs+pquota, btrfs, zfs.
// Trên snapshotter overlayfs (Docker Desktop) cờ được nhận và không có tác dụng.
// Vì vậy driver còn dò host trong `ResourceCaps`, và Apply từ chối to tiếng khi
// đo được là không áp nổi. Bảng tĩnh chặn sai-thiết-kế; dò host chặn sai-máy.

// ByDriver trả năng lực theo thiết kế của một tên driver runtime.
//
// Tên lạ → nil, nghĩa là "chưa biết" chứ không phải "không có gì": nil làm
// MissingCaps trả rỗng, tức là bỏ qua admission chứ không từ chối mọi app. Một
// driver thứ tư được thêm mà quên khai ở đây không được biến thành "không tạo
// được app nào" — nó được canh bởi test đối chiếu bảng này với `runtime.Registered()`.
func ByDriver(name string) Caps {
	switch name {
	case "docker":
		// Docker Engine một máy: đỡ đủ, vì HostConfig có chỗ cho tất cả.
		// disk_quota là thứ DUY NHẤT còn phụ thuộc host (storage driver).
		return Caps{
			CapMemory: true, CapMemorySwap: true,
			CapCPUQuota: true, CapCPUShares: true,
			CapPids: true, CapDiskQuota: true,
			CapIOBps: true, CapIOIOPS: true,
			CapUlimits: true, CapShmSize: true, CapReplicas: true,
		}
	case "swarm":
		// swarm.Limit chỉ có NanoCPUs/MemoryBytes/Pids; SwapBytes nằm ở
		// ResourceRequirements; Ulimits nằm ở ContainerSpec. KHÔNG có chỗ nào
		// khai cpu shares, blkio, storage quota hay shm — `docker service
		// create` cũng không có cờ tương ứng. Bốn thứ đó vắng mặt ở đây vì API
		// không có chỗ, không phải vì chưa ai viết code.
		return Caps{
			CapMemory: true, CapMemorySwap: true,
			CapCPUQuota: true, CapPids: true,
			CapUlimits: true, CapReplicas: true,
		}
	case "k8s":
		// Pod chỉ khai được limits memory/cpu/ephemeral-storage.
		//
		// Bốn thứ vắng mặt, mỗi thứ một lý do khác nhau — và không lý do nào là
		// "chưa làm":
		//   - cpu_shares: k8s có `requests.cpu` và nó THÀNH cpu.weight, nhưng
		//     requests còn quyết định xếp pod và hạng QoS. Map cpu_shares vào đó
		//     là lặng lẽ đổi luôn cả hai thứ kia.
		//   - pids: podPidsLimit là cấu hình của KUBELET, cùng một giá trị cho
		//     mọi pod trên node. Không có đường khai theo app.
		//   - io_bps/io_iops: không có trong resource model.
		//   - ulimits/shm_size: cần securityContext/sysctl hoặc mẹo emptyDir
		//     medium=Memory — cả hai đều không phải hạn mức của container.
		return Caps{
			CapMemory: true, CapCPUQuota: true,
			CapDiskQuota: true, CapReplicas: true,
		}
	}
	return nil
}
