# Hạ tầng mạng thử nghiệm & Dữ liệu mẫu (`feature/lab-fixtures`)

Phần bàn giao của **Trần Trung Nghĩa** gồm 2 nhóm tài nguyên độc lập:

## 1. Bộ dữ liệu xác thực tổng hợp có nhãn (`fixtures/`)
- `fixtures/single_source.jsonl`: Ca một nguồn (1 IP thử 6 lần liên tiếp) -> kích hoạt bộ đếm ngưỡng IP/tài khoản, không kích hoạt đồ thị.
- `fixtures/distributed_spray.jsonl`: Ca nhiều nguồn trùng mục tiêu (7 IP rải vào 7 tài khoản, mỗi IP 3 lần, mỗi tài khoản 3 lần) -> bộ đếm đơn lẻ bỏ sót, đồ thị phát hiện 1 chiến dịch.
- `fixtures/control_disjoint.jsonl`: Ca đối chứng ít trùng mục tiêu (cùng tổng số 21 sự kiện, cùng phân bố 3 lần/IP và 3 lần/tài khoản, nhưng không tạo cụm liên thông) -> đồ thị không báo nhầm.
- `fixtures/expected_outcomes.json`: Kết quả kỳ vọng cho từng kịch bản.

Phát lại cả 3 bộ log qua `SprayDetector`:

```powershell
python -B -m fixtures.loader
```

## 2. Dựng nhiều IP nguồn thật trên Windows Host-only (`lab_net/`)
Chạy PowerShell với quyền **Administrator** khi kết nối Windows sang Kali VM (`server.py --host 0.0.0.0 --port 8000`):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\lab_net\setup_ips.ps1
```

Dọn dẹp sau khi test/demo:

```powershell
.\lab_net\cleanup_ips.ps1
```
