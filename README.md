# IPS phát hiện password spraying phân tán

**Đề tài đăng ký** — Nghiên cứu cơ chế tấn công Brute-Force và xây dựng hệ thống ngăn chặn tự động IPS.

Web và API ghi nhận các sự kiện xác thực về cùng bộ phát hiện. Đồ thị nối IP với tài khoản đăng nhập sai, tìm nhóm IP có mục tiêu trùng nhau và đánh dấu những tài khoản trong cụm. Khi IPS bật và mật khẩu đúng cho tài khoản bị đánh dấu, hệ thống yêu cầu TOTP trước khi cấp phiên. Trang Hồ sơ nội bộ dùng dữ liệu mẫu.

## Chạy bản nền

Cần Python 3.11 trở lên. Chạy các lệnh từ thư mục repo. Dashboard dùng log tổng hợp có nhãn, với IP và thời gian mô phỏng. Kết quả xác thực trong dashboard đến từ cùng logic cấp phiên mà Web/API sử dụng.

```powershell
python -B dashboard.py --port 8080
```

Mở [dashboard](http://127.0.0.1:8080). Chọn **Spray phân tán**, bấm **Phát lại log**, rồi đổi công tắc IPS và phát lại để so sánh. Chọn **Đối chứng ít trùng mục tiêu** để kiểm tra đồ thị trên dữ liệu có cùng tổng số lượt sai theo IP và tài khoản. Ca một IP dùng để kiểm tra các bộ đếm ngưỡng.

Để mở cổng Web/API riêng, dùng PowerShell khác. Thay mật khẩu ví dụ bằng mật khẩu dành riêng cho lab.

```powershell
$env:IPS_LAB_PASSWORD = 'replace-with-a-lab-password'
python -B server.py --ips on
```

Mở [cổng đăng nhập](http://127.0.0.1:8000), dùng tài khoản `user01` và mật khẩu vừa đặt. Có thể dùng `--port` để đổi cổng, hoặc `--host` để lắng nghe trên IP mạng riêng của máy ảo. Trong cấu hình `--ips off`, tầng TOTP theo rủi ro được tắt để làm đối chứng. Khởi động lại giữa các lượt vì phiên và cửa sổ phát hiện nằm trong bộ nhớ.

Để dùng Authenticator cho `user01`, tạo khóa Base32 bằng `python -c "import base64, secrets; print(base64.b32encode(secrets.token_bytes(20)).decode())"`. Đặt `IPS_LAB_TOTP_SECRET` ở terminal chạy máy chủ và nhập cùng khóa vào Authenticator ở chế độ Time-based. Giữ khóa TOTP và mật khẩu trong môi trường cục bộ.

Nếu dùng Docker, đặt các biến môi trường trên cùng terminal trước khi chạy các lệnh sau. Cổng này được mở trên loopback của máy chạy Docker.

```powershell
docker build -t ips-final-project .
docker run --rm -p 127.0.0.1:8000:8000 -e IPS_LAB_PASSWORD -e IPS_LAB_TOTP_SECRET ips-final-project --ips on
```

## Kiểm tra và đo

```powershell
python -B -m unittest discover -s tests -v
python -B benchmark.py
```

Các bài kiểm thử HTTP xác nhận Web/API cùng yêu cầu TOTP, `/profile` trả `401` trước khi có phiên, mã sai bị từ chối và mã đúng mở được hồ sơ. Benchmark xuất JSON cho cùng ba bộ log ở hai chế độ IPS. Bộ đếm IP/tài khoản chỉ cung cấp kết quả đối chiếu. Trường `simulated_alert_ms` đo trên đồng hồ của bộ dữ liệu. Nhóm cần ghi độ trễ thực và tỷ lệ báo nhầm từ một tập đánh giá riêng.

## Phân công và tích hợp

| Thành viên | Nhánh gợi ý | Phần bàn giao |
| --- | --- | --- |
| Nguyễn Đức Minh Nghĩa | `feature/detector` | Hoàn thiện `detector.py`, định nghĩa ngưỡng và lý do cảnh báo. Ghép cảnh báo thật vào dashboard và chạy tích hợp các PR. |
| Trần Trung Nghĩa | `feature/lab-fixtures` | Dựng mạng thử nghiệm và chuẩn bị dữ liệu xác thực tổng hợp có nhãn. Giữ riêng các ca một nguồn, nhiều nguồn và đối chứng. Bàn giao log mẫu có thể phát lại cùng kết quả kỳ vọng. |
| Nguyễn Thái Nguyên | `feature/evaluation` | Mở rộng `benchmark.py` và ma trận kiểm thử. Bàn giao kết quả trên tập riêng về phát hiện, thời gian cảnh báo, số phiên bị chặn và tỷ lệ người dùng hợp lệ bị yêu cầu TOTP. |
| Nguyễn Từ Anh Nguyên | `feature/totp-policy` | Hoàn thiện thời hạn TOTP, chống dùng lại và quản lý phiên. Kiểm tra cả Web và API, bao gồm mã đúng, mã sai, mã hết hạn và nhật ký quyết định. |
| Võ Nhật Nguyên | `feature/target-portal` | Dựng máy mục tiêu trên Kali VM với Windows qua Host-only, hoàn thiện form Web, API, hồ sơ giả và log xác thực. Bàn giao hướng dẫn chạy lại trên máy khác. |

1. **Chốt giao diện giữa các phần.** Nhật ký đăng nhập sai dùng `event`, `timestamp`, `ip`, `account`, `surface`. Cảnh báo kèm `sources`, `targets`, `surfaces`. IP lấy từ kết nối TCP. Log tránh ghi mật khẩu, OTP và token.
2. **Ghép máy chủ và IPS.** Kiểm tra kết nối Windows → Kali và IP trong log trước. Giữ đường desktop replay để kiểm tra detector nhanh. Tách dữ liệu đã chạy qua HTTP khỏi log tổng hợp trong báo cáo.
3. **Chạy nghiệm thu.** So sánh bật/tắt IPS trên cùng bộ log. Quay ba cảnh gồm đối chứng cấp phiên, giữ phiên để chờ TOTP và người dùng nhập mã hợp lệ. Công bố riêng các ca bỏ sót hoặc yêu cầu TOTP nhầm.

Mỗi thành viên tạo nhánh từ `main`, mở PR có cách chạy lại và kết quả test. Giữ phần phân công ở trên làm ranh giới để tránh sửa cùng một khối mã.
