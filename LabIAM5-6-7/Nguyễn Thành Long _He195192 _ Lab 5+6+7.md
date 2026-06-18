LAB 5

Đăng nhập vào mày ảo

![img_011_20ce067a](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_011_20ce067a.png)

![img_013_b5c907da](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_013_b5c907da.png)

tải file mẫu pe từ máy chủ PaloAlto Networks phục vụ cho việc phân tích

![img_014_e5fa65d3](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_014_e5fa65d3.png)

lệnh file pe để xác định đây là tệp tin thực thi 32-bit trên môi trường Windows. Sau đó tải và giải nén Go

![img_006_1d7d2de8](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_006_1d7d2de8.png)

Di chuyển thư mục Go vào hệ thống /usr/local, sau đó khai báo vị trí cài đặt bộ nguồn GO, thiết lập thư mục làm việc tại Lab 5 (GOPATH) và cập nhật đường dẫn môi trường (PATH) để máy tính có thể nhận diện và chạy lệnh Go

![img_019_a12c4be5](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_019_a12c4be5.png)

![img_017_1e457351](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_017_1e457351.png)

tải công cụ cosign và cấp quyền thực thi cho cosign

![img_022_401a75c2](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_022_401a75c2.png)

Sử dụng công cụ Cosign để đối chiếu file cài đặt sift-cli-linux với chữ ký số .sig và khóa công khai .pub. Kết quả trả về 'Verified OK' chứng minh file này là chính gốc từ nhà phát triển SANS

![img_021_480d00be](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_021_480d00be.png)

cấp quyền cho chủ sở hữu toàn quyền còn group và các người khác thì chỉ có quyền đọc và chạy. Sau đó cài đặt sift nhưng không thành công do script cài đặt không xác định được phiên bản Ubuntu, nguyên nhân là do Ubuntu đang dùng là phiên bản mới hơn so với các phiên bản mà SIFT hỗ trợ nhưng trước đó em dùng bản cũ như trong bài hoặc bản lite cũng đều không cài được sift ngay từ đầđầu

![img_025_cbfa1cec](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_025_cbfa1cec.png)

LAB 6 Public AV Scanners (VirusTotal, JoeSandbox)

Sử dụng VirusTotal để quét tệp tin mẫu pe. Kết quả cho thấy hàng loạt các công cụ bảo mật như Fortinet, Google, GData... đều phát hiện và cảnh báo đây là mã độc, với nhãn nhận diện là Trojan

![img_024_f1f0c47c](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_024_f1f0c47c.png)

IOCs
![img_027_06948177](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_027_06948177.png)
:
Behavior:
Thực thi file PE32 trên Windows C:\Users\user\Desktop\wildfire-test-pe-file (2).exe
Load các thư viện hệ thống kernel32.dll, ntdll.dll, user32.dll, advapi32.dll, msvcrt.dll,…
Tạo process con conhost.exe
Ghi một số key registry liên quan PaloAlto HKEY_LOCAL_MACHINE\Software\WOW6432Node\PaloAlto\PanCar
HKEY_LOCAL_MACHINE\Software\WOW6432Node\PaloAlto

JoeSandbox
Báo cáo tổng quan phân loại tệp tin là Malicious

![img_026_06f8670e](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_026_06f8670e.png)

IOC

![img_029_f1c15f13](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_029_f1c15f13.png)

![img_028_a68e0027](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_028_a68e0027.png)

Domains: Không có
URLs: Không có
IPs: Không có

Behavior:
JoeSandbox đưa ra các signature:
PE file có checksum không hợp lệ
PE có section không chuẩn
Không import hàm thông thường
Chương trình ít hoạt động (idle)
Sử dụng PE 32-bit
Không ghi nhận các hành vi như kết nối mạng ,không có file bị drop hay payload giải nén, chương trình hầu như không thực hiện hành vi rõ rệt , có khả năng né sandbox hoặc chờ điều kiện kích hoạt

![img_001_b80813ed](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_001_b80813ed.png)

Kiểm tra thông tin tĩnh Static File Info trên JoeSandbox xác nhận đây là tệp thực thi PE32 executable dành cho môi trường Windows, khớp với thông tin đã kiểm tra bằng lệnh file trên máy SIFđótrong bài LAB

![img_003_5c2ac423](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_003_5c2ac423.png)

LAB 7

![img_002_4079c300](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_002_4079c300.png)

![img_005_ba0dd5ff](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_005_ba0dd5ff.png)

![img_004_10899feb](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_004_10899feb.png)

![img_008_1ba4bb5e](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_008_1ba4bb5e.png)

![img_007_6ed3f556](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_007_6ed3f556.png)

![img_010_ce3de5b1](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_010_ce3de5b1.png)

![img_009_7007d4cd](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_009_7007d4cd.png)

![img_012_ddafa1d8](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_012_ddafa1d8.png)

![img_016_836e9dd6](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_016_836e9dd6.png)

![img_015_37b4c6c4](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_015_37b4c6c4.png)

![img_020_46f0c0e7](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_020_46f0c0e7.png)

![img_018_7823ad87](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_018_7823ad87.png)

![img_023_f75459b1](Nguyễn Thành Long _He195192 _ Lab 5+6+7_images/img_023_f75459b1.png)
