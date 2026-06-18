Lab12
Mục tiêu của bài Lab 12:
- Sử dụng các công cụ phân tích động  như Process Monitor, Regshot, Handle Diff và Process Explorer
- Phân tích hành vi của các mẫu mã độc
- Phân tích kỹ thuật tiêm tiến trình
Kết quả thu được:
Đối với mẫu Lab11-01.exe:
- Dùng Process Monitor phát hiện mã độc sinh ra tệp msgina32.dll và ghi vào khóa Registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDLL
- Dùng Resource Hacker để tìm và trích xuất thành công tệp thực thi độc hại được nhúng ẩn bên trong Resource của mã độc
- Trích xuất thành công mã băm MD5 của tệp msgina32.dll và tệp được xuất ra bằng công cụ HashCalc
Đối với mẫu Lab12-01.exe:

- Bằng PEview, phát hiện được các API thường dùng để tiêm tiến trình gồm: CreateRemoteThread, WriteProcessMemory và VirtualAllocEx
- Trích xuất được các chuỗi (strings) mục tiêu bao gồm explorer.exe, Lab12-01.dll và psapi.dll
- Dùng IDA Pro phân tích mã Assembly, đổi tên các hàm và xác định được hành vi mã độc dùng hàm để rà quét, nhắm mục tiêu vào tiến trình explorer.exe
- Dùng Process Explorer để theo dõi và xác nhận thành công việc thư viện Lab12-01.dll đã được tiêm vào bên trong tiến trình hệ thống explorer.exe

- Tải và cài đặt công cụ Htop trên Ubuntu

![img_006_ad9237e3](Lab12_images/img_006_ad9237e3.png)

Đã cài sẵn Process Monitor nên không cần cài thêm
![img_001_69ada789](Lab12_images/img_001_69ada789.png)

![img_018_39aca8b7](Lab12_images/img_018_39aca8b7.png)
Kiểm tra file Lab11-01.exe bằng Strings
![img_016_ee585555](Lab12_images/img_016_ee585555.png)
Kiếm  tra file lab 11-01.exe bằng công cụ Pe view
![img_012_d599eaf6](Lab12_images/img_012_d599eaf6.png)

![img_007_f23def43](Lab12_images/img_007_f23def43.png)

![img_002_7c967dd1](Lab12_images/img_002_7c967dd1.png)

![img_019_ad1e84b3](Lab12_images/img_019_ad1e84b3.png)

![img_014_48e5aaf7](Lab12_images/img_014_48e5aaf7.png)

![img_010_78c19ccb](Lab12_images/img_010_78c19ccb.png)

![img_008_b262f805](Lab12_images/img_008_b262f805.png)

![img_003_b3d171c9](Lab12_images/img_003_b3d171c9.png)

![img_017_3cee4567](Lab12_images/img_017_3cee4567.png)

![img_011_8c5fbf57](Lab12_images/img_011_8c5fbf57.png)

![img_005_0321b3c2](Lab12_images/img_005_0321b3c2.png)

![img_020_ed39929b](Lab12_images/img_020_ed39929b.png)

![img_015_6d22422a](Lab12_images/img_015_6d22422a.png)

![img_013_51d4587c](Lab12_images/img_013_51d4587c.png)

![img_009_4cc121ab](Lab12_images/img_009_4cc121ab.png)

![img_004_2fcaff3f](Lab12_images/img_004_2fcaff3f.png)
