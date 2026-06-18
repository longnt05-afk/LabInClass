**Lab**** ****8:**
Mục tiêu của bài Lab 8
- Thực hiện phân tích tĩnh cơ bản (Basic Static Techniques) trên các mẫu mã độc (Lab01-01.exe, Lab01-01.dll, Lab01-02.exe)
- Nhận diện và tiến hành giải nén unpack mã độc bị nén (packe
- Thực hiện phân tích động cơ bản Basic Dynamic Techniques trên mẫu Lab03-01.exe
- Sử dụng kết hợp các công cụ chuyên dụng: Hybrid-Analysis, PEview, PEiD, Strings/FLOSS, Dependency Walker, PEstudio, UPX, INetSim, Process Explorer, Process Monitor, Wireshark
Kết quả thu được từ bài làm
Phần Phân tích tĩnh
- Kiểm tra thành công mức độ độc hại của Lab01-01 và Lab01-02 trên Hybrid-Analysis
- Xác định được thông tin PE Header thời gian biên dịch, First Bytes bằng PEview và PEiD
- Trích xuất được các chuỗi (strings) quan trọng bằng công cụ FLOSS
- Xác định được các hàm API, thư viện DLL như KERNEL32.dll, WS2_32.dll mà mã độc import/export bằng công cụ PEstudio
- Phát hiện Lab01-02.exe bị nén bằng UPX và thực hiện lệnh giải nén (unpack) thành công trên môi trường Flare VM
Phần Phân tích động
- Thiết lập thành công môi trường mạng giả lập với INetSim và chuyển đổi DNS trên máy Windows
- Bắt được gói tin mạng thông qua Wireshark
- Xác định được mã độc tạo ra đối tượng Mutant (Mutex) mang tên WinVMX32 bằng Process Explorer
- Thiết lập thành công các bộ lọc (Filter) trên Process Monitor để chuẩn bị theo dõi hành vi ghi file và registry của Lab03-01.exe
- Phát hiện được truy vấn DNS kết nối đến tên miền độc hại www.practicalmalwareanalysis.com trong log báo cáo của INetSim
- Basic Static Techniquesa
![img_018_02d9d84f](Lab8_images/img_018_02d9d84f.png)

![img_014_dc87a5ba](Lab8_images/img_014_dc87a5ba.png)

![img_006_dd7a3b43](Lab8_images/img_006_dd7a3b43.png)

![img_031_3c8df4e0](Lab8_images/img_031_3c8df4e0.png)

![img_025_ac1731c0](Lab8_images/img_025_ac1731c0.png)

Vì  Dependency Walker không vào được nên em dùng qua pe studio 
![img_022_96c45836](Lab8_images/img_022_96c45836.png)

![img_015_4da11821](Lab8_images/img_015_4da11821.png)

![img_007_a2fc3433](Lab8_images/img_007_a2fc3433.png)

![img_001_7f339aa5](Lab8_images/img_001_7f339aa5.png)

![img_026_91b09954](Lab8_images/img_026_91b09954.png)
Do máy hết bộ nhớ và có sẵn công cụ UPX nên em copy qua flare VM làm 
![img_019_f23baa57](Lab8_images/img_019_f23baa57.png)

![img_011_3fc53e72](Lab8_images/img_011_3fc53e72.png)

![img_008_da863604](Lab8_images/img_008_da863604.png)
Sau bước trên thì có bước chuyển DNS sang 8.8.8.8 tải các file app do trước đó có bài lab dùng DNS của inetsim để đánh lừa malware và do win cũng có sẵn nên không cần cài thêm gì
Do không dùng được Dependentcy nên lại dùng PE studio để check
![img_002_47653fa7](Lab8_images/img_002_47653fa7.png)

![img_023_49f07a39](Lab8_images/img_023_49f07a39.png)

![img_012_abab0197](Lab8_images/img_012_abab0197.png)
Sau khi set xong và tải các file app cần để phân tích động thì lại Set DNS về của Inetsim để phân tích
![img_004_fb2f2457](Lab8_images/img_004_fb2f2457.png)

![img_027_ef6954d8](Lab8_images/img_027_ef6954d8.png)

![img_020_7550239c](Lab8_images/img_020_7550239c.png)

![img_016_aa969619](Lab8_images/img_016_aa969619.png)

![img_009_43e42542](Lab8_images/img_009_43e42542.png)

![img_003_e6039505](Lab8_images/img_003_e6039505.png)

![img_028_dce969a5](Lab8_images/img_028_dce969a5.png)

![img_021_fa5d86a5](Lab8_images/img_021_fa5d86a5.png)

![img_013_2d933a7b](Lab8_images/img_013_2d933a7b.png)

![img_029_cf4353c9](Lab8_images/img_029_cf4353c9.png)

![img_024_224ef315](Lab8_images/img_024_224ef315.png)

![img_017_0192725b](Lab8_images/img_017_0192725b.png)

![img_010_d0161ddd](Lab8_images/img_010_d0161ddd.png)

![img_005_c7cfd7ba](Lab8_images/img_005_c7cfd7ba.png)

![img_030_1647157a](Lab8_images/img_030_1647157a.png)
