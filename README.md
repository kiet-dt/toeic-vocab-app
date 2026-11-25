# Luyện từ vựng TOEIC (nhiều người dùng, mỗi người có từ riêng)

- public/index.html           -> giao diện (đăng nhập / đăng ký / quên mật khẩu / thêm từ)
- netlify/functions/api.mjs   -> backend (API /api/*)
- package.json, netlify.toml  -> cấu hình cho Netlify
- Database: Netlify Blobs (có sẵn, không cần tạo gì thêm)

Không cần đặt biến môi trường nào. Khóa ký đăng nhập tự sinh ở lần chạy đầu.
(Tùy chọn: đặt SESSION_SECRET = một chuỗi dài ngẫu nhiên nếu muốn tự quản khóa.)

Lưu ý: "Quên mật khẩu" chỉ cần tên tài khoản + mật khẩu mới (không có mã xác minh),
nên ai biết tên tài khoản của bạn đều đổi được mật khẩu và đọc được từ riêng của bạn.
