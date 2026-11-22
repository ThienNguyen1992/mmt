# Chính sách Quyền riêng tư & Dữ liệu — OpenGuard Kids (OGK-013)

> **Triết lý cốt lõi:** *"Công cụ đồng hành, không phải phần mềm theo dõi lén."*
> Tài liệu tuân thủ nguyên tắc tối thiểu dữ liệu (**NT2**), minh bạch hai chiều (**NT5**) và phạm vi xử lý dữ liệu cá nhân theo **Nghị định 13/2023/NĐ-CP**.

---

## 1. Dữ liệu ĐƯỢC thu thập (Khớp 100% lược đồ DB & Event)

### 1.1. Bảng `events` (7 trường nghiệp vụ + khóa kỹ thuật)

| Trường / Bảng | Mục đích | Thời hạn lưu | Ai xem được | Bảo vệ kỹ thuật |
|---|---|---|---|---|
| `events.id` | Khóa chính định danh duy nhất bản ghi sự kiện | 90 ngày (tự xóa) | Hệ thống nội bộ | UUIDv4 ngẫu nhiên |
| `events.idempotency_key` | Chống đếm trùng khi Agent đồng bộ lại lúc mất mạng | 90 ngày (tự xóa) | Hệ thống nội bộ | UUIDv4 `UNIQUE` |
| `events.ts` | Xác định thời điểm sự kiện để vẽ biểu đồ ngày/tuần | 90 ngày (tự xóa) | Phụ huynh sở hữu, Trẻ (`child-view`) | UTC ISO-8601 (`DateTime(tz=True)`) |
| `events.device_id` | Phân biệt thiết bị khi 1 trẻ dùng nhiều máy | 90 ngày / khi gỡ thiết bị | Phụ huynh sở hữu, Trẻ (`child-view`) | UUID nội bộ + kiểm tra ownership |
| `events.child_id` | Gắn dữ liệu vào đúng hồ sơ trẻ | 90 ngày / khi xóa dữ liệu | Phụ huynh sở hữu, Trẻ (`child-view`) | UUID + kiểm tra sở hữu chống IDOR |
| `events.type` | Phân loại 9 loại sự kiện (`app_start` → `override_granted`) để thống kê | 90 ngày (tự xóa) | Phụ huynh sở hữu, Trẻ (`child-view`) | Enum `EventType` kiểm tra tại API |
| `events.subject` | Tên tiến trình (vd `word.exe`) hoặc tên miền cấp hai eTLD+1 (vd `youtube.com`) | 90 ngày (tự xóa) | Phụ huynh sở hữu, Trẻ (`child-view`) | Validator Pydantic cấm URL đầy đủ/path/query |
| `events.duration_sec` | Cộng dồn thời lượng sử dụng thực | 90 ngày (tự xóa) | Phụ huynh sở hữu, Trẻ (`child-view`) | Số nguyên không âm (`ge=0`) |
| `events.policy_id` | Đối chiếu phiên bản luật đang áp dụng tại thời điểm sự kiện | 90 ngày (tự xóa) | Phụ huynh sở hữu, Trẻ (`child-view`) | Phục vụ giải trình minh bạch NT4 |

### 1.2. Các bảng quản lý tài khoản, chính sách, yêu cầu & kiểm toán

| Trường / Bảng | Mục đích | Thời hạn lưu | Ai xem được | Bảo vệ kỹ thuật |
|---|---|---|---|---|
| `parents.*` (`email`, `password_hash`, `role`, `failed_login_count`, `locked_until`) | Xác thực phụ huynh, khóa tạm khi đăng nhập sai 5 lần và phân quyền RBAC | Đến khi xóa tài khoản | Phụ huynh sở hữu | Băm mật khẩu **Argon2id** (`passlib`) |
| `children.name_enc`, `birth_year`, `age_group` | Hiển thị tên hồ sơ trẻ và áp dụng preset lứa tuổi (6–11 / 12–15) | Đến khi phụ huynh xóa | Phụ huynh sở hữu, Trẻ (`child-view`) | Tên trẻ mã hóa **AES-256-GCM** |
| `devices.fingerprint_enc`, `device_secret_hash`, `name`, `is_active`, `last_seen_at` | Định danh thiết bị chống giả mạo và theo dõi trạng thái Online/Offline | Đến khi gỡ thiết bị | Phụ huynh sở hữu | Fingerprint mã hóa **AES-256-GCM**; secret băm **SHA-256** |
| `policies.*` (`version`, `content_json`, `signature`) | Lưu lịch sử các phiên bản luật (quota, lịch 7×48, app/domain rules) | Đến khi gỡ thiết bị | Phụ huynh sở hữu, Agent (verify) | Ký số toàn vẹn **Ed25519** |
| `audit_logs.*` (`actor_role`, `action`, `ip_address`, `old_value`, `new_value`) | Nhật ký minh bạch mọi thay đổi chính sách/lệnh khẩn của phụ huynh | 90 ngày (tự xóa) | Phụ huynh sở hữu **và Trẻ (chỉ đọc)** | Append-only (**NT5**) |
| `child_requests.*` (`request_type`, `subject`, `requested_minutes`, `status`, `parent_note`) | Ghi nhận và phản hồi yêu cầu *Xin thêm giờ* / *Báo chặn nhầm* từ trẻ | 90 ngày / khi xóa dữ liệu | Phụ huynh sở hữu, Trẻ (`child-view`) | Ràng buộc sở hữu theo `child_id` (**NT3**) |
| `sessions.*` | Quản lý phiên đăng nhập Web Dashboard (hạn 12h, thu hồi khi logout) | 12 giờ / khi logout | Hệ thống xác thực | Cookie `HttpOnly`, `Secure`, `SameSite=Lax` |
| `refresh_tokens.*` | Cấp lại access token JWT 15 phút cho Agent mà không lưu mật khẩu | 30 ngày / khi revoke | Hệ thống xác thực | Lưu băm **SHA-256** (`token_hash`) |
| `enrollment_codes.*` (`code`, `consent_confirmed`, `consent_ip`) | Điểm ghi nhận sự đồng ý của cha mẹ khi ghép đôi thiết bị (Nghị định 13/2023) | Hết hạn sau 10 phút | Phụ huynh sở hữu | Mã 8 ký tự dùng 1 lần duy nhất |

---

## 2. Dữ liệu TUYỆT ĐỐI KHÔNG thu thập

1. **Không** lưu URL đầy đủ (path, query string, fragment, từ khóa tìm kiếm trên trình duyệt/công cụ tìm kiếm).
2. **Không** lưu tiêu đề cửa sổ (window title), nội dung tin nhắn, email, tài liệu hay tệp cá nhân của trẻ.
3. **Không** ghi phím bấm (keylogger), **không** chụp ảnh màn hình (screenshot), **không** bật micro hoặc webcam.
4. **Không** ẩn tiến trình/dịch vụ (Tray icon luôn hiển thị minh bạch; tắt Tray sẽ tự dừng giám sát).
5. **Không** gửi, bán hoặc chia sẻ bất kỳ dữ liệu nào tới máy chủ hay dịch vụ bên thứ ba.

---

## 3. Quyền kiểm soát dữ liệu & Phạm vi sử dụng hợp pháp

- **Tự động xóa sau 90 ngày (Retention):** Tác vụ nền trên Server (`retention_service`) định kỳ xóa các bản ghi `events` và `audit_logs` quá 90 ngày.
- **Xóa ngay lập tức theo yêu cầu:** Nút *"Xóa toàn bộ dữ liệu của con tôi"* (`POST /privacy/{child_id}/delete-all`) xóa đồng thời dữ liệu sử dụng trên Server DB và gửi lệnh `wipe_local_cache` để xóa sạch bộ đệm cục bộ (`ogk_agent.db`) trên máy trẻ.
- **Quyền xem hai chiều (NT5):** Trẻ em có thể xem cùng bộ thống kê hoạt động của mình qua màn hình *"Hôm nay em đã dùng gì"* (`child-view`) và xem nhật ký thay đổi luật (`audit_logs`) ở chế độ chỉ đọc.
- **Phạm vi sử dụng hợp pháp (Nghị định 13/2023/NĐ-CP):** OpenGuard Kids chỉ được phép cài đặt và vận hành trên máy tính cá nhân trong gia đình có sự đồng ý, thiết lập trực tiếp của cha mẹ hoặc người giám hộ hợp pháp (`consent_confirmed=True`). Tuyệt đối nghiêm cấm sử dụng để theo dõi người khác khi chưa có sự đồng ý hoặc thử nghiệm trên thiết bị không thuộc quyền quản lý hợp pháp.
