# API Contract — OpenGuard Kids (OGK-012)

Tài liệu chuẩn hóa toàn bộ giao tiếp HTTP/HTTPS và WebSocket của `openguard-server`.

---

## 1. Quy ước chung & 10 nhóm Prefix chuẩn

- **Base URL (Lab TLS):** `https://<server-host>:8443` (hoặc `http://127.0.0.1:8000` khi chạy dev cục bộ)
- **Swagger / OpenAPI:** `GET /docs`, `GET /openapi.json`
- **Quy tắc Prefix:** Toàn dự án **KHÔNG** chèn `/api/` vào bất kỳ route nào. Toàn bộ API và Dashboard sử dụng thống nhất đúng **10 nhóm prefix** (kèm `GET /health`):
  1. `/auth` — Đăng ký, đăng nhập, đăng xuất, chuyển phiên `child-view`
  2. `/enroll` — Tạo mã ghép đôi (Nghị định 13/2023), enroll thiết bị, refresh & revoke token
  3. `/policy` — Phát hành/tải chính sách ký Ed25519 và heartbeat 60s
  4. `/events` — Tiếp nhận lô sự kiện chuẩn 7 trường từ Agent
  5. `/commands` — Kênh WebSocket lệnh khẩn (< 5s) và endpoint gửi lệnh từ phụ huynh
  6. `/reports` — API thống kê ngày/tuần, Top 10 app/domain, số lần bị chặn
  7. `/audit` — Nhật ký kiểm toán append-only (phụ huynh & trẻ `child-view` đọc)
  8. `/requests` — Luồng yêu cầu NT3 (*Xin thêm giờ*, *Báo chặn nhầm*)
  9. `/privacy` — Xóa toàn bộ dữ liệu trẻ (Server DB + lệnh `wipe_local_cache` Agent)
  10. `/dashboard` — Giao diện web responsive mobile cho phụ huynh & trẻ

### Chuẩn xác thực & bảo mật (F5)

| Cơ chế | Đối tượng áp dụng | Chi tiết |
|---|---|---|
| **Session Cookie (`ogk_session`)** | `parent`, `admin`, `child-view` | Cookie `HttpOnly`, `Secure`, `SameSite=Lax`, hạn `12h` (`43200s`), lưu trạng thái `revoked` phía server |
| **CSRF Protection** | Mọi `POST/PUT/PATCH/DELETE` từ trình duyệt | API JSON dùng header `X-CSRF-Token`; HTML Form Dashboard dùng hidden field `csrf_token` (`validate_csrf_value`) |
| **Device Bearer JWT** | Agent (`device_id`) | Header `Authorization: Bearer <access_token>` (hạn `15m`, payload `sub=device_id`, `type="access"`). Làm mới qua `/enroll/refresh` |
| **WebSocket Auth** | Agent (`/commands/ws/{device_id}`) | Header `Authorization: Bearer <access_token>` (TLS 1.2+ + Certificate Pinning); đóng code `4401` nếu token hết hạn/không hợp lệ |
| **Rate Limit** | `/auth/*`, `/enroll/*` | `slowapi` theo IP nguồn (`HTTP 429` khi vượt ngưỡng) |
| **Chống IDOR** | Mọi route có `child_id` / `device_id` / `request_id` | Kiểm tra `Child.parent_id == current_parent.id` (hoặc `session.child_id == child_id` với `child-view`) ở tầng truy vấn SQLAlchemy |

---

## 2. System Health

### `GET /health`
- **Trạng thái:** Đã triển khai (`app/main.py`)
- **Auth:** Không yêu cầu
- **Response `200 OK`:**
```json
{"status": "ok"}
```

---

## 3. Nhóm `/auth` — Xác thực & Phiên làm việc

| Method | Path | Auth | CSRF | Rate Limit | Mô tả & Trạng thái |
|---|---|---|---|---|---|
| `POST` | `/auth/register` | Public | Không | `5/minute` | Đăng ký phụ huynh (`Argon2id`, password ≥ 10 ký tự) — **Đã triển khai** |
| `POST` | `/auth/login` | Public | Không | `10/minute` | Đăng nhập tạo cookie `ogk_session` 12h + khóa 15p sau 5 lần sai (`423`) |
| `POST` | `/auth/logout` | Cookie | Có | — | Đánh dấu `Session.revoked = True` & xóa cookie `ogk_session` |
| `POST` | `/auth/child-view` | Cookie (`parent`/`admin`) | Có | `10/minute` | Tạo phiên `role="child-view"` giới hạn theo `child_id` (NT5) |

### Chi tiết Schema `/auth`
- **`POST /auth/register`** (`201 Created`):
  - Request (`RegisterRequest`): `{"email": "user@example.com", "password": ">=10 chars"}`
  - Response (`RegisterResponse`): `{"id": "<uuid>", "email": "user@example.com", "role": "parent"}`
  - Lỗi: `409` (trùng email), `422` (email sai định dạng / mật khẩu < 10 ký tự), `429` (vượt rate limit).
- **`POST /auth/login`** (`200 OK`):
  - Request (`LoginRequest`): `{"email": "...", "password": "..."}`
  - Response: `{"message": "...", "parent_id": "<uuid>", "role": "parent|admin", "csrf_token": "<token>"}` + `Set-Cookie: ogk_session=...; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`.
  - Lỗi: `401` (sai thông tin), `423` (khóa tạm 15 phút sau 5 lần sai), `429`.
- **`POST /auth/child-view`** (`200 OK`):
  - Request (`ChildViewLoginRequest`): `{"child_id": "<uuid>"}`
  - Response: `{"message": "...", "role": "child-view", "child_id": "<uuid>"}`.
  - Lỗi: `403` (nếu caller là `child-view`), `404` (trẻ không thuộc phụ huynh).

---

## 4. Nhóm `/enroll` — Ghép đôi & Token Thiết bị

| Method | Path | Auth | CSRF | Rate Limit | Mô tả |
|---|---|---|---|---|---|
| `POST` | `/enroll/create-code` | Cookie (`parent`/`admin`) | Có | `10/minute` | Sinh mã ghép đôi 8 ký tự (bỏ `0/O/1/I`), hạn 10 phút, bắt buộc `consent_confirmed=True` |
| `POST` | `/enroll/device` | Public (Enrollment Code) | Không | `10/minute` | Agent đổi mã + hardware fingerprint lấy `device_id`, `child_id`, JWT, refresh token, `policy_public_key_pem` |
| `POST` | `/enroll/refresh` | Refresh Token | Không | `20/minute` | Đổi `refresh_token` lấy `access_token` mới (15 phút) |
| `POST` | `/enroll/revoke/{device_id}` | Cookie (`parent`/`admin`) | Có | — | Gỡ thiết bị (`is_active=False`), thu hồi mọi `RefreshToken`, ghi `AuditLog` |

### Chi tiết Schema `/enroll`
- **`POST /enroll/create-code`**:
  - Request: `{"child_id": "<uuid>", "consent_confirmed": true}` (`False` → `422`)
  - Response: `{"code": "AB23CD45", "expires_at": "<iso-utc>"}`
- **`POST /enroll/device`**:
  - Request: `{"code": "AB23CD45", "fingerprint": "<sha256-hw>", "device_name": "Laptop Windows"}`
  - Response: `{"device_id": "<uuid>", "child_id": "<uuid>", "access_token": "<jwt>", "refresh_token": "<raw>", "policy_public_key_pem": "-----BEGIN PUBLIC KEY-----..."}`
  - Lỗi: `404` (sai mã), `410` (mã đã dùng hoặc hết hạn).
- **`POST /enroll/refresh`**:
  - Request: `{"refresh_token": "<raw>"}`
  - Response: `{"access_token": "<jwt>"}` (`401` nếu token revoked/hết hạn hoặc thiết bị đã bị gỡ).

---

## 5. Nhóm `/policy` — Chính sách Ed25519 & Heartbeat

| Method | Path | Auth | CSRF | Mô tả |
|---|---|---|---|---|
| `POST` | `/policy/{device_id}` | Cookie (`parent`/`admin`) | Có | Tạo version mới (`PolicyContent`), ký Ed25519 bằng Private Key, ghi `AuditLog` với IP thực |
| `GET` | `/policy/{device_id}` | Device Bearer JWT | Không | Agent tải policy mới nhất kèm chữ ký `signature` Ed25519 (`device.id == device_id`) |
| `POST` | `/policy/heartbeat/{device_id}` | Device Bearer JWT | Không | Agent báo cáo trạng thái mỗi 60s, Server cập nhật `last_seen_at` & báo có bản policy mới hay không |

### Chi tiết Schema `/policy`
- **`POST /policy/{device_id}` & `GET /policy/{device_id}`** → `PolicyResponse`:
  - `{"policy_id": "<uuid>", "device_id": "<uuid>", "version": 2, "content": {PolicyContent}, "signature": "<base64-ed25519>", "created_at": "<iso-utc>"}`
- **`POST /policy/heartbeat/{device_id}`**:
  - Request (`HeartbeatRequest`): `{"policy_version": 1, "quota_used_min": 35, "is_locked": false}`
  - Response (`HeartbeatResponse`): `{"server_policy_version": 2, "policy_update_available": true, "server_utc": "<iso-utc>", "pending_commands": []}`

---

## 6. Nhóm `/events` — Thu thập Sự kiện Tối thiểu (NT2 / F3)

| Method | Path | Auth | CSRF | Mô tả & Trạng thái |
|---|---|---|---|---|
| `POST` | `/events/batch` | Device Bearer JWT | Không | Nhận tối đa 200 event/lô, chống trùng `idempotency_key` — **Đã triển khai** |

### Chi tiết Schema `POST /events/batch`
- **Request (`EventBatchRequest`):**
  - `events`: danh sách tối đa `200` `EventItem` (`extra="forbid"`):
    - `idempotency_key`: `str` (`1..128` ký tự, UUIDv4)
    - 7 trường nghiệp vụ bắt buộc: `ts` (`datetime`), `device_id` (`str`), `child_id` (`str`), `type` (`EventType` 9 giá trị), `subject` (`str | null`, ≤ 255 ký tự, cấm `://`, `/`, `?`, `=`, `#`), `duration_sec` (`int >= 0`), `policy_id` (`str | null`).
- **Response `200 OK` (`EventBatchResponse`):**
  - `{"inserted": 2, "skipped_duplicates": 0}`
- **Hành vi đặc biệt (NT3):** Event `type == "unlock_request"` tự tạo bản ghi `ChildRequest` (`extra_time` hoặc `wrong_block:<domain>`).
- **Lỗi:** `401` (thiếu/sai JWT hoặc thiết bị bị gỡ), `403` (`device_id`/`child_id` không khớp token), `422` (`type` lạ, thừa trường, hoặc `subject` chứa URL đầy đủ/path/query).

---

## 7. Nhóm `/commands` — Lệnh khẩn WebSocket (< 5 giây)

| Protocol / Method | Path | Auth | CSRF | Mô tả |
|---|---|---|---|---|
| `WS` / `WSS` | `/commands/ws/{device_id}` | Header `Authorization: Bearer <jwt>` | Không | Kênh push lệnh khẩn + `ping`/`pong` keep-alive (đóng `4401` khi unauthorized) |
| `POST` | `/commands/send/{device_id}` | Cookie (`parent`/`admin`) | Có | Đẩy lệnh `lock_now`, `unlock`, `add_minutes`, `wipe_local_cache` tới thiết bị và ghi `AuditLog` |

### Chi tiết Schema `/commands`
- **`POST /commands/send/{device_id}`**:
  - Request: `{"type": "lock_now|unlock|add_minutes|wipe_local_cache", ...}` (vd `{"type": "add_minutes", "minutes": 15}`)
  - Response: `{"delivered": true, "command": {...}}` (`422` nếu `type` ngoài 4 lệnh cho phép, `404` nếu thiết bị không thuộc phụ huynh).

---

## 8. Nhóm `/reports` — Thống kê Hoạt động (Phụ huynh & Trẻ)

| Method | Path | Auth | Mô tả |
|---|---|---|---|
| `GET` | `/reports/{child_id}/daily` | Cookie (`parent`, `admin`, `child-view`) | Thời lượng sử dụng theo từng ngày (mặc định 7 ngày) |
| `GET` | `/reports/{child_id}/weekly` | Cookie (`parent`, `admin`, `child-view`) | Tổng hợp thời lượng theo tuần |
| `GET` | `/reports/{child_id}/top-apps` | Cookie (`parent`, `admin`, `child-view`) | Top 10 ứng dụng sử dụng nhiều nhất (từ `app_stop`) |
| `GET` | `/reports/{child_id}/top-domains` | Cookie (`parent`, `admin`, `child-view`) | Top 10 tên miền cấp hai eTLD+1 truy cập nhiều nhất (từ `domain_query`) |
| `GET` | `/reports/{child_id}/blocked` | Cookie (`parent`, `admin`, `child-view`) | Thống kê số lần bị chặn app/domain |

- **Kiểm tra quyền (IDOR/RBAC):** `child-view` chỉ được phép truy vấn đúng `session.child_id == child_id` (khác → `403`); `parent` phải là chủ sở hữu `Child.parent_id == parent.id` (khác → `404`).

---

## 9. Nhóm `/audit` — Nhật ký Kiểm toán Minh bạch (NT5)

| Method | Path | Auth | Mô tả |
|---|---|---|---|
| `GET` | `/audit` | Cookie (`parent`, `admin`, `child-view`) | Lấy danh sách `AuditLog` chỉ đọc (lọc theo `?child_id=...`); `child-view` chỉ xem được log của chính mình |

---

## 10. Nhóm `/requests` — Yêu cầu của Trẻ (NT3)

| Method | Path | Auth | CSRF | Mô tả |
|---|---|---|---|---|
| `GET` | `/requests` | Cookie (`parent`, `admin`, `child-view`) | Không | Danh sách yêu cầu *Xin thêm giờ* / *Báo chặn nhầm* (`child-view` chỉ xem của mình) |
| `POST` | `/requests/{request_id}/respond` | Cookie (`parent`/`admin`) | Có | Phụ huynh Duyệt/Từ chối (`approved`/`rejected`), tự đẩy WS `add_minutes` hoặc mở `custom_allowed_domains` (ký Ed25519) + ghi event `override_granted` |

---

## 11. Nhóm `/privacy` — Retention 90 ngày & Xóa toàn bộ dữ liệu (F3)

| Method | Path | Auth | CSRF | Mô tả |
|---|---|---|---|---|
| `POST` | `/privacy/{child_id}/delete-all` | Cookie (`parent`/`admin`) | Có | Xóa toàn bộ `Event` và `ChildRequest` của trẻ trên Server DB + gửi lệnh `wipe_local_cache` xóa `ogk_agent.db` trên Agent |

---

## 12. Nhóm `/dashboard` — Giao diện Web Responsive (Jinja2 + Chart.js Local)

| Method | Path | Auth | CSRF | Mô tả |
|---|---|---|---|---|
| `GET` | `/dashboard` | Cookie (`parent`/`admin`) | Không | Trang tổng quan `1 parent : n child : m device`, trạng thái Online/Offline (120s), nút lệnh khẩn |
| `POST` | `/dashboard/children` | Cookie (`parent`/`admin`) | Form `csrf_token` | Tạo hồ sơ trẻ mới (`name`, `age_group`: `6-11` \| `12-15`) |
| `POST` | `/dashboard/devices/{device_id}/policy` | Cookie (`parent`/`admin`) | Form `csrf_token` | Lưu cấu hình Quota, lịch `7×48`, App/Domain rules → parse `PolicyContent` → ký Ed25519 + ghi `AuditLog` |
| `GET` | `/dashboard/children/{child_id}/reports` | Cookie (`parent`/`admin`) | Không | Trang biểu đồ ngày/tuần & bảng Top 10 dùng `chart.umd.min.js` local + `textContent` chống XSS |
| `GET` | `/dashboard/child-view/{child_id}` | Cookie (`parent`, `admin`, `child-view`) | Không | Màn hình *"Hôm nay em đã dùng gì"* cho trẻ + Audit Log chỉ đọc (NT5) |
| `GET` | `/dashboard/transparency/{child_id}/export.json` | Cookie (`parent`, `admin`, `child-view`) | Không | Xuất dữ liệu sử dụng & audit log của trẻ dạng JSON |
