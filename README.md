# OpenGuard Kids

Ứng dụng hỗ trợ quản lý việc sử dụng máy tính của trẻ em — *"Công cụ đồng hành, không phải phần mềm theo dõi lén"*.

## Cấu trúc các project thành phần

- `openguard-shared/` — Package dùng chung (`shared.network_constants`, `schedule`, `subnet`...) cài editable `-e ../openguard-shared`
- `openguard-server/` — Backend API (FastAPI + SQLite WAL + TLS 1.2+ + WebSocket) & Dashboard (`dashboard/`)
- `openguard-agent/` — Windows Service (`OGKAgent`), DNS Proxy `127.0.0.1:53`, App Controller, Firewall & Tray UI
- `network-labs/` — Thực nghiệm & giáo cụ môn Mạng máy tính (TCP handshake, UDP vs TCP, DNS dump, subnetting)
- `docs/` — Tài liệu thiết kế chung (ERD, API Contract, Báo cáo, Sơ đồ mạng)

Mỗi thư mục con có `.venv`, `pyproject.toml`, `pytest.ini`, `README.md` riêng để build/chạy độc lập.
