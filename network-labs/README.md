# network-labs

Thư mục tách riêng cho các bài thực nghiệm & giáo cụ môn Mạng máy tính (Epic E10, E12):
- Phân tích TCP 3-way handshake, TLS 1.2+, HTTP/1.1, WebSocket RFC 6455
- Thực nghiệm đo UDP vs TCP, MTU/Fragmentation, DNS dump thủ công
- Raw Socket Programming, Subnetting/VLSM, chẩn đoán LAN/ARP/NAT

## Cài đặt & Test

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -v
ruff check .
black --check .
```
