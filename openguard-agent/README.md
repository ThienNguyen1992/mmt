# openguard-agent

Windows Service (`OGKAgent`), DNS Proxy `127.0.0.1:53`, App Controller, Firewall & Tray UI.

## Cài đặt & Chạy

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# Chạy Agent skeleton
python -m agent.main

# Chạy test & lint
pytest -v
ruff check .
black --check .
```

Khi đóng gói EXE sản phẩm với PyInstaller, dùng virtualenv chỉ cài `requirements-agent.txt`.
