# openguard-server

Backend API (FastAPI + SQLite WAL + TLS 1.2+ + WebSocket) và Dashboard Web phụ huynh/trẻ em.

## Cài đặt & Chạy

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env

# Chạy server dev
uvicorn app.main:app --reload --port 8000

# Chạy test & lint
pytest -v
ruff check .
black --check .
```
