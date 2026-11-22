# openguard-shared

Thư viện thuần Python dùng chung giữa `openguard-server`, `openguard-agent` và `network-labs`.

## Cài đặt & Test

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -v
ruff check .
black --check .
```
