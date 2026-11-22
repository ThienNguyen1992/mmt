from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "docs" / "api_contract.md"

REQUIRED_PREFIXES = (
    "/auth",
    "/enroll",
    "/policy",
    "/events",
    "/commands",
    "/reports",
    "/audit",
    "/requests",
    "/privacy",
    "/dashboard",
)


def test_api_contract_exists_and_lists_all_10_prefixes():
    assert CONTRACT_PATH.exists(), "Thiếu docs/api_contract.md"
    content = CONTRACT_PATH.read_text(encoding="utf-8")

    for prefix in REQUIRED_PREFIXES:
        assert prefix in content, f"API contract thiếu nhóm prefix {prefix}"

    assert "/health" in content


def test_openapi_docs_match_api_contract_and_no_api_prefix_drift():
    client = TestClient(app)

    docs_res = client.get("/docs")
    assert docs_res.status_code == 200

    schema_res = client.get("/openapi.json")
    assert schema_res.status_code == 200
    openapi = schema_res.json()

    contract_text = CONTRACT_PATH.read_text(encoding="utf-8")
    paths = openapi.get("paths", {})
    assert "/health" in paths
    assert "/auth/register" in paths
    assert "/events/batch" in paths

    for path, methods in paths.items():
        assert not path.startswith("/api/"), f"Không được dùng prefix /api/ cho {path}"
        assert path in contract_text, f"Route {path} trong Swagger chưa có trong api_contract.md"
        for method in methods:
            assert method.upper() in contract_text
