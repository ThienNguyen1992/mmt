from agent.core import config as agent_config
from agent.core import notifier


def test_notifier_push_and_pop_fifo_order(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    notifier.push_notification("quota_warning", {"remaining_min": 5, "message": "Còn 5 phút"})
    notifier.push_notification(
        "blocked_app",
        {"subject": "game.exe", "reason": "Luật do Phụ huynh đặt"},
    )

    items = notifier.pop_pending_notifications()
    assert len(items) == 2
    assert items[0]["type"] == "quota_warning"
    assert items[0]["remaining_min"] == 5
    assert items[1]["type"] == "blocked_app"
    assert items[1]["reason"] == "Luật do Phụ huynh đặt"

    # Queue is empty after pop
    assert notifier.pop_pending_notifications() == []
