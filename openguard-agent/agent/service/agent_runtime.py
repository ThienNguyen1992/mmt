import threading

from agent.core.config import load_config
from agent.core.event_queue import count_pending
from agent.core.local_store import (
    clear_all_local_data,
    get_state_int,
    init_schema,
    purge_synced_events,
)
from agent.core.logger import get_logger
from agent.core.policy_enforcer import PolicyEnforcer

logger = get_logger("agent_runtime")


class AgentRuntime:
    """Bộ điều phối vòng đời Agent chạy trong Windows Service OGKAgent hoặc console."""

    def __init__(self, start_network: bool = True):
        self.config = load_config()
        self.start_network = start_network
        self.device_id = self.config.get("device_id")
        self.child_id = self.config.get("child_id", "unknown")
        self.server_base_url = (
            f"https://{self.config.get('server_host', '127.0.0.1')}:"
            f"{self.config.get('server_port', 8443)}"
        )
        self.verify_cert_path = self.config.get("ca_cert_path", "./certs/ca.crt")
        self.pinned_cert_path = self.config.get("pinned_cert_path", "./certs/server.crt")

        self._stop_event = threading.Event()
        self._lock_flag = False
        self._lock_reason = ""
        self._extra_minutes_today = 0

        # Telemetry từ Tray UI (giải quyết Session 0 Isolation)
        self._user_idle_sec: float | None = None
        self._user_fg_process: str | None = None
        self._user_session_locked: bool | None = None

        self.enforcer = PolicyEnforcer(device_id=self.device_id)
        self.offline_tracker = self._init_optional("agent.core.offline_tracker", "OfflineTracker")
        self.fail_mode = self._init_fail_mode()

        self.workers: list = []
        self.ipc_server = None
        self.screen_time = None
        self.app_controller_worker = None
        self.dns_proxy_worker = None
        self.tray_watchdog = None

    @staticmethod
    def _init_optional(module_name: str, attr_name: str):
        try:
            mod = __import__(module_name, fromlist=[attr_name])
            return getattr(mod, attr_name)()
        except ImportError:
            return None

    def _init_fail_mode(self):
        if self.offline_tracker is None:
            return None
        try:
            from agent.core.fail_mode import FailModeEvaluator

            return FailModeEvaluator(self.offline_tracker)
        except ImportError:
            return None

    def start(self) -> None:
        logger.info("=== OGK-Agent khởi động ===")
        init_schema()
        try:
            from agent.core.acl_hardening import harden_agent_directories

            harden_agent_directories()
        except Exception as exc:
            logger.warning("Không thể siết ACL (có thể đang chạy dev non-admin): %s", exc)

        try:
            from agent.core.ipc_server import IPCServer
            from agent.core.ipc_token import rotate_ipc_token

            rotate_ipc_token()
            self.ipc_server = IPCServer(runtime=self)
            self.ipc_server.start()
        except ImportError:
            pass

        if self.start_network and self.device_id:
            self._start_network_workers()
        self._start_enforcement_workers()
        self._start_housekeeping()

    def _refresh_token(self) -> str:
        from agent.core.sync_client import refresh_access_token

        return refresh_access_token(
            self.server_base_url,
            verify_cert_path=self.verify_cert_path,
            pinned_cert_path=self.pinned_cert_path,
        )

    def _start_network_workers(self) -> None:
        from agent.core.command_listener import CommandListener
        from agent.core.sync_client import EventSyncWorker, HeartbeatWorker

        hb = HeartbeatWorker(
            self.server_base_url,
            state_provider=self.get_status_snapshot,
            interval_sec=self.config.get("heartbeat_interval_sec", 60),
            verify_cert_path=self.verify_cert_path,
            pinned_cert_path=self.pinned_cert_path,
            policy_enforcer=self.enforcer,
            offline_tracker=self.offline_tracker,
        )
        hb.start()
        self.workers.append(hb)

        ev_sync = EventSyncWorker(
            self.server_base_url,
            verify_cert_path=self.verify_cert_path,
            pinned_cert_path=self.pinned_cert_path,
            offline_tracker=self.offline_tracker,
        )
        ev_sync.start()
        self.workers.append(ev_sync)

        cmd = CommandListener(
            ws_url=(
                f"wss://{self.config.get('server_host', '127.0.0.1')}:"
                f"{self.config.get('server_port', 8443)}/commands/ws/{self.device_id}"
            ),
            token_provider=lambda: load_config().get("access_token", ""),
            refresh_token_fn=self._refresh_token,
            ca_cert_path=self.verify_cert_path,
            pinned_cert_path=self.pinned_cert_path,
            on_lock_now=lambda _cmd: self.lock_device("parent_emergency_lock"),
            on_unlock=lambda _cmd: self.unlock_device(),
            on_add_minutes=lambda mins, _cmd: self.add_extra_minutes(mins),
            on_wipe_local_cache=lambda _cmd: self.wipe_local_data(),
        )
        cmd.start()
        self.workers.append(cmd)

    def _start_enforcement_workers(self) -> None:
        from agent.core.screen_time import ScreenTimeCounter

        self.screen_time = ScreenTimeCounter(runtime=self)
        self.screen_time.start()
        self.workers.append(self.screen_time)

    def _start_housekeeping(self) -> None:
        try:
            purge_synced_events(older_than_days=7)
        except Exception as exc:
            logger.warning("Housekeeping purge_synced_events lỗi: %s", exc)

    def stop_enforcement_only(self) -> None:
        """Dùng cho TrayWatchdog (NT1/F5): dừng giám sát nếu Tray tắt, giữ IPC để log/restart."""
        for w in (self.screen_time, self.app_controller_worker, self.dns_proxy_worker):
            if w:
                try:
                    w.stop()
                except Exception as exc:
                    logger.warning("Lỗi dừng worker %s: %s", type(w).__name__, exc)

    def stop(self) -> None:
        self._stop_event.set()
        self.stop_enforcement_only()
        extra = ([self.tray_watchdog] if self.tray_watchdog else []) + (
            [self.ipc_server] if self.ipc_server else []
        )
        for w in self.workers + extra:
            if w:
                try:
                    w.stop()
                except Exception as exc:
                    logger.warning("Lỗi dừng %s: %s", type(w).__name__, exc)

    def wait(self, timeout: float | None = None) -> bool:
        return self._stop_event.wait(timeout=timeout)

    def update_tray_telemetry(
        self,
        idle_sec: float | None,
        fg_process: str | None,
        session_locked: bool | None,
    ) -> None:
        self._user_idle_sec = idle_sec
        self._user_fg_process = fg_process
        self._user_session_locked = session_locked

    def lock_device(self, reason: str) -> None:
        self._lock_flag = True
        self._lock_reason = reason
        try:
            from agent.core.notifier import push_notification

            push_notification(
                "lock_screen",
                {"reason": reason, "message": f"Máy tạm khóa ({reason})."},
            )
        except ImportError:
            pass
        logger.info("Thiết bị chuyển sang trạng thái LOCKED: %s", reason)

    def unlock_device(self) -> None:
        self._lock_flag = False
        self._lock_reason = ""
        logger.info("Thiết bị được MỞ KHÓA theo lệnh phụ huynh")

    def add_extra_minutes(self, minutes: int) -> None:
        self._extra_minutes_today += int(minutes)
        if self._lock_flag and self._lock_reason == "quota_exceeded":
            self.unlock_device()
        try:
            from agent.core.notifier import push_notification

            push_notification(
                "override_granted",
                {"minutes": minutes, "message": f"Phụ huynh đã cộng thêm {minutes} phút!"},
            )
        except ImportError:
            pass

    def wipe_local_data(self) -> None:
        clear_all_local_data()
        if self.screen_time:
            self.screen_time.reset_counters()

    def is_locked(self) -> bool:
        return self._lock_flag

    def get_effective_policy(self) -> dict:
        content = self.enforcer.get_content()
        if self.fail_mode is not None:
            return self.fail_mode.evaluate(content)
        return dict(content or {})

    def get_status_snapshot(self) -> dict:
        eff = self.get_effective_policy()
        remaining_min = (
            self.screen_time.get_quota_remaining_sec() / 60.0 if self.screen_time else 0.0
        )
        offline_days = (
            round(self.offline_tracker.get_offline_duration_days(), 2)
            if self.offline_tracker
            else 0.0
        )
        is_online = not self.offline_tracker.is_offline() if self.offline_tracker else True
        return {
            "device_id": self.device_id,
            "policy_version": self.enforcer.get_current_version(),
            "quota_used_min": get_state_int("quota_used_sec", 0) // 60,
            "quota_used_sec": get_state_int("quota_used_sec", 0),
            "quota_remaining_min": round(remaining_min, 1),
            "is_locked": self._lock_flag,
            "lock_reason": self._lock_reason,
            "pending_events": count_pending(),
            "online": is_online,
            "offline_days": offline_days,
            "fail_mode_active": eff.get("fail_mode_active", False),
            "fail_mode_reason": eff.get("reason", ""),
        }
