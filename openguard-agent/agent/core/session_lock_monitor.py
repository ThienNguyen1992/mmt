"""Windows session lock monitor (Win+L, Screen Saver, Fast User Switching)."""

from __future__ import annotations

import ctypes
import sys
import threading

WM_WTSSESSION_CHANGE = 0x02B1
WM_QUIT = 0x0012
WTS_SESSION_LOCK = 0x7
WTS_SESSION_UNLOCK = 0x8
NOTIFY_FOR_ALL_SESSIONS = 1


class SessionLockMonitor:
    """Tracks interactive session lock state via IPC telemetry or WTS notifications."""

    def __init__(self, hook_os: bool = True) -> None:
        self._hook_os = hook_os and sys.platform == "win32"
        self._locked = False
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._ready = threading.Event()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def handle_wts_event(self, event_code: int) -> None:
        with self._lock:
            if event_code == WTS_SESSION_LOCK:
                self._locked = True
            elif event_code == WTS_SESSION_UNLOCK:
                self._locked = False

    def is_locked(self, override_session_locked: bool | None = None) -> bool:
        if override_session_locked is not None:
            return bool(override_session_locked)
        with self._lock:
            return self._locked

    def start(self) -> None:
        if not self._hook_os:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._ready.clear()
        self._thread = threading.Thread(target=self._run_loop, name="session-lock-mon", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=1.0)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread_id is not None and sys.platform == "win32":
            try:
                ctypes.windll.user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
            except Exception:
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self) -> None:
        hwnd = None
        try:
            import win32api
            import win32con
            import win32gui

            self._thread_id = win32api.GetCurrentThreadId()

            def _wnd_proc(h: int, msg: int, wparam: int, lparam: int) -> int:
                if msg == WM_WTSSESSION_CHANGE:
                    self.handle_wts_event(int(wparam))
                return win32gui.DefWindowProc(h, msg, wparam, lparam)

            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = _wnd_proc
            wc.hInstance = win32api.GetModuleHandle(None)
            wc.lpszClassName = f"OGKSessionLockMon_{id(self)}"
            try:
                class_atom = win32gui.RegisterClass(wc)
            except Exception:
                class_atom = wc.lpszClassName

            hwnd = win32gui.CreateWindow(
                class_atom,
                "OGKSessionLockMon",
                0,
                0,
                0,
                0,
                0,
                win32con.HWND_MESSAGE,
                0,
                wc.hInstance,
                None,
            )
            ctypes.windll.wtsapi32.WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_ALL_SESSIONS)
            self._ready.set()
            win32gui.PumpMessages()
        except Exception:
            self._ready.set()
        finally:
            if hwnd:
                try:
                    ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification(hwnd)
                    import win32gui

                    win32gui.DestroyWindow(hwnd)
                except Exception:
                    pass
