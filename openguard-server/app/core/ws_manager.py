import asyncio
import json

from fastapi import WebSocket


class ConnectionManager:
    """Quản lý kết nối WebSocket theo device_id để đẩy lệnh khẩn cấp (< 5s)."""

    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections[device_id] = websocket

    async def disconnect(self, device_id: str) -> None:
        async with self._lock:
            self.active_connections.pop(device_id, None)

    async def send_command(self, device_id: str, command: dict) -> bool:
        async with self._lock:
            ws = self.active_connections.get(device_id)
        if not ws:
            return False
        try:
            await ws.send_text(json.dumps(command))
            return True
        except Exception:
            await self.disconnect(device_id)
            return False


manager = ConnectionManager()
