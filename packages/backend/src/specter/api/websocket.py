"""WebSocket endpoints for real-time agent updates."""

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# In-memory connection store (use Redis in production)
active_connections: list[WebSocket] = []


@router.websocket("/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time agent event streaming."""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Keep connection alive and listen for client messages
            data = await websocket.receive_text()
            message = json.loads(data)

            # Handle subscription requests
            if message.get("type") == "subscribe":
                await websocket.send_json(
                    {
                        "type": "subscribed",
                        "channels": message.get("channels", []),
                    }
                )
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception:
        if websocket in active_connections:
            active_connections.remove(websocket)


async def broadcast_event(event: dict):
    """Broadcast an event to all connected WebSocket clients."""
    disconnected = []
    for conn in active_connections:
        try:
            await conn.send_json(event)
        except Exception:
            disconnected.append(conn)
    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)
