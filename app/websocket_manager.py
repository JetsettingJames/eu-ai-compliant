from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # Stores active WebSocket connections: {scan_id: [WebSocket, ...]}
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info(f"WebSocket connected for scan_id: {scan_id}. Total connections for this scan: {len(self.active_connections[scan_id])}")

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections and websocket in self.active_connections[scan_id]:
            self.active_connections[scan_id].remove(websocket)
            logger.info(f"WebSocket disconnected for scan_id: {scan_id}.")
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
                logger.info(f"No more connections for scan_id: {scan_id}. Entry removed.")
        else:
            logger.warning(f"Attempted to disconnect WebSocket for scan_id: {scan_id}, but connection not found or scan_id not tracked.")

    async def send_progress(self, scan_id: str, message_data: Dict[str, Any]):
        if scan_id in self.active_connections:
            # Create a message structure
            progress_update = {
                "scan_id": scan_id,
                "type": "progress_update",
                "data": message_data
            }
            # Send to all connected clients for this scan_id
            # Make a copy of the list for iteration in case of disconnections during send
            connections_to_send = list(self.active_connections[scan_id])
            for connection in connections_to_send:
                try:
                    await connection.send_json(progress_update)
                except WebSocketDisconnect:
                    logger.info(f"WebSocket disconnected during send for scan_id: {scan_id}. Removing.")
                    # Handle disconnection here if not handled by a separate ping/pong or keepalive mechanism
                    # For simplicity, disconnect is primarily handled in the endpoint's except block
                    if connection in self.active_connections.get(scan_id, []):
                         self.active_connections[scan_id].remove(connection)
                         if not self.active_connections[scan_id]:
                             del self.active_connections[scan_id]
                except Exception as e:
                    logger.error(f"Error sending progress to WebSocket for scan_id {scan_id}: {e}")
        else:
            logger.debug(f"No active WebSocket connections for scan_id: {scan_id} to send progress.")

# Global instance of the connection manager
manager = ConnectionManager()
