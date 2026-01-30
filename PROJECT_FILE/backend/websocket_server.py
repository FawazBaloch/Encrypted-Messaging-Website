# websocket_server.py
# Accepts already-encrypted messages/files from frontend and stores + forwards them

import asyncio
import websockets
import json
from database import store_message, store_file

ACTIVE_CLIENTS = {}  # { username: websocket }

async def handle_client(websocket, path):
    # Parse username from query
    try:
        params = dict(p.split("=") for p in websocket.path.split("?")[1].split("&"))
    except:
        await websocket.close()
        return

    username = params.get("username")
    if not username:
        await websocket.close()
        return

    print(f"[WS] {username} connected")
    ACTIVE_CLIENTS[username] = websocket

    try:
        async for packet in websocket:
            data = json.loads(packet)
            packet_type = data.get("type")

            # -------------------------
            # TEXT MESSAGE
            # -------------------------
            if packet_type == "message":
                sender = data["sender"]
                receiver = data["receiver"]

                encrypted_message = data["encrypted_message"]
                encrypted_aes_key = data["encrypted_aes_key"]
                iv = data["iv"]

                print(f"[WS][MSG] {sender} -> {receiver} | enc_msg={encrypted_message[:40]}... key={encrypted_aes_key[:40]}... iv={iv[:16]}...")

                store_message(sender, receiver, encrypted_message, encrypted_aes_key, iv)

                payload = json.dumps({
                    "type": "message",
                    "sender": sender,
                    "receiver": receiver,
                    "encrypted_message": encrypted_message,
                    "encrypted_aes_key": encrypted_aes_key,
                    "iv": iv
                })

                if receiver in ACTIVE_CLIENTS:
                    await ACTIVE_CLIENTS[receiver].send(payload)
                if sender in ACTIVE_CLIENTS:
                    await ACTIVE_CLIENTS[sender].send(payload)

            # -------------------------
            # FILE TRANSFER
            # -------------------------
            elif packet_type == "file":
                sender = data["sender"]
                receiver = data["receiver"]

                filename = data["filename"]
                mime_type = data["mime_type"]
                size_bytes = int(data["size_bytes"])
                sha256 = data["sha256"]

                encrypted_file = data["encrypted_file"]
                encrypted_aes_key_receiver = data["encrypted_aes_key_receiver"]
                encrypted_aes_key_sender = data["encrypted_aes_key_sender"]
                iv = data["iv"]

                print(f"[WS][FILE] {sender} -> {receiver} | {filename} ({size_bytes} bytes) sha256={sha256[:16]}... enc_file={encrypted_file[:30]}...")

                store_file(
                    sender, receiver,
                    filename, mime_type, size_bytes, sha256,
                    encrypted_file,
                    encrypted_aes_key_receiver,
                    encrypted_aes_key_sender,
                    iv
                )

                payload = json.dumps({
                    "type": "file",
                    "sender": sender,
                    "receiver": receiver,
                    "filename": filename,
                    "mime_type": mime_type,
                    "size_bytes": size_bytes,
                    "sha256": sha256,
                    "encrypted_file": encrypted_file,
                    "encrypted_aes_key_receiver": encrypted_aes_key_receiver,
                    "encrypted_aes_key_sender": encrypted_aes_key_sender,
                    "iv": iv
                })

                if receiver in ACTIVE_CLIENTS:
                    await ACTIVE_CLIENTS[receiver].send(payload)
                if sender in ACTIVE_CLIENTS:
                    await ACTIVE_CLIENTS[sender].send(payload)

            else:
                continue

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        ACTIVE_CLIENTS.pop(username, None)
        print(f"[WS] {username} disconnected")

async def main():
    print("🔥 WebSocket running ws://localhost:5001/ws")
    async with websockets.serve(handle_client, "0.0.0.0", 5001):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
