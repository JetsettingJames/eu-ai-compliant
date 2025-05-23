import asyncio
import websockets
import requests
import json
import os

FASTAPI_BASE_URL = os.getenv("FASTAPI_URL", "http://127.0.0.1:8000")
API_V1_PREFIX = "/api/v1"
# Using a small, well-known repo for testing. Replace if you have a preferred one.
REPO_TO_SCAN = "https://github.com/octocat/Spoon-Knife"

async def test_scan_websockets():
    print(f"FastAPI Base URL: {FASTAPI_BASE_URL}")
    print(f"Initiating scan for: {REPO_TO_SCAN}\n")
    
    scan_endpoint = f"{FASTAPI_BASE_URL}{API_V1_PREFIX}/graph-scan/"
    
    try:
        # 1. Initiate the scan via HTTP POST
        print(f"Sending POST request to: {scan_endpoint}")
        response = requests.post(
            scan_endpoint,
            json={"repo_url": REPO_TO_SCAN}
        )
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        scan_init_data = response.json()
        scan_id = scan_init_data.get("scan_id")
        ws_path = scan_init_data.get("websocket_url")

        if not scan_id or not ws_path:
            print("Error: Could not get scan_id or websocket_url from response.")
            print(f"Response Data: {scan_init_data}")
            return

        print(f"Scan initiated successfully.")
        print(f"  Scan ID: {scan_id}")
        print(f"  WebSocket Path: {ws_path}\n")

        # 2. Connect to the WebSocket endpoint
        # Construct the full WebSocket URL (ws:// or wss://)
        ws_scheme = "ws" if FASTAPI_BASE_URL.startswith("http://") else "wss"
        ws_host = FASTAPI_BASE_URL.split("://")[1]
        full_ws_url = f"{ws_scheme}://{ws_host}{ws_path}"
        
        print(f"Connecting to WebSocket: {full_ws_url}")
        async with websockets.connect(full_ws_url) as websocket:
            print("WebSocket connection established. Waiting for messages...\n")
            
            # 3. Listen for messages
            try:
                while True:
                    message_str = await websocket.recv()
                    try:
                        message = json.loads(message_str)
                        print(f"[PROGRESS] Status: {message.get('status')}, Detail: {message.get('detail', 'N/A')}")
                        if message.get('data'):
                            print(f"           Data: {json.dumps(message.get('data'))}")
                        
                        # Check for completion or error status to terminate
                        if message.get("status") == "completed" or message.get("status") == "error":
                            print("\nScan finished or errored based on WebSocket message.")
                            if message.get("status") == "completed" and message.get('data', {}).get('tier'):
                                print(f"Final Tier: {message['data']['tier']}")
                            elif message.get("status") == "error" and message.get('data', {}).get('error_details'):
                                print(f"Error Details: {message['data']['error_details']}")
                            break
                    except json.JSONDecodeError:
                        print(f"Received non-JSON message: {message_str}")
                        
            except websockets.exceptions.ConnectionClosedOK:
                print("\nWebSocket connection closed by server (gracefully).")
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"\nWebSocket connection closed with error: {e}")
            except Exception as e:
                print(f"\nError during WebSocket communication: {e}")

    except requests.exceptions.HTTPError as e:
        print(f"HTTP request failed with status {e.response.status_code}: {e.response.reason}")
        try:
            error_details = e.response.json()
            print(f"Error details: {error_details.get('detail') or e.response.text}")
        except json.JSONDecodeError:
            print(f"Response content: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    print("--- WebSocket Scan Test Client ---")
    print("Ensure your FastAPI server (main.py) is running.")
    print("Required libraries: 'requests', 'websockets' (pip install requests websockets)")
    print("Ensure OPENAI_API_KEY environment variable is set for the FastAPI server.\n")
    
    # Example: For testing with a local server that might not be 127.0.0.1
    # You can set FASTAPI_URL in your environment if needed, e.g.:
    # export FASTAPI_URL=http://localhost:8000
    
    asyncio.run(test_scan_websockets())
