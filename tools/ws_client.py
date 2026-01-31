import asyncio
import json
import argparse
import os
import websockets

async def listen(uri: str, token: str | None):
    extra_headers = []
    if token:
        extra_headers = [("Authorization", f"Bearer {token}")]
    try:
        async with websockets.connect(uri, extra_headers=extra_headers) as ws:
            print("WS connected:", uri)
            async for message in ws:
                try:
                    obj = json.loads(message)
                    print("RECV:", json.dumps(obj, ensure_ascii=False))
                except Exception:
                    print("RECV (raw):", message)
    except Exception as e:
        print("WS error:", e)

def build_uri(host: str, port: int, path: str) -> str:
    if path.startswith("/"):
        path = path
    return f"ws://{host}:{port}{path}"

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Simple WS listener for consultations chat")
    p.add_argument("--host", default=os.environ.get("HOST", "10.10.7.19"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8001)))
    p.add_argument("--path", default="/ws/consultations/15/")
    # default token set as requested
    p.add_argument(
        "--token",
        default=os.environ.get("JWT_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzk1NzIzMjczLCJpYXQiOjE3Njk4MDMyNzMsImp0aSI6ImYxYTk4YTM1ZGE5MDRmMjM4ZjM3OWMzNGM5ZjI0ZGE1IiwidXNlcl9pZCI6IjI4In0.xBdBq-WoOROwEgDubXtMkINcMZ8GV_DFm-TaXdxDSfc")
    args = p.parse_args()
    uri = build_uri(args.host, args.port, args.path)
    asyncio.run(listen(uri, args.token or None))