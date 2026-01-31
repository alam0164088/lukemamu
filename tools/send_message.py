import requests
import argparse
import os
import json

DEFAULT_TOKEN = os.environ.get("JWT_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzk1NzIzMjczLCJpYXQiOjE3Njk4MDMyNzMsImp0aSI6ImYxYTk4YTM1ZGE5MDRmMjM4ZjM3OWMzNGM5ZjI0ZGE1IiwidXNlcl9pZCI6IjI4In0.xBdBq-WoOROwEgDubXtMkINcMZ8GV_DFm-TaXdxDSfc")

def send(host: str, port: int, consultation_id: int, token: str, content: str):
    url = f"http://{host}:{port}/api/attorney/consultations/{consultation_id}/messages/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    payload = {"content": content}
    r = requests.post(url, headers=headers, json=payload, timeout=10)
    try:
        print("STATUS", r.status_code, json.dumps(r.json(), ensure_ascii=False))
    except Exception:
        print("STATUS", r.status_code, r.text)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("HOST", "10.10.7.19"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8001)))
    p.add_argument("--consultation", type=int, required=True)
    p.add_argument("--token", default=DEFAULT_TOKEN)
    p.add_argument("--content", required=True)
    args = p.parse_args()
    send(args.host, args.port, args.consultation, args.token, args.content)