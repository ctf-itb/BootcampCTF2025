import httpx

BASE_URL = "http://localhost:8115/"

res = httpx.post(
    BASE_URL,
    headers={"Content-Type": "text/plain"},
    content='\ufeff{"plisssakumauflaggratisss": true}',  # UTF-8 BOM
)

print(res.text)