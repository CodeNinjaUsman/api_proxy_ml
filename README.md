# Api Proxy ML Based
Run the code:
```
cd api_proxy_ml
python manage.py runserver
```
Send data like this:
```
{"Request":"GET HTTP/1.1", "AcceptHdr":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8","Encoding":"gzip, deflate, br", "Lang":"en-US,en;q=0.5", "Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36", "Cookie":"PHPSESSID=abcdef1234567890; userID=1234; cartID=abcd|1234; lang=en", "Cdata": "10001", "Clength":"300", "URL":"https://www.google.com/../../../etc/pwd"}
```
Python:
```
import requests
import json

url = "http://127.0.0.1:8000/"

payload = json.dumps({
  "Request": "GET HTTP/1.1",
  "AcceptHdr": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8",
  "Encoding": "gzip, deflate, br",
  "Lang": "en-US,en;q=0.5",
  "Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
  "Cookie": "PHPSESSID=abcdef1234567890; userID=1234; cartID=abcd|1234; lang=en",
  "Cdata": "10001",
  "Clength": "300",
  "URL": "https://www.google.com/../../../etc/pwd"
})
headers = {
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
```
