## Simple program to test how server handles requests
import requests

headers = {"sender": "zman", "receiver": "llee", "password": "abc123"}

URL = "http://127.0.0.1:5001"

print("Test HTTP GET")
r = requests.get(URL)
print(r.content+"\n")

print("TEST HTTP PUT")
r= requests.put("http://127.0.0.1:5001", 
    data="Stand in message",
    headers=headers)
print(r.content)
