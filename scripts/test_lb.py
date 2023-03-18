import requests, sys

if len(sys.argv) == 2:
    request_count = int(sys.argv[1])
else:
    request_count = 100


for i in range(1, request_count + 1):
    print("sending a get request")
    requests.get("http://127.0.0.1:8000/products")
    print(f"{i} requests out of {request_count} were sent")