import requests
import json

with open('test_scan.json') as f:
    scan_data = json.load(f)

response = requests.post(
    'http://localhost:5000/api/scan-results',
    json=scan_data,
    headers={'Content-Type': 'application/json'}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")