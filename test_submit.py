import requests
import json

BASE_URL = 'http://localhost:5000'
USERNAME = 'testuser'
PASSWORD = 'testpassword123'

session = requests.Session()

# 1. Obtain a CSRF token via the API endpoint (no login required).
#    The session cookie is set here and reused for the login POST,
#    so the token is valid for the form submission.
csrf_token = session.get(f'{BASE_URL}/api/csrf-token').json()['csrf_token']

# 2. Log in, including the CSRF token in the form data
login = session.post(f'{BASE_URL}/login', data={
    'username': USERNAME,
    'password': PASSWORD,
    'csrf_token': csrf_token,
})
if login.status_code not in (200, 302):
    print(f"Login failed (status {login.status_code})")
    exit(1)
print(f"Login status: {login.status_code}")

# 3. Submit scan results (endpoint is @csrf.exempt so no CSRF token needed)
with open('misconfigured-scan-working.json') as f:
    scan_data = json.load(f)

response = session.post(
    f'{BASE_URL}/api/scan-results',
    json=scan_data,
    headers={'Content-Type': 'application/json'},
)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
