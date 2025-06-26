# Setup & Installation

## Protected Login Server

```bash
# In the root directory
npm install
node server.js
```

The server will run locally (default port usually 3000 or 5000) exposing the `/login` endpoint.

## Running the Brute-force Script

To run the brute-force script properly, it needs to reach your server from outside your local machine.

You have two options:

### 1. Using ngrok to expose your local server

Run ngrok with your local IP and port to create a public URL accessible from anywhere:

```bash
ngrok http 192.168.1.50:5000
```

Replace `192.168.1.50` with your actual local IP address and `5000` with your server's port.

Ngrok will provide a public URL, for example:

```
http://abcd1234.ngrok.io
```

Use this URL in the brute-force script:

```python
URL = "http://abcd1234.ngrok.io/login"
```

### 2. Using your local IP address and port directly (Local Network Only)

If you want to run the brute-force script on a device connected to the same local network as your server, you can set the URL to your local IP and port:

For example, if your local IP (found via `ipconfig` on Windows or `ifconfig` / `ip addr` on Linux) is `192.168.1.50` and your server runs on port `5000`, set:

```python
URL = "http://192.168.1.50:5000/login"
```

Make sure your firewall/router allows access to that port and that the device running the brute-force script is connected to the same network.

## Brute-force Script Setup

Make sure Tor is installed and running with SOCKS port 9050 and Control port 9051 configured.

```bash
cd Bruteforce
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Edit `brute_force_tor.py` to set the URL as explained above.

Run the brute-force simulation:

```bash
python brute_force_tor.py
```

## AWS Lambda Function

Deploy the contents of the `Lambda/` folder to AWS Lambda using your preferred method (AWS Console, CLI, or Infrastructure as Code).

Ensure dependencies and environment variables are configured as needed.

## Important Notes

- The brute-force script generates passwords of length 1-4 using lowercase letters (a-z). Modify `generate_passwords()` to change this behavior.
- The IP rotation (`renew_tor_ip()`) requires Tor configured to accept the NEWNYM signal on the control port.
- The protected server uses basic protections and is not intended for production use.
- Always use this project responsibly and only on systems you own or have explicit permission to test.

## Legal Warning

⚠️ **Unauthorized testing or use against systems you do not own or have permission to test is illegal and may lead to legal consequences. Use only in controlled, authorized environments.**

## Additional Documentation

A detailed PDF document with more information about the project is included in the root directory. Please refer to this PDF for extended explanations and guidance.

## License

MIT License

## Contact

For questions or contributions, feel free to open issues or pull requests.

**Author:** Nicolò Marotta  
**Date:** 2025