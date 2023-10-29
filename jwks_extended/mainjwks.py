from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import sqlite3
import base64
import json
import jwt
import datetime

hostName = "localhost"
serverPort = 8080

DATABASE_NAME = "totally_not_my_privateKeys.db"

#connect to the db and create table
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
conn.commit()
conn.close()

#save the generated private keys to db
def save_key_to_db(key, expiration):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiration))
    conn.commit()
    conn.close()

#generate private keys, save them
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save_key_to_db(private_key, int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save_key_to_db(expired_key, int((datetime.datetime.utcnow() - datetime.timedelta(minutes=1)).timestamp()))

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return


    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            if 'expired' in params:
                cursor.execute("SELECT key FROM keys WHERE exp <= ?", (int(datetime.datetime.utcnow().timestamp()),))
            else:
                cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            row = cursor.fetchone()
            if not row:
                self.send_response(500)
                self.end_headers()
                return
            pem_key = row[0]
            conn.close()
            
            headers = {"kid": str(row[0])}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            valid_keys = cursor.fetchall()
            conn.close()
            
            keys = {"keys": []}
            for row in valid_keys:
                key = serialization.load_pem_private_key(row[0], None)
                numbers = key.private_numbers()
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(row[0]),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e)
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return



if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
