#Kaylyn King
#CSCE 3550
#kaylynking@my.unt.edu
#4/2/24
#Project 3
#I used base code from project 2 to complete this assignment
import os
import secrets
import sqlite3
import base64
import json
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import jwt
import uuid
import hashlib

hostName = "localhost"
serverPort = 8080

#encrypting AES logic
def encrypt_aes(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

#generating private rsa key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#serializing private rsa key
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

#AES encryption for RSA key using environment variable NOT_MY_KEY
os.environ['NOT_MY_KEY'] = '<new_key_create>'
key = os.environ.get('NOT_MY_KEY')
iv = os.urandom(16)
encrypted_key = encrypt_aes(pem, key.encode(), iv)

#generate numbers from private key for jwks
numbers = private_key.private_numbers()

#connect to database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
c = conn.cursor()

#create key table
c.execute('''CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
             )''')
#create users table
c.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash STEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP)
    ''')
#create auth_logs table
c.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,  
                FOREIGN KEY(user_id) REFERENCES users(id)
             )''')
conn.commit()

#set expiry
pem_expiry = (datetime.datetime.utcnow() + datetime.timedelta(hours=1))

#insert keys into table
c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_key, int(pem_expiry.timestamp())))
conn.commit()

#rate limiter variables
RATE_LIMIT_WINDOW = 1
RATE_LIMIT_REQUESTS = 10

#store request counts for each IP address
request_counts = {}

#converts integer into base64
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#set up class structure for server
class MyServer(BaseHTTPRequestHandler):
    #PUT endpoint
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    #PATCH end point
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    #DELETE endpoint
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    #HEAD endpoint
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    #POST endpoint
    def do_POST(self):
        #get path for post endpoint
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        #register path
        if parsed_path.path == "/register":
            #get and separate data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            username = data.get('username')
            email = data.get('email')

            #return error if username or email not found
            if not username or not email:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes(json.dumps({'error': 'Username and email are required'}), 'utf-8'))
                return
            
            #generate and hash user password
            generated_password = str(uuid.uuid4())
            password_bytes = generated_password.encode('utf-8')
            hashed_password = hashlib.sha256(password_bytes).hexdigest()

            #put user info into users table
            c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashed_password, email))
            conn.commit()

            #send response
            self.send_response(201)
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'password':generated_password}), 'utf-8'))
            return
        #auth path
        elif parsed_path.path == "/auth":
            #get and separate data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            username = data.get('username')
            user_id = 1

            #get ip address
            request_ip = self.client_address[0]

            #store request amount for each ip address
            if request_ip not in request_counts:
                request_counts[request_ip] = []

            #current time for system and user
            current_time = time.time()
            request_counts[request_ip] = [t for t in request_counts[request_ip] if t > current_time - RATE_LIMIT_WINDOW]
            
            #check if request count exceeds the limit
            if len(request_counts[request_ip]) >= RATE_LIMIT_REQUESTS:
                self.send_response(429)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(bytes("Too Many Requests", "utf-8"))
                return

            #add current request timestamp to the list
            request_counts[request_ip].append(current_time)

            #get time from system in format and stores in table auth_logs
            request_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                      (request_ip, request_timestamp, user_id))
            conn.commit()

            #auth jwt
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": int(pem_expiry.timestamp())
            }
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
        else:
            self.send_response(405)
            self.end_headers()

    #GET end point
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

#run server and closes database
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    conn.close()
    webServer.server_close()
