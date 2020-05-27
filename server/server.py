from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from hashlib import sha256
import sqlite3
import time

PORT = 5001

class BlockchainClientHandler(BaseHTTPRequestHandler):
    """

    """
    def do_GET(r):
        r.send_response(200)
        r.end_headers()
        r.wfile.write(b"No messages yet.")

    def do_PUT(r):
        sender = r.headers["sender"]
        receiver = r.headers["receiver"]
        message = str(r.rfile.read(int(r.headers["content-length"])))
        print("Sender: "+sender)
        print("Receiver: "+receiver)
        print("Password: "+r.headers["password"])
        print("Message: "+message)
        r.send_response(200)
        r.end_headers()
        r.wfile.write(b"Received all the headers!")

        # "sent" tracks when the server received the message.
        # This will be useful for ordering message history.
        sent = time.time()
        # Query the message table
        conn = sqlite3.connect('message.db')
        c = conn.cursor()
        with conn:
            c.execute("INSERT INTO messages VALUES \
            (:sender, :receiver, :message, :isSent, :sent)",
            {'sender': sender, 'receiver': receiver,
            'message': message, 'isSent': 0, 'sent': sent})
        print("Printing what was inputting in the db: "+c.fetchall())
        conn.commit()
        conn.close()

    def authenticate(r):
        sender = r.headers["sender"]
        password = r.headers["password"]
        # Query the users table.
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        with conn:
            # Gather the rows of users so we have access to the salt & hash.
            c.execute("SELECT * FROM users")
            users = c.fetchall()
            for user in users:
                # Hash the given password just like we did when we
                # generated the hashes upon initialization.
                newh = sha256((user[2]+password).encode()).hexdigest()
                # Attempt to match the sender and password with the user
                # and password in the database.
                c.execute("SELECT * FROM users WHERE user= ? and password= ?",
                (sender, newh))
                found = c.fetchone()
                if found:
                    conn.close
                    return True
            # Found never returned true
            conn.close
            return False

def main():
    """
    Instantiates server, runs it indefinitely.
    """
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, BlockchainClientHandler)
    httpd.serve_forever()

main()
