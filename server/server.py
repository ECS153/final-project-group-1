from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
import sqlite3

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

        conn = sqlite3.connect('message.db')
        c = conn.cursor()
        with conn:
            c.execute("INSERT INTO messages VALUES \
            (:sender, :receiver, :message, :isSent)",
            {'sender': sender, 'receiver': receiver,
            'message': message, 'isSent': 0})
        print("Printing what was inputting in the db: "+c.fetchall())
        conn.commit()
        conn.close()

def main():
    """
    Instantiates server, runs it indefinitely.
    """
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, BlockchainClientHandler)
    httpd.serve_forever()

main()
