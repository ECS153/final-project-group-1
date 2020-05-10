from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

PORT = 5001

class BlockchainClientHandler(BaseHTTPRequestHandler):
    """

    """
    def do_GET(r):
        r.send_response(200)
        r.end_headers()
        r.wfile.write(b"No messages yet.")

    def do_PUT(r):
        print("Sender: "+r.headers["sender"])
        print("Receiver: "+r.headers["receiver"])
        print("Password: "+r.headers["password"])
        print("Message: "+str(r.rfile.read(int(r.headers["content-length"]))))
        r.send_response(200)
        r.end_headers()
        r.wfile.write(b"Received all the headers!")

def main():
    """
    Instantiates server, runs it indefinitely.
    """
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, BlockchainClientHandler)
    httpd.serve_forever()

main()
