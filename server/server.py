from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
import sqlite3

PORT = 5001

class BlockchainClientHandler(BaseHTTPRequestHandler):
    """

    """
    def do_GET(r):
        """
        arg: a get request

        checks for unread messages intended for the user in the database, the
        user's name is in the receiver attribute and isSent attribute is 0, and
        gives it back to the user in the response as a string with each
        individual message separated by a newline "/n".

        The messages that were "read" will have their isSent attribute in
        the database changed to 1.
        """
        r.send_response(200)
        r.end_headers()
        user = r.headers['user_name']
        conn = sqlite3.connect("message.db")
        c = conn.cursor()

        sql_read_query = """SELECT message FROM messages WHERE receiver=? 
                AND isSent=?"""

        c.execute(sql_read_query, (user, 0))
        data = c.fetchall()

        for i in range(len(data)):
            data[i] = data[i][0]

        sql_update_query = """Update messages SET isSent=1 WHERE receiver=? 
                AND isSent=?"""

        c.execute(sql_update_query, (user, 0))
        conn.commit()
        c.close()
        conn.close()

        messages: str = ""
        for msg in data:
            messages += msg + "\n"

        r.wfile.write(bytes(messages, "utf8"))

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
