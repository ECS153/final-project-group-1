from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from hashlib import sha256
import sqlite3
import json

PORT = 5001


class BlockchainClientHandler(BaseHTTPRequestHandler):
    """

    """

    def get_unread_messages(self, user, contact):
        conn = sqlite3.connect("message.db")
        c = conn.cursor()

        sql_read_query = """SELECT * FROM messages WHERE
                                receiver=?
                                AND sender=? 
                                AND isSent=?"""

        c.execute(sql_read_query, (user, contact, 0))
        data = c.fetchall()

        # turn data into list of dictionary
        for i in range(len(data)):
            data[i] = {
                "timestamp": data[i][4],
                "sender": data[i][0],
                "message": data[i][2]
            }

        # sort by timestamp ascending value
        length = len(data)
        j = 0
        while j < length - 1:
            if data[j]["timestamp"] > data[j + 1]["timestamp"]:
                temp = data[j]
                data[j] = data[j + 1]
                data[j + 1] = temp
                j = -1
            j += 1

        sql_update_query = """Update messages SET isSent=1 WHERE
                                receiver=?
                                AND sender=? 
                                AND isSent=?"""

        c.execute(sql_update_query, (user, contact, 0))
        conn.commit()
        c.close()
        conn.close()

        return json.dumps(data)

    def get_history(self, user, contact):
        conn = sqlite3.connect("message.db")
        c = conn.cursor()

        sql_read_query = """SELECT * FROM messages WHERE
                                        receiver=?
                                        AND sender=?"""

        c.execute(sql_read_query, (user, contact))
        data_user = c.fetchall()

        c.execute(sql_read_query, (contact, user))
        data_contact = c.fetchall()

        data = data_user + data_contact

        for i in range(len(data)):
            data[i] = {
                "timestamp": data[i][4],
                "sender": data[i][0],
                "message": data[i][2]
            }

        length = len(data)
        j = 0
        while j < length - 1:
            if data[j]["timestamp"] > data[j + 1]["timestamp"]:
                temp = data[j]
                data[j] = data[j + 1]
                data[j + 1] = temp
                j = -1
            j += 1

        c.close()
        conn.close()

        return json.dumps(data)

    def authenticate_password(self, user, password):
        conn = sqlite3.connect("message.db")
        c = conn.cursor()

        my_salt = c.execute("SELECT salt FROM users WHERE user=?", user)
        my_hash = c.execute("SELECT hash FROM users WHERE user=?", user)
        c.close()
        conn.close()

        made_hash = sha256((my_salt + password).encode()).hexdigest()

        if made_hash == my_hash:
            return False

        return True

    def do_GET(self, r):
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
        contact = r.headers['contact']
        unread = r.headers['contact']
        password = r.headers['password']

        if self.authenticate_password(user, password):
            print("Error: wrong password")
            return

        if unread:
            response = self.get_unread_messages(user, contact)
        else:
            response = self.get_history(user, contact)

        r.wfile.write(bytes(response, "utf8"))

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
