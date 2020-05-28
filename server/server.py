from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from hashlib import sha256
import sqlite3
import json
import time
from hashgenerator import generate_hash
from merklechain import MerkleChain
from merkletree import MerkleTree

PORT = 5001


class MerkleChainClientHandler(BaseHTTPRequestHandler):
    """

    """

    chain = MerkleChain()

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

        return made_hash == my_hash

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
        contact = r.headers['contact']
        unread = r.headers['contact']
        password = r.headers['password']

        if not r.authenticate_password(user, password):
            print("Error: wrong password")
            return

        if unread:
            response = self.get_unread_messages(user, contact)
        else:
            response = self.get_history(user, contact)

        r.wfile.write(bytes(response, "utf8"))

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
        if not r.authenticate_password(sender, r.headers["password"]):
            print("Return password")
            return

        # "sent" tracks when the server received the message.
        # This will be useful for ordering message history.
        sent = time.time()
        # Query the message table
        conn = sqlite3.connect('message.db')
        c = conn.cursor()
        ## index our message
        blk_idx, merkle_idx = get_latest_msg_idx()
        with conn:
            c.execute("INSERT INTO messages VALUES \
            (:sender, :receiver, :message, :isSent, :sent)",
            {'sender': sender, 'receiver': receiver,
            'message': message, 'isSent': 0, 'sent': sent})
        print("Printing what was inputting in the db: "+c.fetchall())
        conn.commit()
        conn.close()

    
    def get_latest_msg_idx():
        conn = sqlite3.connect("message.db")
        c = conn.cursor()
        res = c.execute("SELECT merkle_idx FROM messages "+
                        "WHERE  blk_index = -1 ORDER BY merkle_idx DESC").fetchone()
        conn.close()
        if res[0] == 7:
            self.append_chain()
        else:
            return (-1, res[0] + 1)

    def append_chain():
        conn = sqlite3.connect("message.db")
        c = conn.cursor()
        res = c.execute("SELECT merkle_idx FROM messages "+
                        "WHERE  blk_index = -1 ORDER BY merkle_idx DESC")
        msgs = [r[i] for r in res]
        root = MerkleTree(msgs).get_merkle_root()
        prev_hash = MerkleChainClientHandler.chain.get_latest_block_hash()
        nonce = generate_hash(prev_hash, root, 3)
        return MerkleChainClientHandler.chain.insert(msgs, nonce)

def main():
    """
    Instantiates server, runs it indefinitely.
    """
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, MerkleChainClientHandler)
    httpd.serve_forever()

main()
