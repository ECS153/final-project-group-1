## Instantiates database with user credentials and an empty messages table
from hashlib import sha256
import os
import sqlite3

FILE_NAME = "message.db"

## delete old db file
try:
    os.remove(FILE_NAME)
except:
    pass

## database data for the users table
## user, pass, salt
users= [
("llee", "eell", "154a0bd031e1a7f2"), 
("hepl", "fake123", "584ba914cd45ef67"), 
("bigboi", "hunter2", "1b5384ead392b93f"), 
("zman", "phatripz", "19fe356ab458e1ab")]

## instantiate users table and add values
conn = sqlite3.connect(FILE_NAME)
c = conn.cursor()

c.execute('''CREATE TABLE users
             (user text, salt text, hash text)''')

## load credentials into database
for user in users:
    h = sha256((user[2]+user[1]).encode()).hexdigest()
    c.execute("INSERT INTO users (user, salt, hash) VALUES (?, ?, ?)", (user[0], user[2], h))

## create message table
## TODO: Add indexing fields
c.execute('''CREATE TABLE messages
             (sender text, receiver text, message text, isSent int, sent int)''')
conn.commit()
c.close()
