## Demo of how message integrity works

from hashlib import sha256                                                      
import os                                                                       
import sqlite3 as s3
from load_test_data import load_merkle_chain

merkle_chain = load_merkle_chain()

## Now we take the role of a hacker...
conn = s3.connect("demo.db")
c = conn.cursor()

## Gonna alter one of Bob's messages...

query = "UPDATE messages set msg = 'Time to rob a bank!' WHERE msg = 'Peace'"   
c.execute(query)
conn.commit()

## Bob is going to prison if we don't prove his message was altered
saving_query = "SELECT blk_idx, merk_idx FROM messages WHERE msg = 'Time to rob a bank!'"
blk_idx, merk_idx = c.execute(saving_query).fetchone()   

notAltered = merkle_chain.verify("Time to rob a bank!", blk_idx, merk_idx)

if notAltered:
    print("Bob posted it! Send him to the pound!")
else:
    print("He's been framed!")

## let's see if it also verifies the original message
original = merkle_chain.verify("Peace", blk_idx, merk_idx)

if original:
    print("He was just saying peace!")                                 
