import sqlite3
from os import remove
from hashgenerator import generate_hash
from merklechain import MerkleChain
from merkletree import MerkleTree

def load_merkle_chain():
    FILE_NAME = "demo.db"                                                                                       
                     
    try:
        remove(FILE_NAME)
    except:
        pass
                                                           
    ## instantiate users table and add values                                       
    conn = sqlite3.connect(FILE_NAME)                                               
    c = conn.cursor()
                                                                                
    ## create message table                                                                                                           
    c.execute('''CREATE TABLE messages                                              
             (sender text, receiver text, msg text, blk_idx int, merk_idx int)''')
    conn.commit()   

    msges = [
        ("Bob", "Alice", "Hi!",                          1, 0),
        ("Alice", "Bob", "Hey!",                         1, 1),
        ("Bob", "Alice", "How are ya!",                  1, 2),
        ("Alice", "Bob", "Doing good!",                  1, 3),
        ("Bob", "Alice", "School been fine?",            1, 4),
        ("Alice", "Bob", "Meh. I miss going outside",    1, 5),
        ("Bob", "Alice", "Same fam.",                    1, 6),
        ("Alice", "Bob", "At least we're graduating.",   1, 7),
        ("Bob", "Alice", "Very true.",                   2, 0),
        ("Alice", "Bob", "I gotta dip tho.",             2, 1),
        ("Bob", "Alice", "All good, talk to you later!", 2, 2),
        ("Alice", "Bob", "See ya!",                      2, 3),
        ("Bob", "Alice", "Also",                         2, 4),
        ("Alice", "Bob", "What?",                        2, 5),
        ("Bob", "Alice", "Nothin'. Peace!",              2, 6),
        ("Alice", "Bob", "Peace",                        2, 7)
    ]

    for msg in msges:
        c.execute('''INSERT INTO messages (sender, receiver, msg, blk_idx, merk_idx) VALUES(?, ?, ?, ?, ?)''', msg)
    conn.commit()
    c.close()
    blk1 = [msges[i][2] for i in range(0, 8)]
    blk2 = [msges[i][2] for i in range(8, 16)]    

    c = MerkleChain()
    prev_hash = c.get_latest_block_hash()
    nonce = generate_hash(prev_hash, MerkleTree(blk1).get_merkle_root(), 4)
    c.insert(blk1, nonce)
    prev_hash = c.get_latest_block_hash()
    nonce = generate_hash(prev_hash, MerkleTree(blk2).get_merkle_root(), 4)
    c.insert(blk2, nonce)
    return c
