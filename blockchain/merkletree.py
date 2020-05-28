from hashlib import sha256
from math import log

class MerkleTree:
    _NUM_NODES = 8    
    _ARRAY_SIZE = 2**(3+1) - 1

    def __init__(self, messages):
        if (len(messages) != 8):
            print("This implementation requires block size of",MerkleTree._NUM_NODES, "messages!")
            return
        self.tree = self._construct_tree(messages)

    def _construct_tree(self, messages):
        tree = [""] * MerkleTree._ARRAY_SIZE
        offset = MerkleTree._NUM_NODES - 1
        msg_in_row = (MerkleTree._ARRAY_SIZE + 1) / 2
        
        ## first add hashes based on messages passed in
        for i in range(offset, offset + msg_in_row):
            tree[i] = sha256(messages[i-offset]).hexdigest()
        msg_in_row /= 2
        offset -= msg_in_row
        while msg_in_row > 0:
            for i in range(offset, offset + msg_in_row):
                tree[i] = sha256(tree[2*i+1]+tree[2*i+2]).hexdigest()
            msg_in_row /= 2
            offset -= msg_in_row
        print(tree)
        return tree

    def get_merkle_root(self):
        return self.tree[0]

    def verify_message(self, message, index):
        index += MerkleTree._NUM_NODES - 1
        depth = int(log(MerkleTree._ARRAY_SIZE + 1, 2))

        ## create hash and test against tree
        message_hash = sha256(message).hexdigest()
        parent = (index - 1)/2 if index % 2 == 1 else (index - 2) / 2
        print("PARENT:", parent)
        print("MESSAGE HASH:",message_hash)
        child1 = self.tree[2*parent + 1] if index % 2 == 0 else message_hash
        child2 = self.tree[2*parent + 2] if index % 2 == 1 else message_hash
        print(self.tree[parent])
        print("LEFT:",child1)
        print("RIGHT:", child2)
        print(sha256(child1 + child2).hexdigest())
        if self.tree[parent] != sha256(child1 + child2).hexdigest():
            print("MATCH FAILED AT PARENT:",parent)
            return False

        ## go up rest of tree to verify
        for _ in range(0, depth - 2):
            print("INDEX: ",index)
            ## get parent index based on whether child is left or right
            parent = ((index - 1)/2 if index % 2 == 1 else (index - 2) / 2) if index != 0 else 0
            ## see if hashes match
            print("PARENT:", parent)
            child1 = self.tree[2*parent + 1]
            child2 = self.tree[2*parent + 2]
            print("CHILDREN:", 2*parent + 1, 2*parent + 2)
            print(self.tree[parent])
            print(sha256(child1 + child2).hexdigest())
            if self.tree[parent] != sha256(child1 + child2).hexdigest():
                print("MATCH FAILED AT PARENT:",parent)
                return False
            index = parent
        return True

messages = ["abc", "def", "ghi", "jkl", "mno", "pqr", "stu", "vwx"]

t = MerkleTree(messages)

if t.verify_message("abc", 0):
    print("Passed")

if not t.verify_message("jkle", 7):
    print("Also passed!")

