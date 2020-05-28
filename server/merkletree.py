from hashlib import sha256
from math import log

class MerkleTree:
    """
    Array based merkle tree implementation. Can be adjusted for larger block 
    sizes (powers of 2). Allows for quick verification of message given it's 
    array index when passed into the tree constructor
    """
    ## number of messages must be power of 2
    _NUM_NODES = 2**3    
    ## Array size based on number of messages allowed
    _ARRAY_SIZE = 2**(3+1) - 1

    def __init__(self, messages):
        """
        Checks that correct number of messages are passed in, then constructs 
        tree.
        """
        if (len(messages) != 8):
            print("This implementation requires block size of",MerkleTree._NUM_NODES, "messages!")
            return
        self.tree = self._construct_tree(messages)

    def _construct_tree(self, messages):
        """
        Creates a merkle tree from the array of messages.

        Creates array of hashes that represent merkle tree based on messages 
        passed in. Hashes are computed using SHA256.

        Args:
        messages: grouping of messages to be hashed and used as leaves of the
        merkle tree

        Return:
        (List) containing all the hashes, where for parent at index i, it's left 
        child is at index 2i + 1 and it's right child at index 2i + 2
        """
        tree = [""] * MerkleTree._ARRAY_SIZE
        offset = MerkleTree._NUM_NODES - 1
        msg_in_row = (MerkleTree._ARRAY_SIZE + 1) // 2
        
        ## first add hashes based on messages passed in
        for i in range(offset, offset + msg_in_row):
            tree[i] = sha256(messages[i-offset].encode()).hexdigest()
        msg_in_row /= 2
        offset -= msg_in_row
        while msg_in_row > 0:
            for i in range(int(offset), int(offset + msg_in_row)):
                tree[i] = sha256((tree[2*i+1]+tree[2*i+2]).encode()).hexdigest()
            msg_in_row /= 2
            offset -= msg_in_row
        print(tree)
        return tree

    def get_merkle_root(self):
        """
        Returns the root hash of the tree, which is constructed from the hashes
        of every other node in the tree.

        Return:
        (str) Root hash of merkle tree
        """
        return self.tree[0]

    def verify_message(self, message, index):
        """
        Uses index to check if message matches tree or not.

        Uses index of the message in the array that was passed into the 
        tree constructor.

        Args:
        message (str): message to be verified
        index (int): message's location in the array when tree constructed

        Return:
        True if hash matches, false otherwise. False implies message was 
        altered.
        """
        index += MerkleTree._NUM_NODES - 1
        depth = int(log(MerkleTree._ARRAY_SIZE + 1, 2))

        ## create hash and test against tree
        message_hash = sha256(message.encode()).hexdigest()
        parent = int((index - 1)/2 if index % 2 == 1 else (index - 2) / 2)
        print("PARENT:", parent)
        print("MESSAGE HASH:",message_hash)
        child1 = self.tree[2*parent + 1] if index % 2 == 0 else message_hash
        child2 = self.tree[2*parent + 2] if index % 2 == 1 else message_hash
        print(self.tree[parent])
        print("LEFT:",child1)
        print("RIGHT:", child2)
        print(sha256((child1 + child2).encode()).hexdigest())
        if self.tree[parent] != sha256((child1 + child2).encode()).hexdigest():
            print("MATCH FAILED AT PARENT:",parent)
            return False

        ## go up rest of tree to verify
        for _ in range(0, depth - 2):
            print("INDEX: ",index)
            ## get parent index based on whether child is left or right
            parent = int(((index - 1)/2 if index % 2 == 1 else (index - 2) / 2) if index != 0 else 0)
            ## see if hashes match
            print("PARENT:", parent)
            child1 = self.tree[2*parent + 1]
            child2 = self.tree[2*parent + 2]
            print("CHILDREN:", 2*parent + 1, 2*parent + 2)
            print(self.tree[parent])
            print(sha256((child1 + child2).encode()).hexdigest())
            if self.tree[parent] != sha256((child1 + child2).encode()).hexdigest():
                print("MATCH FAILED AT PARENT:",parent)
                return False
            index = parent
        return True

## TEST CODE
#messages = ["abc", "def", "ghi", "jkl", "mno", "pqr", "stu", "vwx"]

#t = MerkleTree(messages)

#if t.verify_message("abc", 0):
#    print("Passed")

#if not t.verify_message("jkle", 7):
#    print("Also passed!")

