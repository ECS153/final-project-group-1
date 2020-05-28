from merkletree import MerkleTree
from hashlib import sha256

class _node:
    """
    Node class that contains tree, prev_hash of block, nonce
    """
    def __init__(self, messages, prev_hash, nonce):
        self.tree = MerkleTree(messages)
        self.prev_hash = prev_hash
        self.nonce = nonce
        self.nxt = None

class MerkleChain:
    def __init__(self):
        """
        Adds first default block.
        """
        default_msges = ["abgh", "1", "asd", "153", "153", "190", "100", "190"]
        self.first = _node(default_msges, "", 1000)
        self.last = self.first
        self.latest_block_idx = 0
    
    def insert(self, messages, nonce):
        """
        Inserts message group into chain.

        Return:
        The index of the block the messages are placed into.
        """
        prev_hash = self.get_latest_block_hash()
        self.last.nxt = _node(messages, prev_hash, nonce)
        self.last = self.last.nxt
        self.latest_block_idx += 1
        return self.latest_block_idx

    def get_latest_block_hash():
        """
        Constructs and returns SHA-256 hash of current leading node. 
        """
        return sha256(self.last.prev_hash + 
                      self.last.tree.getMerkleRoot() + 
                      str(self.last.nonce))

#m = MerkleChain()
#for i in range(0, 10):
#    m.insert([str(i)], i+1)

#node = m.first
#while node is not None:
#    print(node.nonce)
#    node = node.nxt
