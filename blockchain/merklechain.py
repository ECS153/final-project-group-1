from merkletree import MerkleTree
from hashlib import sha256

class _node:
    def __init__(self, messages, prev_hash, nonce):
        self.tree = MerkleTree(messages)
        self.prev_hash = prev_hash
        self.nonce = nonce
        self.nxt = None

class MerkleChain:
    def __init__(self):
        ## construct root node using a default set of messages and precomputed nonce
        default_msges = ["abgh", "1", "asd", "153", "153", "190", "100", "190"]
        self.first = _node(default_msges, "", 1000)
        self.last = self.first
        self.latest_block_idx = 0
    
    def insert(self, messages, nonce):
        ## TODO: Get hash of latest block
        self.last.nxt = _node(messages, "", nonce)
        self.last = self.last.nxt
        self.latest_block_idx += 1
        return self.latest_block_idx

    def getLatestBlockHash():
        return sha256(self.prev_hash + self.last.tree.getMerkleRoot() + str(self.nonce))

m = MerkleChain()
for i in range(0, 10):
    m.insert([str(i)], i+1)

node = m.first
while node is not None:
    print(node.nonce)
    node = node.nxt
