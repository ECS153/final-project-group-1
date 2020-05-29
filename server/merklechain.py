from merkletree import MerkleTree
from hashlib import sha256
from hashgenerator import generate_hash

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

    def get_latest_block_hash(self):
        """
        Constructs and returns SHA-256 hash of current leading node. 
        """
        return sha256((self.last.prev_hash + 
                      self.last.tree.get_merkle_root() + 
                      str(self.last.nonce)).encode()).hexdigest()

    def verify(self, msg, blk_idx, merk_idx):
        """
        Calls merkle tree's verify at blk_idx to see if message was altered
        """
        ## iterate to correct idx
        if blk_idx > self.latest_block_idx or merk_idx > 7:
            return False
        node = self.first
        for _ in range(0, blk_idx):
            node = node.nxt

        return node.tree.verify(msg, merk_idx)      


def merkle_test():
    m = MerkleChain()

    b1 = ["Hey!", "Hi!", "How are ya?", "Not bad!", "Cool!", "School good?", "Yes!", "Aight Imma head out"]
    b2 = ["My life is a lie", "The void grows bigger." ,"I smell pennies", "Hmmm yes", "Enslaved water?", "Yes indeed", "Big yums", "Lovely"]
    b3 = ["Oof", "No", "Ah yes", "Ahhh no", "Big oofs", "No oofs here", "Stop", "go"]
    blocks = [b1, b2, b3]
    for i in range(0, len(blocks)):
        ## cons nonce
        prev_hash = m.get_latest_block_hash()
        root = MerkleTree(blocks[i]).get_merkle_root()
        nonce = generate_hash(prev_hash, root, 3)
        ## add entry
        m.insert(blocks[i], nonce)
        assert m.latest_block_idx == i + 1
        print(m.get_latest_block_hash())
    
    ## run some test cases against blocks
    assert m.verify("Hey!", 1, 0)
    assert not m.verify("Ah yes", 3, 1)
    assert m.verify("Ah yes", 3, 2)
    assert m.verify("The void grows bigger.", 2, 1)
    assert m.verify("Aight Imma head out", 1, 7)
    assert not m.verify("Oofie", 3, 0)
