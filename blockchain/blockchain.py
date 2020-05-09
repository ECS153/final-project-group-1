from merkle_tree import MerkleTree

class _node:
    """
    Private class that defines data in a Blockchain node
    """
    def __init__(messages, block_hash):
        """
        Args:
        Messages = 
        """
        tree = MerkleTree(messages, block_hash)
        nxt = None


class Blockchain:
    """
    Simple blockchain implementation using a linked list. Supports block
    insertion and verification of a message based on its index.
    """

    ## TODO: Add fields to the constructor
    def __init__():
        pass


    
    def insert(messages, block_hash):
        """
        Inserts a block into the blockchain.

        Creates new node and inserts into the blockchain structure. Will create
        a new merkle tree instance for its node, using the messages.

        Args:
        messages: A list of 16 messages that will be hashed, stored in tree,
        and added to blockchain.
        block_hash: Hash string that will be used as a key to hash the messages
        in the merkle tree.
        """
        pass

    def verify(msg, blk_idx, msg_idx):
        """
        Verifies if a message has been tampered or not.

        Iterates across chain to node of index blk_idx, and calls verify 
        method of the node's merkle tree. Returns that value.

        Return:
        True if message has not been tampered, false otherwise.
        """
        return True
        
        



