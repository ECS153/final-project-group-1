from merkle_tree import MerkleTree
from time import time

class _node:
    """
    Private class that defines data in a Blockchain node
    """
    def __init__(self, messages, nonce, prev_blk_hash)
        """
        Args:
        messages: the messages to be added to the tree
        nonce: appended to end of messages to generate appropriate blockchain
        hash. 
        prev_blk_hash: The hash of the previous block
        """
        self.merkle_root      = MerkleTree(messages)
        self.prev_block_hash  = prev_blk_hash
        self.nonce            = nonce
        self.time_stamp       = time
        self.nxt              = None


class Blockchain:
    """
    Simple blockchain implementation using a singly linked list. Supports block
    insertion and verification of a message based on its index.
    """

    ## TODO: Add fields to the constructor
    ## NOTE: Make sure that when the class it constructed that you are creating
    ## a default block an inserting it.
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
        
    def get_hash_latest_block():
        """
        Returns the hash of the most recent block in the chain.

        Construct SHA-256 hash of the concatenation of the most recent block's
        prev_block_hash + merkle_root + nonce

        Return:
        Hash of prev_block_hash + merkle_root + nonce
        """
        return ""
