class MerkleTree:
    """
    Hash tree that uses SHA-256 to hash messages together. Allows for quick 
    verification of records. NOTE: Expects to hash blocks of 16 messages at a 
    time.
    """

    def __init__(messages, block_hash, prev_merkle_root):
        """
        Constructs Merkle Tree with the following messages, using the 
        concatenation of block_hash and prev_merkle_root as the key.

        Args:
        messages: list of 16 messages used to build block.
        block_hash: the hash that was computed by hash generator
        """


    def verify(msg, idx):
        """

        """
