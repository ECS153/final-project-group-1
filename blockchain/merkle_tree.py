class MerkleTree:
    """
    Hash tree that uses SHA-256 to hash messages together. Allows for quick 
    verification of records. NOTE: Expects to hash blocks of 16 messages at a 
    time.
    """

    def __init__(messages):
        """
        Constructs Merkle Tree with the following messages, using the 
        concatenation of block_hash and prev_merkle_root as the key.

        Args:
        messages: list of 16 messages used to build block.
        """
        pass


    def verify(msg, idx):
        """
        Verifies a message at idx was not altered.

        Iterates up the merkle tree, hashing the messages up to the merkle root
        If matches are correct, returns True.

        Args:
        msg: Message to verify
        idk: Index of the message within the merkle tree

        Return:
        True if the message hasn't been altered. False otherwise.
        """
        pass
