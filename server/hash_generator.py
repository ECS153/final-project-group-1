def generate_hash(prev_block_hash, msgs, num_starting_0s):
    """
    Creates a nonce for the block that is to be published to the blockchain.

    To make block chain secure, generating hashes needs to be difficult. This 
    function will hash the string pre_block_hash+msgs+nonce until the hash 
    produced using SHA-256 starts with num_starting_0s. The nonce is a simply
    a number appended to the end of the string.

    Args:
    prev_block_hash: This is the merkle root of the previously hashed block
    msgs: A list of messages to be added to the block
    num_starting_0s: How many zeroes the hash needs to start with

    Return:
    The nonce such that SHA156.Hash(prev_block_hash+msgs+nonce) starts with
    num_starting_0s 0s.
    """

    return 0
