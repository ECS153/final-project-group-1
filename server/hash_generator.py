from hashlib import sha256
from random import randrange


def generate_hash(prev_block_hash, merkle_root, num_starting_0s):
    """
    Creates a nonce for the block that is to be published to the blockchain.

    To make block chain secure, generating hashes needs to be difficult. This
    function will hash the string prev_block_hash+merkle_root+nonce
    until the hash produced using SHA-256 starts with num_starting_0s. The nonce is simply
    a number appended to the end of the string.

    Args:
    prev_block_hash: This is the merkle root of the previously hashed block
    merkle_root: Merkle root construted
    num_starting_0s: How many zeroes the hash needs to start with

    Return:
    The nonce such that SHA156.Hash(prev_block_hash+merle_root+nonce).Hex()
    starts with num_starting_0s 0s.
    """
    nonce = str(randrange(0, 300001))
    hash_string = prev_block_hash + merkle_root + nonce
    my_hash = sha256(hash_string.encode('utf-8')).hexdigest()
    num_zeros = make_zeros_str(num_starting_0s)

    if my_hash.startswith(num_zeros):
        return nonce
    else:
        return generate_hash(prev_block_hash, merkle_root, num_starting_0s)


def make_zeros_str(num_zero):
    value = ""
    for x in range(num_zero):
        value = value + "0"
    return value
