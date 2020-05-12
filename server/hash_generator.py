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

    while check_zeros(my_hash, num_starting_0s):
        nonce = str(randrange(0, 300001))
        hash_string = prev_block_hash + merkle_root + nonce
        my_hash = sha256(hash_string.encode('utf-8')).hexdigest()

    return nonce


# function to check condition for while loop
def check_zeros(my_hash, num_zero):

    if num_zero >= len(my_hash):
        print("Error: too many zeros wanted")
        return False

    for x in range(num_zero):
        if my_hash[x] != "0":
            return True

    if my_hash[num_zero] == "0":
        return True

    return False
