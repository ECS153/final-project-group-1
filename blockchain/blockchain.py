## Baseline setup to communicate with the Ethereum blockchain, set up basic transaction uploads

from web3 import Web3

web3 = Web3(Web3.HTTPProvider(EthereiumTesterProvider()))

## Set up a blockchain transaction
account = "zman"

def uploadMessage(sender, receiver, message):
    private_key = "a01963817b1753e182c18618cabf3"
    tx = {
        'nonce': web3.eth.getTransactionCount(sender),
        'to': receiver,
        'value': message,
        'gas': 20000000,
        'gasPrice': web3.toWei('50', 'gwei')
    }
    signed_tx = web3.eth.account.signTransaction(tx, private_key)
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    return tx_hash


def verify(sender, receiver, message):
    return True
