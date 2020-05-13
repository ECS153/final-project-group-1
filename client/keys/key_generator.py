# Used to generate public private keys for each user, store in file
from Crypto.PublicKey import RSA

users = ["llee", "zman", "hepl", "bigboi"]

for user in users:
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()   
    private_pem = private_key.exportKey().decode()
    public_pem = public_key.exportKey().decode()
    with open("private_"+user+".pem", 'w') as f:
        f.write(private_pem)
    with open("public_"+user+".pem", 'w') as f:
        f.write(public_pem)
