import argparse
import tqdm
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

argp = argparse.ArgumentParser(description='Program for creating mass amounts of RSA keys')

argp.add_argument('--count', type=int, help='Amount of keys to generate', default=5)
argp.add_argument('--size', type=int, choices=[1024, 2048, 4096], help='Key size to generate', required=True)
argp.add_argument('--outpub', help='File to output public keys to', required=True)
argp.add_argument('--outpriv', help='File to output private keys to', required=True)
argp.add_argument('--pwd', help='Password for private keys', required=True)

args = argp.parse_args()

pubs = {}
privs = {}
for x in tqdm.tqdm(range(args.count), unit='key'):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=args.size,
        backend=default_backend()
    )

    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.PKCS1
    )

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(args.pwd.encode('utf-8'))
    )

    private_key_str = pem.decode('utf-8')
    public_key_str = public_key.decode('utf-8')

    pubs.update({x: public_key_str})
    privs.update({x: private_key_str})

with open(args.outpub, 'w') as f: f.write(json.dumps(pubs, indent=4))
with open(args.outpriv, 'w') as f: f.write(json.dumps(privs, indent=4))
