import os
import socket
import tmgr
import functools
import json
import base64

import sqprotolib as sqlib
from handler import sqhandler

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

class squab:
    class error:
        class InvalidMethodError(Exception): pass
        class InvalidPortError(Exception): pass

    def __init__(self, pvk_path, pbk_path):
        if(not os.path.exists(pvk_path)): raise FileNotFoundError(f'Private key list file not found at location {pvk_path}')
        if(not os.path.exists(pbk_path)): raise FileNotFoundError(f'Private key list file not found at location {pbk_path}')

        self.ident = sqlib.sqpacket.sqident.generate('server', 69)
        self.handler = sqhandler()
        self.cmgr = tmgr.clientmgr(self.handler, self.ident)

        self.pvk_path = pvk_path
        self.pbk_path = pbk_path

    def method(self, method):
        if(not isinstance(method, sqlib.sqpacket.flag)): raise self.error.InvalidMethodError(f'Method must be sqlib.sqpacket.flag, not {type(method).__name__}')
        def inner(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                pack: sqlib.sqpacket = kwargs['packet']
                response: tmgr.clientmgr.client._response_handler = kwargs['response']
                print(f'({func.__name__}){pack.src_ident.title}#{pack.src_ident.keyid} - {sqlib.sqpacket.flag(pack.flags).name} >> {pack.get_data() if pack.flags != sqlib.sqpacket.flag.SEC.value else "**hidden**"}')
                if(pack.flags == sqlib.sqpacket.flag.SEC.value):
                    stxt = pack.secure_text.decode()
                    with open(self.pvk_path, 'r') as f:
                        privkeys = json.loads(f.read())
                        if(pack.src_ident.keyid > 0):
                            if(str(pack.src_ident.keyid) not in privkeys):
                                response.send(0, f'Public key {pack.src_ident.keyid} not found in keychain')
                                return func(args, kwargs)
                            else:
                                key = privkeys[str(pack.src_ident.keyid)]
                                private_key = serialization.load_pem_private_key(
                                    key.encode('utf-8'),
                                    password=b'hello',
                                    backend=default_backend()
                                )

                                short = pack.secure_text.split(b'\0', 1)[0]
                                full = base64.b64decode(short)
                                decrypted = private_key.decrypt(
                                    full,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )

                                kwargs.update({'data': decrypted})

                res = func(*args, **kwargs)
                return res

            self.handler.register_method(sqhandler.method(method, wrapper))
            return wrapper
        return inner

    def main_loop(self, host: str = 'localhost', port: int = 7901):
        if(port < 1 or port > 65535): raise self.error.InvalidPortError(f'Port must be an integer ranging from 1 to 65535')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, port))
        sock.listen(5)

        try: 
            while True:
                conn, host = sock.accept()
                self.cmgr.register_connection(conn, host)

        except KeyboardInterrupt:
            print('exiting...')
            exit(1)
