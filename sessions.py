import logger
import json
import struct
import util
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

from datetime import datetime

import sqprotolib as sqlib

class session:
    def _gen_response(this, success: bool, extra):
        return json.dumps({'success': success, 'extra': extra})

    def __init__(self, host, conn):
        self.host = host
        self.conn = conn

    req_map_finished = {}
    pre_req_map = {}
    timeout_map = {}
    _REQ_DELETE_SECS = 3
    def start_listen(self, ident, args):
        host_str = f'{self.host[0]}:{self.host[1]}'
        logger.positive(f'connection started', host_str)

        while True:
            try: data = self.conn.recv(65535)
            except ConnectionResetError:
                logger.negative(f'connection reset', host_str)
                break

            time = datetime.now()
            self.pre_req_map.update({time: data})

            if not data:
                logger.negative(f'closing connection', host_str)
                break

            removed = 0
            while True:
                try:
                    for pre_req in self.pre_req_map.items():
                        delta = time - pre_req[0]
                        self.pre_req_map.pop(pre_req[0])
                    break
                except RuntimeError: continue

            if(removed > 0): logger.debug(f'removed {removed} pre_req requests')

            try: pack = sqlib.sqpacket.unpack(data)
            except sqlib.sqpacket.exceptions.UnpackError as ex:
                logger.negative(str(ex), host_str)
                self.conn.sendall(f'failed finding the treasure, maybe try again...'.encode('utf-8'))
                continue

            try: flags = util.sum_to_n(pack.flags)[0]
            except IndexError: flags = []

            if(sqlib.sqpacket.flag.KEY.value in flags):
                logger.positive(f'key request, getting {pack.src_ident.keyid}', host_str)
                with open(args.pbk_path, 'r') as f:
                    pubkeys = json.loads(f.read())
                    if(pack.src_ident.keyid > 0):
                        # print(json.dumps(pubkeys, indent=4))
                        if(str(pack.src_ident.keyid) not in pubkeys):
                            logger.negative(f'requested key ID doesn\'t exist on server', host_str)
                            self.conn.sendall(sqlib.sqpacket(1000, 0, pack.counter + 1, ident, '', self._gen_response(False, {'error': 'Requested key wasnt found on the server'})).pack())
                            continue
                        else:
                            pubkey = pubkeys[str(pack.src_ident.keyid)]
                            self.conn.sendall(sqlib.sqpacket(1000, 0, pack.counter + 1, ident, '', self._gen_response(True, {'key': pubkey})).pack())
                            continue
            elif(sqlib.sqpacket.flag.SEC.value in flags):
                keyid = pack.src_ident.keyid
                with open(args.pvk_path, 'r') as f:
                    pvk_data = json.loads(f.read())
                    if(keyid > 0):
                        if(str(keyid) not in pvk_data):
                            logger.negative(f'requested key ID doesn\'t exist on server', host_str)
                            self.conn.sendall(sqlib.sqpacket(1000, 0, pack.counter + 1, ident, '', self._gen_response(False, {'error': 'Requested key ID wasnt found on the server'})).pack())
                            continue
                        else:
                            pvk = pvk_data[str(keyid)]
                            private_key = serialization.load_pem_private_key(
                                pvk.encode('utf-8'),
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

                            logger.positive(f'received secret data: {decrypted.decode()}, replying...', host_str)
                            self.conn.sendall(f'i got ur message'.encode('utf-8'))
                            continue
            elif(sqlib.sqpacket.flag.SYN.value in flags):
                logger.positive(f'SYN received', host_str)
                self.conn.sendall(sqlib.sqpacket(1000, sqlib.sqpacket.flag.ACK.value, pack.counter + 1, ident, '', '').pack())
                continue
            elif(len(flags) == 0):
                logger.positive(f'received insecure data: {pack.data.decode()}', host_str)
                self.conn.sendall(sqlib.sqpacket(1000, 0, pack.counter + 1, ident, '', 'woah! thats pretty... insecure').pack())
                continue

            logger.positive(f'received data #{pack.counter}, replying...', host_str)
            self.conn.sendall(b'received')
