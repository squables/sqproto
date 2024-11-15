import squab
import dotenv
import os
import json
import tmgr

import sqprotolib as sqlib

dotenv.load_dotenv()

sq = squab.squab()

pvk_path = os.environ['PVK_PATH']
pbk_path = os.environ['PBK_PATH']

@sq.method(sqlib.sqpacket.flag.SEC)
def sec_msg():
    print('hello from sec_msg')

@sq.method(sqlib.sqpacket.flag.KEY)
def key_req(packet: sqlib.sqpacket, response: tmgr.clientmgr.client._response_handler):
    with open(pbk_path, 'r') as f:
        pubkeys = json.loads(f.read())
        if(packet.src_ident.keyid > 0):
            # print(json.dumps(pubkeys, indent=4))
            if(str(packet.src_ident.keyid) not in pubkeys):
                response.send(0, f'Public key {packet.src_ident.keyid} not found in keychain')
            else:
                pubkey = pubkeys[str(packet.src_ident.keyid)]
                resp = response._gen_def_resp(0, None, extra={'key': pubkey})
                response.send_raw(packet, json.dumps(resp), secure=False)

sq.main_loop()
