import squab
import json
import tmgr

import sqprotolib as sqlib

pvk_path = 'keys/priv.json'
pbk_path = 'keys/pub.json'

sq = squab.squab(pvk_path, pbk_path)

@sq.method(sqlib.sqpacket.flag.SEC)
def sec_req(*args, **kwargs):
    packet = kwargs['packet']
    response = kwargs['response']
    data = kwargs['data']
    return f'i see the message, {data.decode()}\nthis was sent securely using key#{packet.src_ident.keyid}'

@sq.method(sqlib.sqpacket.flag.NON)
def non_req(*args, **kwargs):
    data = kwargs['packet'].get_data()
    return f'i see the message, {data}\nthis was NOT sent securely, i recommend enabling that'

@sq.method(sqlib.sqpacket.flag.SYN)
def ack_syn(*args, **kwargs):
    packet = kwargs['packet']
    return (f'ok', sqlib.sqpacket.flag.ACK)

@sq.method(sqlib.sqpacket.flag.KEY)
def key_req(*args, **kwargs):
    packet = kwargs['packet']
    response = kwargs['response']
    with open(pbk_path, 'r') as f:
        pubkeys = json.loads(f.read())
        if(packet.src_ident.keyid > 0):
            if(str(packet.src_ident.keyid) not in pubkeys):
                response.send(0, f'Public key {packet.src_ident.keyid} not found in keychain', flag=sqlib.sqpacket.flag.KEY)
            else:
                pubkey = pubkeys[str(packet.src_ident.keyid)]
                resp = response._gen_def_resp(0, None, extra={'key': pubkey})
                response.send_raw(packet, json.dumps(resp), flag=sqlib.sqpacket.flag.KEY)

sq.main_loop()
