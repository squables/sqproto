import argparse
import logger
import time
import socket
import json
import base64
import command_manager as cmgr
import datetime
import util

import sqprotolib as sqlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

name = 'client'

argp = argparse.ArgumentParser(description=f'I like making things that dont work', epilog='uhhhhhhh')

packet_props = argp.add_argument_group(title='Packet Properties', description='Properties that the packet has, such as max length, version, etc.')

packet_props.add_argument('--name', type=str, dest='name', help='Name to request from', required=True)

sqk = argp.add_argument_group(title='SquableKey Properties', description='Properties for connecting to & using SquableKey servers')
sqk.add_argument('--sqkid', type=int, dest='sqkid', help='Key ID to use', required=True)
sqk.add_argument('--sqkpwd', type=str, dest='sqkpwd', help='Password to access the SquableKey', required=True)
sqk.add_argument('--sqkip', type=str, dest='sqkip', help='IP to connect to SquableKey with', default='localhost')
sqk.add_argument('--sqkport', type=int, dest='sqkport', help='Port to connect to SquableKey with', default=7901)

args = argp.parse_args()

url = f'{args.sqkip}:{args.sqkport}'

logger.neutral(f"Attempting ping to {logger.neutral_c}{url}{logger.neutral_c.OFF} for SquableKey server", name, '')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try: sock.connect((args.sqkip, args.sqkport))
except ConnectionRefusedError:
    print('\r', end='', flush=True)
    logger.negative(f"Attempting ping to {logger.negative_c}{url}{logger.neutral_c.OFF} for SquableKey server", name)
    logger.negative(f"Connection refused, exiting...", name)
    exit(1)

print('\r', end='', flush=True)
logger.positive(f"Attempting ping to {logger.positive_c}{url}{logger.neutral_c.OFF} for SquableKey server", name)

logger.neutral(f'Attempting to obtain new key', name, end='')

ident = sqlib.sqpacket.sqident.generate('squables', args.sqkid)
packet = sqlib.sqpacket(1000, sqlib.sqpacket.flag.KEY.value, 0, ident, args.sqkpwd, '')
data = packet.pack()

sock.send(data)
try: recv = sock.recv(65535)
except ConnectionResetError:
    print('\r', end='')
    logger.negative(f'Attempt to obtain new key {logger.negative_c}failed{logger.negative_c.OFF}', name)
    logger.negative(f'connection reset, exiting...', name)
    exit(1)


unpack_data = sqlib.sqpacket.unpack(recv)
unpack_data = unpack_data.data.split(b'\0', 1)[0]
try: data = json.loads(unpack_data.decode())
except Exception as ex:
    print('\r', end='')
    logger.negative(f'Attempt to obtain new key {logger.negative_c}failed{logger.negative_c.OFF}', name)
    logger.negative(f'failed parsing response: {ex}', name)
    exit(1)

if('key' not in data['extra']):
    print('\r', end='')
    logger.negative(f'Attempt to obtain new key {logger.negative_c}failed{logger.negative_c.OFF}', name)
    logger.negative(f'key is not in extra', name)
    exit(1)

print('\r', end='')
logger.positive(f'Attempt to obtain new key {logger.positive_c}succeded{logger.positive_c.OFF}', name)

time_start = time.time()

key = data['extra']['key']
pubkey = serialization.load_pem_public_key(key.encode('utf-8'))

logger.positive(f'Obtained public key #{ident.keyid}', name)

def close_conn(argz):
    logger.negative('Exiting program...', argz[0])
    sock.close()
    exit(1)

def conn_stats(argz):
    alive_packet = sqlib.sqpacket(1000, sqlib.sqpacket.flag.SYN.value, 0, ident, '', '')
    sock.send(alive_packet.pack())

    try: recv_alive = sock.recv(65535)
    except ConnectionResetError:
        logger.negative('connection reset, exiting', argz[0])
        exit(1)

    recv_pack = sqlib.sqpacket.unpack(recv_alive)
    status = ''

    if(2 not in util.sum_to_n(recv_pack.flags)[0]): status = f'alive ({logger.negative_c}no ACK{logger.negative_c.OFF})'
    else: status = f'alive ({logger.positive_c}yes ACK{logger.positive_c.OFF})'

    logger.neutral(f'Connection Status: {status}', argz[0])
    logger.neutral(f'Alive Time: {datetime.timedelta(seconds=time.time() - time_start)}', argz[0])
    logger.neutral(f'Host: {args.sqkip}:{args.sqkport}', argz[0])
    logger.neutral(f'Ident: {ident.title}', argz[0])
    return cmgr.command_manager.command.cmd_res(True, None)

def insecure_send(argz):
    if(len(argz) == 0): return cmgr.command_manager.command.cmd_res(False, f'no text provided')
    args_joined = ' '.join(argz[1:])
    pkt = sqlib.sqpacket(1000, 0, 0, ident, '', args_joined)
    sock.sendall(pkt.pack())

    recv = sock.recv(65535)
    recv_unpacked = sqlib.sqpacket.unpack(recv)
    full_recv = ''
    for x in recv_unpacked.secure_text.decode():
        if(ord(x) == 0): break
        full_recv += x
    data = json.loads(full_recv)
    print(data['message'])
    return cmgr.command_manager.command.cmd_res(True, None)

def help_cmd(argz):
    longest_trig = 0
    longest_name = 0
    longest_desc = 0
    n_inc = 1
    for x in cmd_mgr.commands:
        trig = len(x.trigger) + n_inc
        name = len(x.name) + n_inc
        desc = len(x.cmd_help) + n_inc

        if(trig > longest_trig): longest_trig = trig
        if(name > longest_name): longest_name = name
        if(desc > longest_desc): longest_desc = desc

    for x in cmd_mgr.commands:
        total_str = f'{x.trigger} ({x.name}){"".join(" " for x in range((longest_name + longest_trig) - (len(x.trigger) + len(x.name))))}{x.cmd_help}'
        logger.neutral(total_str, argz[0])
    return cmgr.command_manager.command.cmd_res(True, None)

cmd_mgr = cmgr.command_manager('.')
cmd_mgr.reg_cmd(cmgr.command_manager.command('info', 'Connection Info', 'Gets information on the current connection', conn_stats))
cmd_mgr.reg_cmd(cmgr.command_manager.command('insecure', 'Insecure Send', 'Send data insecurely', insecure_send))
cmd_mgr.reg_cmd(cmgr.command_manager.command('exit', 'Exit', 'Closes the sock & exits program', close_conn))
cmd_mgr.reg_cmd(cmgr.command_manager.command('help', 'Help', 'Gets a list of useable commands', help_cmd))

while True:
    data = input(' > ')
    cmd_res = cmd_mgr.attempt_exec(data.split(' '))
    if(not cmd_res[1].success):
        logger.negative(f'executing command failed: {cmd_res[1].message}', name)
        continue

    if(cmd_res[0]): 
        if(cmd_res[1].data is not None):
            logger.neutral(f'returned data: {cmd_res[1].data}', name)
        continue

    enc_data = pubkey.encrypt(data.encode('utf-8'), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    packet2 = sqlib.sqpacket(1000, sqlib.sqpacket.flag.SEC.value, 1, ident, base64.b64encode(enc_data), '')
    try: sock.sendall(packet2.pack())
    except BrokenPipeError:
        logger.negative(f'Pipe broke, exiting')
        sock.close()
        exit(1)

    try: recv = sock.recv(65535)
    except ConnectionResetError:
        logger.negative('Connection reset, exiting...', name)
        exit(1)

    recv_pack = sqlib.sqpacket.unpack(recv)
    full_resp = ''
    for x in recv_pack.secure_text.decode():
        if(ord(x) == 0): break
        full_resp += x
    resp = json.loads(full_resp)
    msg = resp['message']
    print(msg)
