import socket
import time
import logger
import argparse
import uuid
import json
import util
import os
import ctypes
import base64
import sessions 
import threading

import sqprotolib as sqlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

argp = argparse.ArgumentParser(description='SquableKey server')

argp.add_argument('--port', type=int, default=7901, help='Port to bind to')
argp.add_argument('--host', type=str, default='localhost', help='Host to bind to')
argp.add_argument('--pbkf', type=str, dest='pbk_path', help='Path to public key list file')
argp.add_argument('--pvkf', type=str, dest='pvk_path', help='Path to private key list file')

args = argp.parse_args()

if(not os.path.exists(args.pbk_path)):
    logger.negative('Public key list file doesn\'t exist', 'server')
    exit(1)

if(not os.path.exists(args.pvk_path)):
    logger.negative('Private key list file doesn\'t exist', 'server')
    exit(1)

if(args.port <= 0 or args.port > 65535):
    logger.negative('Port must be between 1 and 65535', 'server')
    exit(1)

class server:
    class exceptions:
        class NotThreadError(Exception): pass

    class thread_mgr:
        def __init__(self):
            self.threads = []
            self.thread_mgr_thr = threading.Thread(target=self.manage_threads)
            self.name = 'thread_mgr'

        def add_thread(self, thr):
            if(not isinstance(thr, threading.Thread)): raise ValueError(f'must add type of Thread not {type(thr)}')
            self.threads.append(thr)
            thr.daemon = True
            logger.positive(f'starting thread {thr.name}', self.name)
            thr.start()

        def start(self):
            self.thread_mgr_thr.daemon = True
            self.thread_mgr_thr.start()

        def next_thread_num(self) -> int:
            return len(self.threads)

        _LOG_TIME_DEF = 300
        def manage_threads(self):
            log_time = self._LOG_TIME_DEF
            while True:
                time.sleep(1)
                for thr in self.threads:
                    if(not thr.is_alive()): 
                        logger.debug(f'killed thread {thr.name} (not alive)', self.name)
                        thr.join()
                        self.threads.remove(thr)

                if(log_time <= 0):
                    log_time = self._LOG_TIME_DEF
                    alive_ts = 0
                    dead_ts = 0

                    for t in self.threads:
                        if(t.is_alive()): alive_ts += 1
                        else: dead_ts += 1

                    logger.debug(f'found total of {alive_ts + dead_ts} thread(s), {alive_ts} alive and {dead_ts} dead', self.name)
                log_time -= 1

tmgr = server.thread_mgr()
tmgr.start()

keyring = []
ident = sqlib.sqpacket.sqident.generate('server', 0)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try: sock.bind((args.host, args.port))
except OSError:
    logger.negative(f'failed binding to port @ {args.host}:{args.port}', 'server')
    exit(1)

sock.listen(5)
logger.positive(f'binded to port @ {args.host}:{args.port}', 'server')

def main_loop():
    try: 
        while True:
            conn, host = sock.accept()
            ses = sessions.session(host, conn)

            n = tmgr.next_thread_num()
            thr_name = f'#{n}-{host[0]}:{host[1]}'
            thr = threading.Thread(target=ses.start_listen, args=(ident, args), name=thr_name)
            tmgr.add_thread(thr)
    except KeyboardInterrupt:
        yes_decs = ['y', 'ye', 'yes', 'yeah', 'yea', 'yep', 'yuh', 'yh', 'yah', 'yeh', 'yep']
        if(len(tmgr.threads) > 0):
            logger.neutral(f'There\'s still {len(tmgr.threads)} active connections, continue [y/N]? ', 'server', end='')
            dec = input('').lower()
            if(dec in yes_decs):
                logger.negative('Exiting program', 'server')
                sock.close()
                exit(0)
            else:
                logger.positive('Resuming server', 'server')
                main_loop()

main_loop()
