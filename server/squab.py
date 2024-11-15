import dotenv
import os
import socket
import tmgr
import functools

import sqprotolib as sqlib

from handler import sqhandler

class squab:
    class error:
        class InvalidMethodError(Exception): pass
        class InvalidPortError(Exception): pass

    def __init__(self):
        self.ident = sqlib.sqpacket.sqident.generate('server', 69)
        self.handler = sqhandler()
        self.cmgr = tmgr.clientmgr(self.handler, self.ident)

    def method(self, method):
        if(not isinstance(method, sqlib.sqpacket.flag)): raise self.error.InvalidMethodError(f'Method must be sqlib.sqpacket.flag, not {type(method).__name__}')
        def inner(func):
            self.handler.register_method(sqhandler.method(method, func))

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                print(f'calling method with args {args}, {kwargs}')
                return func(*args, **kwargs)
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
                print(conn, host)

                self.cmgr.register_connection(conn, host)

        except KeyboardInterrupt:
            print('exiting...')
            exit(1)
