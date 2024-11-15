import socket
import threading
import json
import os

from handler import sqhandler
import sqprotolib as sqlib

class clientmgr:
    class error:
        class InvalidSocketTypeError(Exception): pass
        class InvalidHandlerTypeError(Exception): pass
        class InvalidCodeTypeError(Exception): pass
        class InvalidIdentTypeError(Exception): pass
        class MethodNotRegisteredError(Exception): pass
        class MethodTypeError(Exception): pass

    class client:
        class _response_handler:
            def __init__(self, conn: socket.socket, ident: sqlib.sqpacket.sqident):
                if(not isinstance(conn, socket.socket)): raise clientmgr.error.InvalidSocketTypeError(f'Socket must be of type socket.socket, not {type(conn).__name__}')
                if(not isinstance(ident, sqlib.sqpacket.sqident)): raise clientmgr.error.InvalidIdentTypeError(f'Ident must be type of sqlib.sqpacket.sqident, not {type(ident).__name__}')
                self.conn = conn
                self.ident = ident

            def _gen_def_resp(self, code: int, message, errors = None, extra = None):
                if(not isinstance(code, int)): raise clientmgr.error.InvalidCodeTypeError(f'Response code must be of type {type(int).__name__}, not {type(code).__name__}')
                resp_dict = {}
                resp_dict.update({'code': code})
                resp_dict.update({'message': message})

                if(errors is not None): resp_dict.update({'errors': errors})
                if(extra is not None): resp_dict.update({'extra': extra})

                return resp_dict

            def send(self, prev_pack: sqlib.sqpacket, code: int, message: str, errors = None, data = None, secure = True):
                resp = self._gen_def_resp(code, message, errors, data)
                if(secure): packet = sqlib.sqpacket(1000, sqlib.sqpacket.flag.SEC.value, prev_pack.counter + 1, self.ident, json.dumps(resp), '')
                else: packet = sqlib.sqpacket(1000, sqlib.sqpacket.flag.SEC.value, prev_pack.counter + 1, self.ident, '', json.dumps(resp))
                 
                self.conn.sendall(packet.pack())

            def send_raw(self, prev_pack: sqlib.sqpacket, data, secure = True):
                if(secure): packet = sqlib.sqpacket(1000, sqlib.sqpacket.flag.SEC.value, prev_pack.counter + 1, self.ident, data, '')
                else: packet = sqlib.sqpacket(1000, sqlib.sqpacket.flag.SEC.value, prev_pack.counter + 1, self.ident, '', data)
                self.conn.sendall(packet.pack())

        def __init__(self, conn: socket.socket, host, handler: sqhandler, ident: sqlib.sqpacket.sqident):
            if(not isinstance(conn, socket.socket)): raise clientmgr.error.InvalidSocketTypeError(f'Socket must be of type {type(socket.socket).__name__}, not {type(conn).__name__}')
            if(not isinstance(handler, sqhandler)): raise clientmgr.error.InvalidHandlerTypeError(f'Handler must be type of {type(sqhandler).__name__}, not {type(handler).__name__}')
            if(not isinstance(ident, sqlib.sqpacket.sqident)): raise clientmgr.error.InvalidIdentTypeError(f'Ident must be type of sqlib.sqpacket.sqident, not {type(ident).__name__}')

            self.conn = conn
            self.host = host
            self.handler = handler
            self.response = self._response_handler(conn, ident)
            self.ident = ident

            self.thread = threading.Thread(target=self.start_client_thread)
            self.thread.daemon = True
            self.thread.start()
        
        def start_client_thread(self):
            host_str = f'{self.host[0]}:{self.host[1]}'
            print(f'started listen on {host_str}')
            while True:
                try: data = self.conn.recv(8192)
                except ConnectionResetError:
                    print(f'ending connection with {host_str}')
                    break

                if not data:
                    break

                try: packet = sqlib.sqpacket.unpack(data)
                except sqlib.sqpacket.exceptions.UnpackError:
                    self.response.send(None, 0, 'uhhhh, i dont understand')
                    continue

                flag = sqlib.sqpacket.flag(packet.flags)
                method = self.handler.get_method(flag)

                if(method is None): self.response.send(packet, 0, 'method not allowed')
                if(not isinstance(method, sqhandler.method)): raise clientmgr.error.InvalidHandlerTypeError(f'Method must be type of sqhandler.method, not {type(method).__name__}')

                res = method.callback(packet=packet, response=self.response)
                self.response.send(packet, 1, res)

    def __init__(self, handler: sqhandler, ident: sqlib.sqpacket.sqident):
        if(not isinstance(handler, sqhandler)): raise clientmgr.error.InvalidHandlerTypeError(f'Handler must be type of {type(sqhandler).__name__}, not {type(handler).__name__}')
        if(not isinstance(ident, sqlib.sqpacket.sqident)): raise clientmgr.error.InvalidIdentTypeError(f'Ident must be type of sqlib.sqpacket.sqident, not {type(ident).__name__}')
        self.handler = handler
        self.ident = ident

    def register_connection(self, conn, host):
        thr = threading.Thread()
        cl = self.client(conn, host, self.handler, self.ident)
