import struct
import socket
import logger
import util
import ctypes
import hashlib
import base64

from enum import Enum

class sqpacket:
    class exceptions:
        class ident:
            class TitleLengthError(Exception): pass
            class KeyIDSizeError(Exception): pass
            class KeyIDTypeError(Exception): pass

        class SecureLengthError(Exception): pass
        class DestinationLengthError(Exception): pass
        class UnpackError(Exception): pass

    class sqident:
        def __init__(self, title, filler, keyid):
            self.title = title
            self.filler = filler
            self.keyid = keyid
            self.keyid_str = str(keyid).zfill(8)

        def validate(self):
            pass

        def __str__(self): return self.strify()
        def __repr__(self): return self.strify()

        def strify(self):
            return f'{self.title}:{self.filler}:{self.keyid_str}'.encode(encoding='utf-8').hex()

        @staticmethod
        def from_raw(raw_hex: str):
            raw = bytearray.fromhex(raw_hex).decode()
            if(len(raw) != 32): return False

            split = raw.split(':')
            if(len(split) != 3): return False
            
            title = split[0]
            filler = split[1]
            keyid = split[2]

            ident = sqpacket.sqident(title, filler, int(keyid))
            return ident

        @staticmethod
        def generate(title, keyid):
            min_len = 0
            max_len = 12
            if(len(title) > max_len or len(title) < min_len):
                raise sqpacket.exceptions.ident.TitleLengthError(f'Title must be <= {max_len} & > {min_len} characters long')

            if(not isinstance(keyid, int)): raise sqpacket.exceptions.ident.KeyIDTypeError(f'Key is type of {type(keyid)}, not int')
            if(keyid > 99999999 or keyid < 0): 
                raise sqpacket.exceptions.ident.KeyIDSizeError(f'Key must be less than 8 numbers / characters in length & >= 0')

            key_max_len = 32

            keyid_str = str(keyid).zfill(8)
            full = f'{title}:{keyid_str}'

            rem_len = key_max_len - len(full) - 1
            filler = util.generate_fill(rem_len)
            return sqpacket.sqident(title, filler, keyid)

    class flag(Enum):
        SYN = 0x01
        ACK = 0x02
        KEY = 0x04
        SEC = 0x08
        RST = 0x10

    _MAX_DEST_LEN = 64
    _MIN_DEST_LEN = 4

    _MAX_SECURE_LEN = 2048
    _MIN_SECURE_LEN = 0

    _MAX_DATA_LEN = 2048
    _MIN_DATA_LEN = 0

    def __init__(self, version: int, flags: int, counter: int, src_ident: sqident, secure_text: str, data: str):
        self.version = version
        self.flags = flags
        self.counter = counter
        self.src_ident = src_ident
        self.secure_text = secure_text
        self.data = data
        self.checksum = hashlib.sha512(data.encode(encoding='utf-8') if isinstance(data, str) else data).hexdigest()

        self.secure_text = self.secure_text.encode('utf-8') if isinstance(self.secure_text, str) else self.secure_text
        self.data = self.data.encode('utf-8') if isinstance(self.data, str) else self.data
        self.checksum = self.checksum.encode('utf-8')

        if(len(self.secure_text) > self._MAX_SECURE_LEN or len(self.secure_text) < self._MIN_SECURE_LEN):
            raise self.exceptions.SecureLengthError(f'Length of secure text must be > {self._MAX_SECURE_LEN} & < {self._MIN_SECURE_LEN}')

    _FORMAT = f'iii64s{_MAX_SECURE_LEN}s{_MAX_DATA_LEN}s64s'
    def pack(self):
        packed_data = struct.pack(self._FORMAT, self.version, self.flags, self.counter, self.src_ident.strify().encode(encoding='utf-8'), self.secure_text, self.data, self.checksum)
        return packed_data

    @staticmethod
    def unpack(data):
        _FORMAT = f'iii64s2048s2048s64s'
        try: unpacked_data = struct.unpack(_FORMAT, data)
        except struct.error as ex:
            raise sqpacket.exceptions.UnpackError(f'Failed unpacking data: {str(ex)}')

        ident = sqpacket.sqident.from_raw(unpacked_data[3].decode())
        return sqpacket(unpacked_data[0], unpacked_data[1], unpacked_data[2], ident, unpacked_data[4], unpacked_data[5])
