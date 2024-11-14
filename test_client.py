import socket
import argparse
import time

argp = argparse.ArgumentParser(description='Client to test socket stuff')

argp.add_argument('--data', dest='data', help='Data to send', required=True)
argp.add_argument('--host', dest='host', help='Host to connect to', default='localhost')
argp.add_argument('--port', dest='port', help='Port to connect to', type=int, default=7901)

args = argp.parse_args()

if(args.port > 65535 or args.port <= 0):
    print(f'port must be between 1 and 65535')
    exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try: sock.connect((args.host, args.port))
except ConnectionRefusedError:
    print(f'connection refused')
    exit(1)

while True:
    sock.send(args.data.encode('utf-8'))
    time.sleep(1/20)

data = sock.recv(1024)
print(f'recv: {data}')