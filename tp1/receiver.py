import ascon
import socket
import argparse
import asyncio

parser = argparse.ArgumentParser(prog='Emitter')
parser.add_argument('-s', '--seed', required=True)

args = parser.parse_args()

seed = bytes(args.seed, 'UTF-8')

cntr = 0

r_bytes = ascon.hash(seed+bytes(cntr), 'Ascon-Xof', 32)
cntr += 1

key = r_bytes[0:16]
nonce = r_bytes[16:32]
associated_data = b''

async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global cntr

    print('counter: ', cntr)
    nonce = ascon.hash(seed+bytes(cntr), 'Ascon-Xof', 16)
    cntr += 1

    data = await reader.read(-1)
    dc = ascon.decrypt(key, nonce, associated_data, data, 'Ascon-128')

    print(f'received and decrypted: {dc}\n')

    writer.close()
    await writer.wait_closed()


async def start_server():
    server = await asyncio.start_server(handle_connection, '127.0.0.1', 8098)
    print('started server')
    async with server:
        await server.serve_forever()
            

asyncio.run(start_server())