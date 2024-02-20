import ascon
import argparse
import asyncio

async def client(seed, message):
    cntr = 0

    r_bytes = ascon.hash(seed+bytes(cntr), 'Ascon-Xof', 32)
    cntr += 1

    key = r_bytes[0:16]
    nonce = r_bytes[16:32]
    associated_data = b''

    while True:
        reader, writer = await asyncio.open_connection('127.0.0.1', 8098)

        print('counter: ', cntr)
        nonce = ascon.hash(seed+bytes(cntr), 'Ascon-Xof', 16)
        cntr += 1

        crypt = ascon.encrypt(key, nonce, associated_data, message, 'Ascon-128')
        writer.write(crypt)
        await writer.drain()

        print(f'sent enc: {crypt}\n')

        writer.close()
        await writer.wait_closed()

        await asyncio.sleep(2)


parser = argparse.ArgumentParser(prog='Emitter')
parser.add_argument('-s', '--seed', required=True)
parser.add_argument('-m', '--message', required=True)

args = parser.parse_args()

seed = bytes(args.seed, 'UTF-8')
message = bytes(args.message, 'UTF-8')

asyncio.run(client(seed, message))