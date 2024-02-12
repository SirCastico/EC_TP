import ascon


key = b'1234567890123456'
nonce = b'1234567890123456'
associated_data = b'asd'

data = b'hello\n'

crypt = ascon.encrypt(key, nonce, associated_data, data, 'Ascon-128')

decrypted = ascon.decrypt(key, nonce, associated_data, crypt, 'Ascon-128')

print(f'enc: {crypt}\ndec: {decrypted}')