from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives import serialization

class Agent:

    def __init__(self):

        # key agreed by both peers
        self.key = None

        # X448 key exchange
        self.private_key_x448 = None
        self.public_key_x448 = None

        # Ed448 Signing&Verification
        self.private_key_ed448 = None
        self.public_key_ed448 = None

    async def generate_keys(self):

        # X448 key exchange
        self.private_key_x448 = x448.X448PrivateKey.generate()
        self.public_key_x448 = self.private_key_x448.public_key()

        # Ed448 Signing&Verification
        self.private_key_ed448 = ed448.Ed448PrivateKey.generate()
        self.public_key_ed448 = self.private_key_ed448.public_key()

    async def send_keys(self):

        x448_bytes = self.public_key_x448.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        ed448_bytes = self.public_key_ed448.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

        signature = self.private_key_ed448.sign(x448_bytes)
        
        # send keys + signature
        data = x448_bytes + ed448_bytes + signature


    async def receive_keys(self):

        # Get peer ed448 key
        peer_public_ed448_bytes = "key_ed448_bytes"
        peer_public_ed448 = ed448.Ed448PublicKey.from_public_bytes(peer_public_ed448_bytes)

        # Get peer x448 key 
        peer_public_x448_bytes = "key_x448_bytes"
        peer_public_x448 = x448.X448PublicKey.from_public_bytes(peer_public_x448_bytes)

        # Get signature
        peer_signature = "signature"

        # Raises InvalidSignature if verification fails
        peer_public_ed448.verify(peer_signature, peer_public_x448_bytes)

        shared_key = self.private_key_x448.exchange(peer_public_x448)
        # Perform key derivation.
        derived_key = HKDF(

            algorithm=hashes.SHA256(),

            length=32,

            salt=None,

            info=b'handshake data',

        ).derive(shared_key)

        self.key = derived_key

    #async def send_message(self, message):


    #async def receive_message(self):


