from random import SystemRandom
from ecdsa import curves, SigningKey, der
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha256

from signature import Signature

class Generator:
    def __init__(self, curve=curves.SECP256k1):
        self.curve = curve
        self.random = SystemRandom()
        self.private_key = self.generate_private_key()
        self.public_key = self.get_public_key()
        
    def generate_private_key(self):
        """Generate a random private key."""
        return self.random.randint(1, self.curve.order - 1)
    
    def get_public_key(self):
        """Compute the public key from the private key."""
        G = self.curve.generator
        public_point = G * self.private_key
        return public_point
    
    def get_public_key_coordinates(self):
        """Return the public key coordinates (x, y)."""
        return (self.public_key.x(), self.public_key.y())
    
    def generate(self, n, leakage_lsb=0, leakage_msb=0):
        byte_length = (self.curve.order.bit_length() + 7) // 8
        signing_key = SigningKey.from_secret_exponent(self.private_key, curve=self.curve)
        signatures = []
        for _ in range(n):
            max = min(2**(256 - leakage_msb) - 1, self.curve.order)
            nonce = (self.random.randrange(0, max // (2 ** leakage_lsb))) << leakage_lsb
            message = self.random.getrandbits(8 * byte_length).to_bytes(byte_length, 'big')
            signature = signing_key.sign(message, hashfunc=sha256,
                k=nonce,sigencode=sigencode_der)
            hash = int(sha256(message).hexdigest(), 16)
            r, s = sigdecode_der(signature, self.curve.order)
            #print(f"Generated signature: r={r}, s={s}, nonce={nonce}")
            signatures.append(Signature(signature.hex(), hash, r, s, 0, nonce))
        return signatures