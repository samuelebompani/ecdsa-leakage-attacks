from random import SystemRandom
from ecdsa import curves, SigningKey, der
from ecdsa.util import sigencode_der
from hashlib import sha256

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
    
    def generate(self, n):
        byte_length = (self.curve.order.bit_length() + 7) // 8
        private_key_bytes = self.private_key.to_bytes(byte_length, 'big')
        signing_key = SigningKey.from_string(private_key_bytes, curve=self.curve)
        signatures = []
        for _ in range(n):
            nonce = self.random.randint(1, self.curve.order - 1)
            message = self.random.getrandbits(8 * byte_length).to_bytes(byte_length, 'big')
            signature = signing_key.sign(message,
            hashfunc=sha256,
            k=nonce,
            sigencode=sigencode_der)
            hash = int(sha256(message).hexdigest(), 16)
            
            r_bytes, s_bytes = None, None
            seq, rest = der.remove_sequence(signature)
            r_bytes, rest = der.remove_integer(seq)
            s_bytes, rest = der.remove_integer(rest)
            r = r_bytes
            s = s_bytes
            signatures.append({"signature": signature.hex(), "hash": hash, "r": r, "s": s, "kp": 0})
        return signatures