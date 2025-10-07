class Signature:
    def __init__(self, signature: str, hash: str, r: int, s: int, leakage: int, nonce: int):
        self.signature = signature
        self.hash = hash
        self.r = r
        self.s = s
        self.leakage = leakage
        self.nonce = nonce

    def __str__(self):
        return f"signature={self.signature}, hash={self.hash}, r={self.r}, s={self.s}, kp={self.leakage}, nonce={self.nonce}"