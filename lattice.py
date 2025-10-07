from fpylll import IntegerMatrix, LLL
from ecdsa import SigningKey

class Lattice:
    def __init__(self, signatures, known_bits, curve, target_pubkey):
        self.signatures = signatures
        self.hnp_samples = []
        self.known_bits = known_bits
        self.curve = curve
        self.target_pubkey = target_pubkey
        n = len(self.signatures)
        self.B = IntegerMatrix(n + 2, n + 2)
        

    def build_lattice(self):
        """
        Constructs a lattice for ECDSA signatures where the LSB 'known_bits'
        of each nonce k_i are zero (trailing-zero leakage).

        Returns:
            B: IntegerMatrix lattice basis
            hnp_samples: list of (a_i, t_i) pairs for the hidden number problem.
        """
        
        n = len(self.signatures)
        self.hnp_samples = []

        q = self.curve.order
        kbi = 2 ** self.known_bits
        sigs = self.signatures

        for i in range(n):
            r, s, h, l = sigs[i].r, sigs[i].s, sigs[i].hash, sigs[i].leakage
            s_inv = pow(s, -1, q)
            kbi_inv = pow(kbi, -1, q)
            self.B[i, i] = 2 * kbi * q
            self.B[n, i] = (2 * kbi * (kbi_inv * (r * s_inv) % q))
            self.B[n + 1, i] = (2 * kbi * (kbi_inv * (l - h * s_inv) % q) + q )
        self.B[0, n] = 1
        self.B[1, n + 1] = q

    def reduce_lattice_LLL(self):
        LLL.reduction(self.B)
        return
    
    def test_result(self):
        mod_n = self.curve.order
        for row in self.B:
            candidate = row[-2] % mod_n
            if candidate > 0:
                cand1 = candidate
                cand2 = mod_n - candidate
                # Check if the candidate is a valid private key
                if(self.check_candidate(cand1, self.target_pubkey)):
                    return cand1
                if(self.check_candidate(cand2, self.target_pubkey)):
                    return cand2
        return 0
    
    def check_candidate(self, candidate, target) -> bool:
        candidate_pk = SigningKey.from_secret_exponent(candidate, curve=self.curve).verifying_key.pubkey.point
        print(f"{candidate_pk.x()}, {candidate_pk.y()}")
        if(candidate_pk.x() == target.x()):
            print("x coordinate matches")
        return candidate_pk == target

    def test_result_with_private_key(self, private_key) -> bool:
        print(private_key)
        mod_n = self.curve.order
        for row in self.B:
            candidate = row[-2] % mod_n
            if candidate > 0:
                cand1 = candidate
                cand2 = mod_n - candidate
                print(f"Testing candidate: {cand1} and {cand2}")
                if(cand1 == private_key or cand2 == private_key):
                    return True
        return False