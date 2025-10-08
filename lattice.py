from fpylll import IntegerMatrix
from ecdsa import SigningKey

class Lattice:
    def __init__(self, signatures, leakage, curve, target_pubkey):
        self.signatures = signatures
        self.hnp_samples = []
        self.leakage = leakage
        self.curve = curve
        self.target_pubkey = target_pubkey
        n = len(self.signatures)
        self.B = IntegerMatrix(n + 2, n + 2)
        

    def build_lattice(self):
        """
        Constructs a lattice for ECDSA signatures where the LSB 'leakage'
        of each nonce k_i are zero (trailing-zero leakage).

        Returns:
            B: IntegerMatrix lattice basis
            hnp_samples: list of (a_i, t_i) pairs for the hidden number problem.
        """
        n = len(self.signatures)
        self.B = IntegerMatrix(n + 2, n + 2)
        self.hnp_samples = []

        q = self.curve.order
        kbi = 2 ** self.leakage
        sigs = self.signatures

        for i in range(n):
            r, s, h = sigs[i].r, sigs[i].s, sigs[i].hash
            s_inv = pow(s, -1, q)
            kbi_inv = pow(kbi, -1, q)
            self.B[i, i] = 2 * kbi * q
            self.B[n, i] = (2 * kbi * (kbi_inv * (r * s_inv) % q))
            self.B[n + 1, i] = (2 * kbi * (kbi_inv * (- h * s_inv) % q) + q )
            #HNP samples
            inv_2l = pow(2, -self.leakage, q)
            t_i = (r * inv_2l * s_inv) % q
            a_i = ((- (s_inv * h) % q) * inv_2l) % q
            self.hnp_samples.append((a_i, t_i))
        self.B[n, n] = 1
        self.B[n + 1, n + 1] = q
    
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

    def test_result_with_private_key(self, private_key):
        mod_n = self.curve.order
        for row in self.B:
            candidate = row[-2] % mod_n
            if candidate > 0:
                cand1 = candidate
                cand2 = mod_n - candidate
                if(cand1 == private_key):
                    return cand1
                if(cand2 == private_key):
                    return cand2
        return False