from fpylll import IntegerMatrix
from ecdsa import SigningKey
import math

class Lattice:
    def __init__(self, signatures, leakage, curve, target_pubkey):
        self.signatures = signatures
        self.hnp_samples = []
        self.leakage = leakage
        self.curve = curve
        self.target_pubkey = target_pubkey
        n = len(self.signatures)
        self.B = IntegerMatrix(n + 2, n + 2)
        self.tau = 0
        self.leakage_type= ""

    def leakage_type_setter(self, type):
        if type not in ["lsb", "msb"]:
            raise ValueError("Invalid type. Use 'lsb' or 'msb'.")
        self.leakage_type = type
        return self.leakage_type

    
    def tau_value(self):
        q = self.curve.order
        if self.leakage_type == "lsb":
            self.tau = int(( q // 2**(self.leakage +1) ) / math.sqrt(3))
        else:  #msb
            self.tau = int(( q // 2**(len(self.signatures) - self.leakage +1) ) / math.sqrt(3))
        return self.tau
    
        

    def build_lattice(self, type="lsb"):
        """
        Constructs a lattice for ECDSA signatures where either:
        - LSB 'leakage' of each nonce k_i are zero (trailing-zero leakage), or
        - MSB 'leakage' of each nonce k_i are zero (leading-zero leakage).

        Args:
            type (str): "lsb" (default) or "msb"
        
        Returns:
            B: IntegerMatrix lattice basis
            hnp_samples: list of (a_i, t_i) pairs for the hidden number problem
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

            # For both cases we will compute (a_i, t_i) differently
            if type == "lsb":
                self.leakage_type = "lsb"
                # ---- LSB leakage ----
                kbi_inv = pow(kbi, -1, q)
                self.B[i + 2, i] = 2 * kbi * q
                self.B[0, i] = 2 * kbi * (kbi_inv * (r * s_inv) % q)
                self.B[1, i] = 2 * kbi * (kbi_inv * (-h * s_inv) % q) + q

                # Hidden number problem samples (LSB version)
                inv_2l = pow(2, -self.leakage, q)
                t_i = (r * inv_2l * s_inv) % q
                a_i = ((- (s_inv * h) % q) * inv_2l) % q

            elif type == "msb":
                self.leakage_type = "msb"
                # ---- MSB leakage ----
                self.B[i + 2, i] = 2 * kbi * q
                self.B[0, i] = 2 * kbi * ((r * s_inv) % q)
                self.B[1, i] = 2 * kbi * (- (h * s_inv)) + q
                #HNP samples
                inv_2l = pow(2, -self.leakage, q)
                t_i = (r * inv_2l * s_inv) % q
                a_i = ((- (s_inv * h) % q) * inv_2l) % q
                
            else:
                raise ValueError("Invalid type. Use 'lsb' or 'msb'.")
            self.hnp_samples.append((a_i, t_i))
        self.B[0, n] = 1                                            #    
        self.B[1, n + 1] = q                                        #
            
        return self.B, self.hnp_samples



    
    def build_lattice_predicate(self, type="lsb"):
        """
        Constructs a lattice for ECDSA signatures where either:
        - LSB 'leakage' of each nonce k_i are zero (trailing-zero leakage), or
        - MSB 'leakage' of each nonce k_i are zero (leading-zero leakage).

        Args:
            type (str): "lsb" (default) or "msb"
        
        Returns:
            B: IntegerMatrix lattice basis
            hnp_samples: list of (a_i, t_i) pairs for the hidden number problem
        """
        n = len(self.signatures)
        self.B = IntegerMatrix(n + 1, n + 1)
        self.hnp_samples = []

        q = self.curve.order
        kbi = 2 ** self.leakage
        sigs = self.signatures
        #tau= math.floor( q / 2**(self.leakage +1) ) / math.sqrt(3)

        #a_0 = 0
        #t_0 = 0
        inv_2l = pow(2, -self.leakage, q)

        for i in range(n):
            r, s, h = sigs[i].r, sigs[i].s, sigs[i].hash
            s_inv = pow(s, -1, q)
            

            # For both cases we will compute (a_i, t_i) differently
            if type == "lsb":
                self.leakage_type = "lsb"
                self.tau =  int(( self.curve.order // 2**(self.leakage +1) ) / math.sqrt(3))
                # Hidden number problem samples (LSB version)
                
                t_i = (r * inv_2l * s_inv) % q
                a_i = ((-s_inv * h) %q) * inv_2l % q  

                if i == 0:
                    a_0 = a_i
                    t_0 = t_i
                    t0_inv = pow(t_0, -1, q) if t_0 != 0 else 0
                else:
                    t_prime = (t_i * t0_inv) %q
                    a_prime = (a_i - a_0 * t0_inv * t_i ) %q
                    # ---- LSB leakage ----
                    kbi_inv = pow(kbi, -1, q)
                    self.B[i-1 , i-1] = q
                    self.B[n-1, i-1] = t_prime
                    self.B[n, i-1] = a_prime
               
               

            elif type == "msb":
                self.leakage_type = "msb"
                self.tau = int(( self.curve.order // 2**(n - self.leakage +1) ) / math.sqrt(3))
                # ---- MSB leakage ----
                inv_2l = pow(2, -self.leakage, q)
                t_i = (r * inv_2l * s_inv) % q
                a_i = ((-s_inv * h) %q) * inv_2l % q

                if i == 0:
                    a_0 = a_i
                    t_0 = t_i
                    t0_inv = pow(t_0, -1, q) if t_0 != 0 else 0
                else:
                    t_prime = t_i * t0_inv %q
                    a_prime = (a_i - a_0 * t0_inv * t_i ) %q

                    self.B[i-1 , i-1] = q
                    self.B[n-1, i-1] = t_prime +q
                    self.B[n, i-1] = a_prime
                

                
            else:
                raise ValueError("Invalid type. Use 'lsb' or 'msb'.")

            self.hnp_samples.append((a_i, t_i))

        self.B[n-1, n-1] = 1   
        self.B[n, n] = self.tau
        

            
        return self.B, self.hnp_samples

    
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

    