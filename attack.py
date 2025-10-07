from lattice import Lattice

def attack(signatures, leakage, curve, target_pubkey, private_key=None):
    lattice = Lattice(signatures, known_bits=leakage, curve=curve, target_pubkey=target_pubkey)
    lattice.build_lattice()
    lattice.reduce_lattice_LLL()
    result = lattice.test_result_with_private_key(private_key)
    if result:
        print(f"Private key found: {result}")
    else:
        print(f"Private key not found: {result}")
    