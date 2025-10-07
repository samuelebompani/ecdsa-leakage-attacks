from lattice import Lattice
from bkz import reduce_lattice_BKZ, reduce_lattice_G6K
import sys

def check(lattice, private_key):
    result = lattice.test_result_with_private_key(private_key)
    if result:
        print(f"Private key found: {result}")
        return result
    else:
        return None

def attack(signatures, leakage, curve, target_pubkey, private_key=None):
    lattice = Lattice(signatures, leakage=leakage, curve=curve, target_pubkey=target_pubkey)
    for i in range(5):
        print(f"Attempt {i+1}/10")
        lattice.build_lattice()
        lattice.reduce_lattice_LLL()
        if(check(lattice, private_key)):
            return True
        success = False
        for block_size in range(len(signatures)-40, len(signatures)+1, 5):
            print(f"[*] G6K reduction with block size {block_size}")
            reduce_lattice_G6K(lattice, block_size)
            if(check(lattice, private_key)):
                success = True
                break
        if success:
            break
    return success