from lattice import Lattice
from bkz import reduce_lattice_BKZ, reduce_lattice_G6K, reduce_lattice_LLL, reduce_lattice_G6K_predicate
from random import SystemRandom
import math

def check(lattice, private_key):
    result = lattice.test_result_with_private_key(private_key)
    if result:
        print(f"Private key found: {result}")
        return result
    else:
        return None

def attack_bkz(lattice, signatures, private_key):
    for block_size in range(20, min(len(signatures), 70)+1, 5):
        print(f"[*] BKZ reduction with block size {block_size}")
        reduce_lattice_BKZ(lattice, block_size)
        if check(lattice, private_key):
            return True
    if(len(signatures)%5 != 0 and len(signatures) < 70):
        block_size = len(signatures)
        print(f"[*] Final BKZ reduction with block size {block_size}")
        reduce_lattice_BKZ(lattice, block_size)
        if check(lattice, private_key):
            return True
    return False

def attack_g6k(lattice, signatures, private_key):
    #random = SystemRandom()
    steps = 5#random.choice([5,10])
    jump = 100#random.choice([30,40])
    extra = 2#random.choice([2,3,4,5])
    dim4free_par = 0.3 #random.uniform(0.28, 0.32)
    print(f"Using steps={steps}, jump={jump}, dim4free_par={dim4free_par:.2f}, extra_dim4free={extra}")
    size = 0
    for block_size in range(max(20,len(signatures)-jump), len(signatures)+1, steps):
        size = block_size
        print(f"[*] G6K reduction with block size {block_size}")
        reduce_lattice_G6K(lattice, block_size, dim4free_par=dim4free_par, extra_dim4free=extra)
        if(check(lattice, private_key)):
            return True
    if(size < len(signatures)):
        block_size = len(signatures)
        print(f"[*] Final G6K reduction with block size {block_size}")
        reduce_lattice_G6K(lattice, block_size, dim4free_par=dim4free_par, extra_dim4free=extra)
        if(check(lattice, private_key)):
            return True
    return False


def attack_g6k_predicate(lattice, signatures, private_key):

    initial_dimension = 50 #dimension chosen in TCHES2023_2_20.pdf

    block_size = initial_dimension
    #print(f"[*] G6K reduction with predicate and block size {block_size}")
    if block_size > len(lattice.signatures):
        return False

    success, alpha, v_candidate =  reduce_lattice_G6K_predicate(lattice, block_size)
    
    if success:
        print(f"Private key found: {alpha}")
        return success
    else:
        return False 








def attack(signatures, leakage, curve, target_pubkey, total_attempts, private_key=None, type="BKZ", leakage_type="lsb", predicate_type="none"):
    lattice = Lattice(signatures, leakage=leakage, curve=curve, target_pubkey=target_pubkey)
    for attempt in range(total_attempts):
        print(f"Attempt {attempt+1}/{total_attempts}")
        
        if predicate_type == "predicate":
            lattice.build_lattice_predicate(leakage_type)
        else:
            lattice.build_lattice(leakage_type)

        
        
        reduce_lattice_LLL(lattice)
        if(check(lattice, private_key)):
            return [True, attempt]
        success = False
        if type == "BKZ" and predicate_type != "predicate":
            print("entrato bkz attack")
            success = attack_bkz(lattice, signatures, private_key)
        elif predicate_type == "predicate":
            print("entrato g6k predicate attack")
            success = attack_g6k_predicate(lattice, signatures, private_key)
        else:
            print("entrato g6k attack")
            success = attack_g6k(lattice, signatures, private_key)
        if success:
            break
    return [success, attempt]