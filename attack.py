from lattice import Lattice
from bkz import reduce_lattice_BKZ, reduce_lattice_G6K, reduce_lattice_LLL
from random import SystemRandom

def check(lattice, private_key):
    result = lattice.test_result_with_private_key(private_key)
    if result:
        print(f"Private key found: {result}")
        return result
    else:
        return None

def attack(signatures, leakage, curve, target_pubkey, total_attempts, private_key=None):
    lattice = Lattice(signatures, leakage=leakage, curve=curve, target_pubkey=target_pubkey)
    for attempt in range(total_attempts):
        print(f"Attempt {attempt+1}/{total_attempts}")
        random = SystemRandom()
        steps = random.choice([5,10])
        jump = random.choice([30,40])
        extra = random.choice([2,3,4,5])
        dim4free_par = random.uniform(0.28, 0.32)
        print(f"Using steps={steps}, jump={jump}, dim4free_par={dim4free_par:.2f}, extra_dim4free={extra}")
        lattice.build_lattice()
        reduce_lattice_LLL(lattice)
        if(check(lattice, private_key)):
            return [True, attempt]
        success = False
        for block_size in range(len(signatures)-jump, len(signatures)+1, steps):
            print(f"[*] G6K reduction with block size {block_size}")
            reduce_lattice_G6K(lattice, block_size, dim4free_par=dim4free_par, extra_dim4free=extra)
            if(check(lattice, private_key)):
                success = True
                break
        if success:
            break
    return [success, attempt]