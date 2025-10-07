from attack import attack
from generator import Generator

leakage = 200
n_signatures = 20
for _ in range(1):
    generator = Generator()
    print("Private Key:", generator.private_key)
    print("Public Key:", generator.public_key.x(), generator.public_key.y())
    
    signatures = generator.generate(n_signatures, leakage_lsb=leakage)
    attack(signatures, leakage=leakage, curve=generator.curve, target_pubkey=generator.public_key, private_key=generator.private_key)