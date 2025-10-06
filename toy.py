from generator import Generator

generator = Generator()
print("Private Key:", generator.private_key)
print("Public Key:", generator.public_key.x())
signatures = generator.generate(4)
for s in signatures:
    print("Signature:", str(s))