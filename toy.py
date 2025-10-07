#!/usr/bin/env python3
import argparse
from attack import attack
from generator import Generator
from timeit import default_timer as timer

def main():
    parser = argparse.ArgumentParser(description='ECDSA Lattice Attack')
    parser.add_argument('-l', '--leakage', type=int, default=5, 
                       help='Number of LSB bits known (default: 5)')
    parser.add_argument('-n', '--signatures', type=int, default=53,
                       help='Number of signatures to generate (default: 53)')
    parser.add_argument('-r', '--runs', type=int, default=1,
                       help='Number of attack runs (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--debug-leakage', action='store_true',
                       help='Debug leakage verification')
    
    args = parser.parse_args()
    
    success_count = 0
    total_runs = args.runs
    total_time = 0
    
    for run in range(total_runs):
        print(f"\n{'='*50}")
        print(f"Run {run + 1}/{total_runs}")
        print(f"Success so far: {success_count}/{run}")
        print(f"{'='*50}")
        
        generator = Generator()
        print(f"Private Key: {generator.private_key}")
        if args.verbose:
            print(f"Public Key: ({generator.public_key.x()}, {generator.public_key.y()})")
        
        signatures = generator.generate(args.signatures, leakage_lsb=args.leakage)
        
        print(f"Testing with {args.leakage} LSB bits known, {args.signatures} signatures")
        
        if args.debug_leakage:
            print("\nLeakage verification (first 3 signatures):")
            for i, sig in enumerate(signatures[:3]):
                actual_lsb = sig.nonce & ((1 << args.leakage) - 1)
                print(f"  Sig {i}: nonce={sig.nonce}, leaked LSBs={actual_lsb}, stored leakage={sig.leakage}")
        
        start = timer()
        result = attack(signatures, leakage=args.leakage, curve=generator.curve, 
                       target_pubkey=generator.public_key, private_key=generator.private_key)
        end = timer()
        print(f"{'='*50}")
        if result:
            success_count += 1
            print(f"✓ SUCCESS: Found private key in run {run + 1}")
        else:
            print(f"✗ FAILED: Private key not found in run {run + 1}")
        print(f"Attack completed in {end - start:.2f} seconds")
        total_time += (end - start)
    
    print(f"\n{'='*50}")
    print(f"SUMMARY: {success_count}/{total_runs} successful attacks")
    print(f"Success rate: {success_count/total_runs*100:.1f}%")
    print(f"Average time per attack: {total_time/total_runs:.2f} seconds")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()