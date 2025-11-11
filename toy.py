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
    parser.add_argument('-a', '--attempts', type=int, default=1,
                       help='Number of attack attempts per run (default: 1)')
    parser.add_argument('--type', choices=['BKZ', 'G6K'], default='BKZ',
                       help='Type of lattice reduction to use (default: BKZ)')
    parser.add_argument('-z', choices=['lsb', 'msb'], default='lsb',
                       help='MSB or LSB leakage (default: lsb)')
    parser.add_argument('-p', choices=['predicate', 'none'], default='none',
                       help='predicate or none (default: none)')
    
    args = parser.parse_args()
    
    success_count = 0
    total_runs = args.runs
    attempts = args.attempts
    attack_type = args.type
    leakage_type = args.z
    predicate_type = args.p
    total_time = 0
    total_sussess_time = 0
    successful_attempts = []
    
    for run in range(total_runs):
        print(f"\n{'='*50}")
        print(f"Run {run + 1}/{total_runs}")
        print(f"Success so far: {success_count}/{run} {success_count/run*100 if run > 0 else 0:.1f}%")
        print(f"{'='*50}")
        
        generator = Generator(leakage_type=leakage_type)
        print(f"Private Key: {generator.private_key}")
        if args.verbose:
            print(f"Public Key: ({generator.public_key.x()}, {generator.public_key.y()})")
        
        signatures = generator.generate(args.signatures, leakage=args.leakage)
        
        print(f"Testing with {args.leakage} bits known, {args.signatures} signatures, {leakage_type.upper()} leakage")
        
        if args.debug_leakage:
            print("\nLeakage verification (first 3 signatures):")
            for i, sig in enumerate(signatures[:3]):
                actual_lsb = sig.nonce & ((1 << args.leakage) - 1)
                print(f"  Sig {i}: nonce={sig.nonce}, leaked LSBs={actual_lsb}, stored leakage={sig.leakage}")
        
        start = timer()
        result, attempt = attack(signatures, leakage=args.leakage, curve=generator.curve, 
                       target_pubkey=generator.public_key, total_attempts=attempts, private_key=generator.private_key, type=attack_type, leakage_type=leakage_type, predicate_type=predicate_type)
        end = timer()
        print(f"{'='*50}")
        total = end - start
        if result:
            success_count += 1
            total_sussess_time += total
            print(f"✓ SUCCESS: Found private key in run {run + 1}")
            successful_attempts.append([attempt + 1, ])
        else:
            print(f"✗ FAILED: Private key not found in run {run + 1}")
        print(f"Attack completed in {end - start:.2f} seconds")
        total_time += total
    
    print(f"\n{'='*50}")
    print(f"SUMMARY: {args.leakage} LSB bits known, {args.signatures} signatures, {total_runs} total runs")
    print(f"Successful attacks: {success_count}/{total_runs}")
    print(f"Success rate: {success_count/total_runs*100:.1f}%")
    print(f"Average time per attack: {total_time/total_runs:.2f} seconds")
    if success_count > 0:
        print(f"Average time per successful attack: {total_sussess_time/success_count:.2f} seconds")
    print(f"Total time for all attacks: {total_time:.2f} seconds")
    print(f"Successful attempts: {successful_attempts}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()