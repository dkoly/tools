#!/usr/bin/env python3

import argparse
import hashlib
import os
import json
import time
from pathlib import Path

class HashChecker:
    def __init__(self):
        self.supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        self.results = []
    
    def calculate_hash(self, file_path, algorithm='sha256'):
        #Calculate hash of a file
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_obj = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (IOError, OSError) as e:
            return f"Error: {str(e)}"
    
    def calculate_multiple_hashes(self, file_path):
        #Calculate multiple hash algorithms for a file
        hashes = {}
        for algorithm in self.supported_algorithms:
            hashes[algorithm] = self.calculate_hash(file_path, algorithm)
        return hashes
    
    def scan_directory(self, directory, algorithm='sha256', recursive=True):
        #Scan directory and calculate hashes for all files
        results = []
        directory_path = Path(directory)
        
        if not directory_path.exists():
            print(f"Error: Directory '{directory}' does not exist")
            return results
        
        # Get all files
        if recursive:
            files = directory_path.rglob('*')
        else:
            files = directory_path.glob('*')
        
        files = [f for f in files if f.is_file()]
        total_files = len(files)
        
        print(f"Scanning {total_files} files in {directory}...")
        
        for i, file_path in enumerate(files, 1):
            if i % 10 == 0 or i == total_files:
                print(f"Progress: {i}/{total_files} files processed")
            
            file_hash = self.calculate_hash(file_path, algorithm)
            file_info = {
                'file': str(file_path),
                'size': file_path.stat().st_size,
                'modified': time.ctime(file_path.stat().st_mtime),
                'hash': file_hash,
                'algorithm': algorithm
            }
            results.append(file_info)
        
        return results
    
    def verify_hash(self, file_path, expected_hash, algorithm='sha256'):
        #Verify file hash against expected value
        calculated_hash = self.calculate_hash(file_path, algorithm)
        
        if "Error:" in calculated_hash:
            return False, calculated_hash
        
        match = calculated_hash.lower() == expected_hash.lower()
        return match, calculated_hash
    
    def verify_from_file(self, hash_file):
        #Verify hashes from a hash file (format: hash filename)
        results = []
        
        try:
            with open(hash_file, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: Hash file '{hash_file}' not found")
            return results
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 2:
                print(f"Warning: Invalid format on line {line_num}: {line}")
                continue
            
            expected_hash = parts[0]
            filename = ' '.join(parts[1:])
            
            # Try to detect algorithm by hash length
            algorithm = self.detect_algorithm(expected_hash)
            
            if not os.path.exists(filename):
                result = {
                    'file': filename,
                    'status': 'FILE_NOT_FOUND',
                    'expected': expected_hash,
                    'calculated': 'N/A',
                    'algorithm': algorithm
                }
            else:
                match, calculated_hash = self.verify_hash(filename, expected_hash, algorithm)
                result = {
                    'file': filename,
                    'status': 'MATCH' if match else 'MISMATCH',
                    'expected': expected_hash,
                    'calculated': calculated_hash,
                    'algorithm': algorithm
                }
            
            results.append(result)
        
        return results
    
    def detect_algorithm(self, hash_value):
        #Detect hash algorithm based on hash length
        hash_lengths = {
            32: 'md5',
            40: 'sha1',
            64: 'sha256',
            128: 'sha512'
        }
        return hash_lengths.get(len(hash_value), 'sha256')
    
    def create_baseline(self, directory, output_file, algorithm='sha256'):
        #Create a baseline hash file for a directory
        results = self.scan_directory(directory, algorithm)
        
        with open(output_file, 'w') as f:
            f.write(f"# Hash baseline created on {time.ctime()}\n")
            f.write(f"# Algorithm: {algorithm.upper()}\n")
            f.write(f"# Directory: {directory}\n\n")
            
            for result in results:
                f.write(f"{result['hash']}  {result['file']}\n")
        
        print(f"Baseline created: {output_file} ({len(results)} files)")
        return results
    
    def compare_baselines(self, baseline1, baseline2):
        #Compare two baseline files
        def load_baseline(filename):
            hashes = {}
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        hashes[parts[1]] = parts[0]
            return hashes
        
        try:
            baseline1_hashes = load_baseline(baseline1)
            baseline2_hashes = load_baseline(baseline2)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            return
        
        all_files = set(baseline1_hashes.keys()) | set(baseline2_hashes.keys())
        
        added = []
        removed = []
        modified = []
        unchanged = []
        
        for file_path in sorted(all_files):
            if file_path in baseline1_hashes and file_path in baseline2_hashes:
                if baseline1_hashes[file_path] == baseline2_hashes[file_path]:
                    unchanged.append(file_path)
                else:
                    modified.append(file_path)
            elif file_path in baseline2_hashes:
                added.append(file_path)
            else:
                removed.append(file_path)
        
        print(f"\nBaseline Comparison:")
        print(f"  Files added: {len(added)}")
        print(f"  Files removed: {len(removed)}")
        print(f"  Files modified: {len(modified)}")
        print(f"  Files unchanged: {len(unchanged)}")
        
        if added:
            print(f"\nAdded files:")
            for f in added[:10]:  # Show first 10
                print(f"  + {f}")
            if len(added) > 10:
                print(f"  ... and {len(added) - 10} more")
        
        if removed:
            print(f"\nRemoved files:")
            for f in removed[:10]:
                print(f"  - {f}")
            if len(removed) > 10:
                print(f"  ... and {len(removed) - 10} more")
        
        if modified:
            print(f"\nModified files:")
            for f in modified[:10]:
                print(f"  * {f}")
            if len(modified) > 10:
                print(f"  ... and {len(modified) - 10} more")
    
    def save_results_json(self, results, output_file):
        #Save results to JSON file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="File Hash Checker - Calculate and verify file hashes")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Calculate hash of a file')
    hash_parser.add_argument('file', help='File to hash')
    hash_parser.add_argument('-a', '--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'],
                           default='sha256', help='Hash algorithm (default: sha256)')
    hash_parser.add_argument('--all', action='store_true', help='Calculate all supported hashes')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan directory and calculate hashes')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('-a', '--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'],
                           default='sha256', help='Hash algorithm (default: sha256)')
    scan_parser.add_argument('-o', '--output', help='Output file for results')
    scan_parser.add_argument('--json', help='Save results as JSON')
    scan_parser.add_argument('--no-recursive', action='store_true', help='Don\'t scan recursively')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify file hash')
    verify_parser.add_argument('file', help='File to verify')
    verify_parser.add_argument('hash', help='Expected hash value')
    verify_parser.add_argument('-a', '--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'],
                             help='Hash algorithm (auto-detect if not specified)')
    
    # Verify-file command
    verify_file_parser = subparsers.add_parser('verify-file', help='Verify hashes from file')
    verify_file_parser.add_argument('hashfile', help='File containing hashes to verify')
    verify_file_parser.add_argument('--json', help='Save results as JSON')
    
    # Baseline command
    baseline_parser = subparsers.add_parser('baseline', help='Create hash baseline')
    baseline_parser.add_argument('directory', help='Directory to baseline')
    baseline_parser.add_argument('-o', '--output', required=True, help='Output baseline file')
    baseline_parser.add_argument('-a', '--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'],
                               default='sha256', help='Hash algorithm (default: sha256)')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two baselines')
    compare_parser.add_argument('baseline1', help='First baseline file')
    compare_parser.add_argument('baseline2', help='Second baseline file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    checker = HashChecker()
    
    if args.command == 'hash':
        if args.all:
            hashes = checker.calculate_multiple_hashes(args.file)
            print(f"File: {args.file}")
            for algorithm, hash_value in hashes.items():
                print(f"  {algorithm.upper()}: {hash_value}")
        else:
            hash_value = checker.calculate_hash(args.file, args.algorithm)
            print(f"{hash_value}  {args.file}")
    
    elif args.command == 'scan':
        recursive = not args.no_recursive
        results = checker.scan_directory(args.directory, args.algorithm, recursive)
        
        if args.json:
            checker.save_results_json(results, args.json)
        elif args.output:
            with open(args.output, 'w') as f:
                f.write(f"# Hash scan of {args.directory}\n")
                f.write(f"# Created: {time.ctime()}\n")
                f.write(f"# Algorithm: {args.algorithm.upper()}\n\n")
                for result in results:
                    f.write(f"{result['hash']}  {result['file']}\n")
            print(f"Results saved to: {args.output}")
        else:
            for result in results:
                print(f"{result['hash']}  {result['file']}")
    
    elif args.command == 'verify':
        algorithm = args.algorithm or checker.detect_algorithm(args.hash)
        match, calculated = checker.verify_hash(args.file, args.hash, algorithm)
        
        if "Error:" in calculated:
            print(f"Error: {calculated}")
        elif match:
            print(f"✓ MATCH: {args.file}")
        else:
            print(f"✗ MISMATCH: {args.file}")
            print(f"  Expected:  {args.hash}")
            print(f"  Calculated: {calculated}")
    
    elif args.command == 'verify-file':
        results = checker.verify_from_file(args.hashfile)
        
        matches = sum(1 for r in results if r['status'] == 'MATCH')
        mismatches = sum(1 for r in results if r['status'] == 'MISMATCH')
        missing = sum(1 for r in results if r['status'] == 'FILE_NOT_FOUND')
        
        print(f"\nVerification Results:")
        print(f"  Matches: {matches}")
        print(f"  Mismatches: {mismatches}")
        print(f"  Missing files: {missing}")
        
        for result in results:
            if result['status'] == 'MATCH':
                print(f"✓ {result['file']}")
            elif result['status'] == 'MISMATCH':
                print(f"✗ {result['file']}")
                print(f"  Expected:  {result['expected']}")
                print(f"  Calculated: {result['calculated']}")
            else:
                print(f"? {result['file']} (not found)")
        
        if args.json:
            checker.save_results_json(results, args.json)
    
    elif args.command == 'baseline':
        checker.create_baseline(args.directory, args.output, args.algorithm)
    
    elif args.command == 'compare':
        checker.compare_baselines(args.baseline1, args.baseline2)

if __name__ == "__main__":
    main()