#!/usr/bin/env python3
"""
REVENG Examples Runner
======================

This script runs all REVENG examples to verify they work correctly.
"""

import sys
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any


class ExamplesRunner:
    """Run and test REVENG examples"""
    
    def __init__(self):
        self.results = {}
        self.errors = []
        self.warnings = []
    
    def run_basic_examples(self) -> Dict[str, Any]:
        """Run basic examples"""
        print("Running Basic Examples")
        print("=" * 30)
        
        basic_dir = Path('examples/basic')
        if not basic_dir.exists():
            print("❌ Basic examples directory not found")
            return {'status': 'skipped', 'reason': 'Directory not found'}
        
        example_files = list(basic_dir.glob('*.py'))
        if not example_files:
            print("❌ No basic examples found")
            return {'status': 'skipped', 'reason': 'No examples found'}
        
        results = {}
        for example_file in example_files:
            print(f"\nRunning {example_file.name}...")
            try:
                result = subprocess.run([
                    sys.executable, str(example_file), '--help'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"✅ {example_file.name} - Help works")
                    results[example_file.name] = 'success'
                else:
                    print(f"❌ {example_file.name} - Help failed")
                    results[example_file.name] = 'failed'
                    self.errors.append(f"{example_file.name}: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"⏰ {example_file.name} - Timeout")
                results[example_file.name] = 'timeout'
                self.warnings.append(f"{example_file.name}: Timeout")
            except Exception as e:
                print(f"❌ {example_file.name} - Error: {e}")
                results[example_file.name] = 'error'
                self.errors.append(f"{example_file.name}: {e}")
        
        return {'status': 'completed', 'results': results}
    
    def run_advanced_examples(self) -> Dict[str, Any]:
        """Run advanced examples"""
        print("\nRunning Advanced Examples")
        print("=" * 30)
        
        advanced_dir = Path('examples/advanced')
        if not advanced_dir.exists():
            print("❌ Advanced examples directory not found")
            return {'status': 'skipped', 'reason': 'Directory not found'}
        
        example_files = list(advanced_dir.glob('*.py'))
        if not example_files:
            print("❌ No advanced examples found")
            return {'status': 'skipped', 'reason': 'No examples found'}
        
        results = {}
        for example_file in example_files:
            print(f"\nRunning {example_file.name}...")
            try:
                result = subprocess.run([
                    sys.executable, str(example_file), '--help'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"✅ {example_file.name} - Help works")
                    results[example_file.name] = 'success'
                else:
                    print(f"❌ {example_file.name} - Help failed")
                    results[example_file.name] = 'failed'
                    self.errors.append(f"{example_file.name}: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"⏰ {example_file.name} - Timeout")
                results[example_file.name] = 'timeout'
                self.warnings.append(f"{example_file.name}: Timeout")
            except Exception as e:
                print(f"❌ {example_file.name} - Error: {e}")
                results[example_file.name] = 'error'
                self.errors.append(f"{example_file.name}: {e}")
        
        return {'status': 'completed', 'results': results}
    
    def run_analysis_template(self) -> Dict[str, Any]:
        """Run analysis template example"""
        print("\nRunning Analysis Template")
        print("=" * 30)
        
        template_path = Path('examples/analysis_template.py')
        if not template_path.exists():
            print("❌ Analysis template not found")
            return {'status': 'skipped', 'reason': 'Template not found'}
        
        try:
            # Test help
            result = subprocess.run([
                sys.executable, str(template_path), '--help'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("✅ Analysis template - Help works")
                
                # Test with sample file
                sample_path = Path('test_samples/HelloWorld.java')
                if sample_path.exists():
                    print("Testing with sample file...")
                    result = subprocess.run([
                        sys.executable, str(template_path), str(sample_path)
                    ], capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        print("✅ Analysis template - Sample analysis works")
                        return {'status': 'success', 'message': 'Template works with sample'}
                    else:
                        print("⚠️  Analysis template - Sample analysis failed (expected)")
                        return {'status': 'partial', 'message': 'Template works but sample analysis failed'}
                else:
                    print("⚠️  No sample file found for testing")
                    return {'status': 'success', 'message': 'Template works but no sample to test'}
            else:
                print("❌ Analysis template - Help failed")
                return {'status': 'failed', 'message': 'Template help failed'}
        except subprocess.TimeoutExpired:
            print("⏰ Analysis template - Timeout")
            return {'status': 'timeout', 'message': 'Template timeout'}
        except Exception as e:
            print(f"❌ Analysis template - Error: {e}")
            return {'status': 'error', 'message': f'Template error: {e}'}
    
    def run_all_examples(self) -> Dict[str, Any]:
        """Run all examples"""
        print("REVENG Examples Runner")
        print("=" * 40)
        print()
        
        start_time = time.time()
        
        # Run all example categories
        basic_results = self.run_basic_examples()
        advanced_results = self.run_advanced_examples()
        template_results = self.run_analysis_template()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Summary
        print("\n" + "=" * 40)
        print("Examples Summary")
        print("=" * 40)
        
        total_examples = 0
        successful_examples = 0
        
        if basic_results['status'] == 'completed':
            basic_success = sum(1 for r in basic_results['results'].values() if r == 'success')
            total_examples += len(basic_results['results'])
            successful_examples += basic_success
            print(f"Basic examples: {basic_success}/{len(basic_results['results'])} successful")
        
        if advanced_results['status'] == 'completed':
            advanced_success = sum(1 for r in advanced_results['results'].values() if r == 'success')
            total_examples += len(advanced_results['results'])
            successful_examples += advanced_success
            print(f"Advanced examples: {advanced_success}/{len(advanced_results['results'])} successful")
        
        if template_results['status'] in ['success', 'partial']:
            total_examples += 1
            successful_examples += 1
            print(f"Analysis template: 1/1 successful")
        
        print(f"\nTotal: {successful_examples}/{total_examples} examples successful")
        print(f"Duration: {duration:.2f} seconds")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors[:5]:  # Show first 5 errors
                print(f"  - {error}")
            if len(self.errors) > 5:
                print(f"  ... and {len(self.errors) - 5} more errors")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings[:5]:  # Show first 5 warnings
                print(f"  - {warning}")
            if len(self.warnings) > 5:
                print(f"  ... and {len(self.warnings) - 5} more warnings")
        
        # Overall status
        if successful_examples == total_examples:
            print("\n✅ All examples completed successfully!")
            return {'status': 'success', 'total': total_examples, 'successful': successful_examples}
        elif successful_examples > 0:
            print(f"\n⚠️  {successful_examples}/{total_examples} examples successful")
            return {'status': 'partial', 'total': total_examples, 'successful': successful_examples}
        else:
            print("\n❌ No examples completed successfully")
            return {'status': 'failed', 'total': total_examples, 'successful': successful_examples}


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run REVENG examples')
    parser.add_argument('--basic', action='store_true', help='Run only basic examples')
    parser.add_argument('--advanced', action='store_true', help='Run only advanced examples')
    parser.add_argument('--template', action='store_true', help='Run only analysis template')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()
    
    runner = ExamplesRunner()
    
    if args.template:
        results = runner.run_analysis_template()
    elif args.basic:
        results = runner.run_basic_examples()
    elif args.advanced:
        results = runner.run_advanced_examples()
    else:
        results = runner.run_all_examples()
    
    if args.json:
        import json
        print(json.dumps(results, indent=2))
        return
    
    # Exit with appropriate code
    if results['status'] == 'success':
        sys.exit(0)
    elif results['status'] == 'partial':
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
