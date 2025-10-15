#!/usr/bin/env python3
"""
REVENG Output Cleaner
=====================

This script cleans generated analysis outputs and temporary files.
"""

import sys
import shutil
from pathlib import Path
from typing import List, Dict, Any


class OutputCleaner:
    """Clean REVENG generated outputs"""
    
    def __init__(self):
        self.cleaned_files = []
        self.cleaned_dirs = []
        self.errors = []
    
    def clean_analysis_outputs(self) -> bool:
        """Clean analysis output directories"""
        print("Cleaning Analysis Outputs...")
        
        # Common analysis output patterns
        output_patterns = [
            'analysis_*',
            'human_readable_*',
            'rebuilt_*',
            'validation_*',
            'reports_*',
            'temp_*',
            'tmp_*'
        ]
        
        cleaned_count = 0
        for pattern in output_patterns:
            for path in Path('.').glob(pattern):
                if path.is_dir():
                    try:
                        shutil.rmtree(path)
                        self.cleaned_dirs.append(str(path))
                        cleaned_count += 1
                        print(f"✅ Removed directory: {path}")
                    except Exception as e:
                        self.errors.append(f"Failed to remove {path}: {e}")
                        print(f"❌ Failed to remove {path}: {e}")
                elif path.is_file():
                    try:
                        path.unlink()
                        self.cleaned_files.append(str(path))
                        cleaned_count += 1
                        print(f"✅ Removed file: {path}")
                    except Exception as e:
                        self.errors.append(f"Failed to remove {path}: {e}")
                        print(f"❌ Failed to remove {path}: {e}")
        
        print(f"Cleaned {cleaned_count} analysis outputs")
        return len(self.errors) == 0
    
    def clean_python_cache(self) -> bool:
        """Clean Python cache files"""
        print("Cleaning Python Cache...")
        
        cache_patterns = [
            '__pycache__',
            '*.pyc',
            '*.pyo',
            '*.pyd',
            '.pytest_cache',
            '.coverage',
            'htmlcov'
        ]
        
        cleaned_count = 0
        for pattern in cache_patterns:
            for path in Path('.').rglob(pattern):
                if path.is_dir():
                    try:
                        shutil.rmtree(path)
                        self.cleaned_dirs.append(str(path))
                        cleaned_count += 1
                        print(f"✅ Removed cache directory: {path}")
                    except Exception as e:
                        self.errors.append(f"Failed to remove {path}: {e}")
                        print(f"❌ Failed to remove {path}: {e}")
                elif path.is_file():
                    try:
                        path.unlink()
                        self.cleaned_files.append(str(path))
                        cleaned_count += 1
                        print(f"✅ Removed cache file: {path}")
                    except Exception as e:
                        self.errors.append(f"Failed to remove {path}: {e}")
                        print(f"❌ Failed to remove {path}: {e}")
        
        print(f"Cleaned {cleaned_count} cache files")
        return len(self.errors) == 0
    
    def clean_test_outputs(self) -> bool:
        """Clean test output files"""
        print("Cleaning Test Outputs...")
        
        test_patterns = [
            'test-results.xml',
            'coverage.xml',
            'htmlcov',
            'tests/coverage',
            'tests/__pycache__',
            'tests/.pytest_cache'
        ]
        
        cleaned_count = 0
        for pattern in test_patterns:
            path = Path(pattern)
            if path.exists():
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                        self.cleaned_dirs.append(str(path))
                    else:
                        path.unlink()
                        self.cleaned_files.append(str(path))
                    cleaned_count += 1
                    print(f"✅ Removed test output: {path}")
                except Exception as e:
                    self.errors.append(f"Failed to remove {path}: {e}")
                    print(f"❌ Failed to remove {path}: {e}")
        
        print(f"Cleaned {cleaned_count} test outputs")
        return len(self.errors) == 0
    
    def clean_logs(self) -> bool:
        """Clean log files"""
        print("Cleaning Log Files...")
        
        log_patterns = [
            '*.log',
            'logs',
            '*.out',
            '*.err'
        ]
        
        cleaned_count = 0
        for pattern in log_patterns:
            for path in Path('.').glob(pattern):
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                        self.cleaned_dirs.append(str(path))
                    else:
                        path.unlink()
                        self.cleaned_files.append(str(path))
                    cleaned_count += 1
                    print(f"✅ Removed log: {path}")
                except Exception as e:
                    self.errors.append(f"Failed to remove {path}: {e}")
                    print(f"❌ Failed to remove {path}: {e}")
        
        print(f"Cleaned {cleaned_count} log files")
        return len(self.errors) == 0
    
    def clean_temporary_files(self) -> bool:
        """Clean temporary files"""
        print("Cleaning Temporary Files...")
        
        temp_patterns = [
            '*.tmp',
            '*.temp',
            '*.swp',
            '*.swo',
            '.DS_Store',
            'Thumbs.db',
            '*.bak',
            '*.backup'
        ]
        
        cleaned_count = 0
        for pattern in temp_patterns:
            for path in Path('.').rglob(pattern):
                try:
                    path.unlink()
                    self.cleaned_files.append(str(path))
                    cleaned_count += 1
                    print(f"✅ Removed temp file: {path}")
                except Exception as e:
                    self.errors.append(f"Failed to remove {path}: {e}")
                    print(f"❌ Failed to remove {path}: {e}")
        
        print(f"Cleaned {cleaned_count} temporary files")
        return len(self.errors) == 0
    
    def clean_all(self) -> Dict[str, Any]:
        """Clean all outputs"""
        print("REVENG Output Cleaner")
        print("=" * 30)
        print()
        
        results = {
            'analysis_outputs': self.clean_analysis_outputs(),
            'python_cache': self.clean_python_cache(),
            'test_outputs': self.clean_test_outputs(),
            'logs': self.clean_logs(),
            'temp_files': self.clean_temporary_files()
        }
        
        # Summary
        print("\n" + "=" * 30)
        print("Cleaning Summary")
        print("=" * 30)
        
        total_cleaned = len(self.cleaned_files) + len(self.cleaned_dirs)
        successful_operations = sum(1 for r in results.values() if r)
        total_operations = len(results)
        
        print(f"Files cleaned: {len(self.cleaned_files)}")
        print(f"Directories cleaned: {len(self.cleaned_dirs)}")
        print(f"Total items cleaned: {total_cleaned}")
        print(f"Operations successful: {successful_operations}/{total_operations}")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors[:5]:  # Show first 5 errors
                print(f"  - {error}")
            if len(self.errors) > 5:
                print(f"  ... and {len(self.errors) - 5} more errors")
        
        if total_cleaned > 0:
            print(f"\n✅ Cleaned {total_cleaned} items successfully!")
        else:
            print("\nℹ️  No items to clean")
        
        return {
            'total_cleaned': total_cleaned,
            'files_cleaned': len(self.cleaned_files),
            'dirs_cleaned': len(self.cleaned_dirs),
            'errors': len(self.errors),
            'successful_operations': successful_operations,
            'total_operations': total_operations
        }


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Clean REVENG outputs')
    parser.add_argument('--analysis', action='store_true', help='Clean analysis outputs only')
    parser.add_argument('--cache', action='store_true', help='Clean Python cache only')
    parser.add_argument('--tests', action='store_true', help='Clean test outputs only')
    parser.add_argument('--logs', action='store_true', help='Clean log files only')
    parser.add_argument('--temp', action='store_true', help='Clean temporary files only')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be cleaned without actually cleaning')
    args = parser.parse_args()
    
    if args.dry_run:
        print("DRY RUN MODE - No files will be actually deleted")
        print("=" * 50)
        # TODO: Implement dry run mode
        return
    
    cleaner = OutputCleaner()
    
    if args.analysis:
        success = cleaner.clean_analysis_outputs()
    elif args.cache:
        success = cleaner.clean_python_cache()
    elif args.tests:
        success = cleaner.clean_test_outputs()
    elif args.logs:
        success = cleaner.clean_logs()
    elif args.temp:
        success = cleaner.clean_temporary_files()
    else:
        results = cleaner.clean_all()
        success = results['errors'] == 0
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
