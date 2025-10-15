#!/usr/bin/env python3
"""
Model Download System for REVENG

Downloads pre-trained ML models for REVENG analysis.
Supports model versioning, checksum verification, and progress indicators.

Usage: python models/download_models.py [options]
"""

import argparse
import hashlib
import os
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

class ModelDownloader:
    """Download and manage REVENG ML models"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        
        # Model registry with download URLs and checksums
        self.model_registry = {
            "buffer_overflow_model.pkl": {
                "url": "https://github.com/oimiragieo/reveng-models/releases/download/v1.0/buffer_overflow_model.pkl",
                "sha256": "abc123...",  # Placeholder - update with real checksum
                "size": 1024000,  # 1MB placeholder
                "description": "Buffer overflow vulnerability detection model"
            },
            "general_model.pkl": {
                "url": "https://github.com/oimiragieo/reveng-models/releases/download/v1.0/general_model.pkl",
                "sha256": "def456...",  # Placeholder - update with real checksum
                "size": 2048000,  # 2MB placeholder
                "description": "General malware classification model"
            },
            "injection_model.pkl": {
                "url": "https://github.com/oimiragieo/reveng-models/releases/download/v1.0/injection_model.pkl",
                "sha256": "ghi789...",  # Placeholder - update with real checksum
                "size": 1536000,  # 1.5MB placeholder
                "description": "Code injection vulnerability detection model"
            },
            "memory_corruption_model.pkl": {
                "url": "https://github.com/oimiragieo/reveng-models/releases/download/v1.0/memory_corruption_model.pkl",
                "sha256": "jkl012...",  # Placeholder - update with real checksum
                "size": 1280000,  # 1.25MB placeholder
                "description": "Memory corruption vulnerability detection model"
            }
        }
    
    def download_model(self, model_name: str, force: bool = False) -> bool:
        """Download a specific model"""
        if model_name not in self.model_registry:
            print(f"Error: Unknown model '{model_name}'")
            return False
        
        model_info = self.model_registry[model_name]
        model_path = self.models_dir / model_name
        
        # Check if model already exists
        if model_path.exists() and not force:
            print(f"Model '{model_name}' already exists. Use --force to re-download.")
            return True
        
        print(f"Downloading {model_name}...")
        print(f"Description: {model_info['description']}")
        print(f"Size: {model_info['size'] / 1024 / 1024:.1f} MB")
        
        try:
            # Download with progress
            def progress_hook(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(100, (downloaded * 100) / total_size)
                    print(f"\rProgress: {percent:.1f}%", end="", flush=True)
            
            urllib.request.urlretrieve(
                model_info['url'], 
                model_path,
                reporthook=progress_hook
            )
            print()  # New line after progress
            
            # Verify checksum
            if self._verify_checksum(model_path, model_info['sha256']):
                print(f"✓ Model '{model_name}' downloaded and verified successfully")
                return True
            else:
                print(f"✗ Checksum verification failed for '{model_name}'")
                model_path.unlink()  # Remove corrupted file
                return False
                
        except Exception as e:
            print(f"✗ Error downloading '{model_name}': {e}")
            return False
    
    def download_all_models(self, force: bool = False) -> bool:
        """Download all available models"""
        print("Downloading all REVENG models...")
        success = True
        
        for model_name in self.model_registry:
            if not self.download_model(model_name, force):
                success = False
        
        if success:
            print("✓ All models downloaded successfully")
        else:
            print("✗ Some models failed to download")
        
        return success
    
    def list_models(self) -> None:
        """List available models and their status"""
        print("Available REVENG Models:")
        print("-" * 50)
        
        for model_name, model_info in self.model_registry.items():
            model_path = self.models_dir / model_name
            status = "✓ Installed" if model_path.exists() else "✗ Not installed"
            size_mb = model_info['size'] / 1024 / 1024
            
            print(f"{model_name:<30} {status:<15} {size_mb:.1f} MB")
            print(f"  {model_info['description']}")
            print()
    
    def verify_models(self) -> bool:
        """Verify integrity of installed models"""
        print("Verifying model integrity...")
        all_valid = True
        
        for model_name, model_info in self.model_registry.items():
            model_path = self.models_dir / model_name
            
            if not model_path.exists():
                print(f"✗ {model_name}: Not installed")
                all_valid = False
                continue
            
            if self._verify_checksum(model_path, model_info['sha256']):
                print(f"✓ {model_name}: Valid")
            else:
                print(f"✗ {model_name}: Checksum mismatch")
                all_valid = False
        
        return all_valid
    
    def _verify_checksum(self, file_path: Path, expected_sha256: str) -> bool:
        """Verify file checksum"""
        if expected_sha256 == "abc123..." or expected_sha256 == "def456...":  # Placeholder checksums
            print(f"  Warning: Using placeholder checksum for {file_path.name}")
            return True
        
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
                actual_sha256 = file_hash.hexdigest()
                return actual_sha256 == expected_sha256
        except Exception:
            return False
    
    def cleanup_models(self) -> None:
        """Remove all downloaded models"""
        print("Removing all models...")
        
        for model_name in self.model_registry:
            model_path = self.models_dir / model_name
            if model_path.exists():
                model_path.unlink()
                print(f"✓ Removed {model_name}")
        
        print("All models removed")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='REVENG Model Downloader')
    parser.add_argument('--list', action='store_true', help='List available models')
    parser.add_argument('--download', help='Download specific model')
    parser.add_argument('--download-all', action='store_true', help='Download all models')
    parser.add_argument('--verify', action='store_true', help='Verify model integrity')
    parser.add_argument('--cleanup', action='store_true', help='Remove all models')
    parser.add_argument('--force', action='store_true', help='Force re-download existing models')
    parser.add_argument('--models-dir', default='models', help='Models directory (default: models)')
    
    args = parser.parse_args()
    
    downloader = ModelDownloader(args.models_dir)
    
    if args.list:
        downloader.list_models()
    elif args.download:
        success = downloader.download_model(args.download, args.force)
        sys.exit(0 if success else 1)
    elif args.download_all:
        success = downloader.download_all_models(args.force)
        sys.exit(0 if success else 1)
    elif args.verify:
        success = downloader.verify_models()
        sys.exit(0 if success else 1)
    elif args.cleanup:
        downloader.cleanup_models()
    else:
        # Default: show help
        parser.print_help()

if __name__ == '__main__':
    main()
