"""
REVENG v5.0 - Cloud-Distributed Analysis Platform & Cloud Exploitation

Kubernetes-based distributed binary analysis:
- Horizontal scaling for massive binary corpora
- Distributed fuzzing and symbolic execution
- Cloud storage integration
- Job queue management
- Result aggregation

Cloud-Native Exploitation (Modern Hacker's Playbook):
- AWS EBS snapshot triage
- S3 encryption bypass
- Cloud API discovery
- Container security scanning
"""

from .aws_ebs_triage import AWSEBSTriage, EBSSnapshot, SecretMatch
from .cloud_api_analyzer import CloudAPIAnalyzer
from .container_scanner import ContainerScanner
from .s3_encryption_bypass import S3EncryptionBypass

__all__ = [
    "AWSEBSTriage",
    "EBSSnapshot",
    "SecretMatch",
    "S3EncryptionBypass",
    "CloudAPIAnalyzer",
    "ContainerScanner",
]
