#!/usr/bin/env python3
"""
Threat Intelligence Correlator
=============================

IOC extraction, threat intelligence integration, and attribution analysis
for the AI-Enhanced Universal Binary Analysis Engine.

This module provides comprehensive threat intelligence correlation capabilities:
- IOC extraction from malicious binaries
- VirusTotal API integration for hash and domain lookups
- MISP integration for threat intelligence sharing
- MITRE ATT&CK framework mapping
- APT group attribution based on TTPs and code patterns

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import json
import re
import hashlib
import requests
import time
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import urllib.parse
from pathlib import Path

# Import our data models
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ai_enhanced_data_models import (
    IOC, APTAttribution, MITREMapping, MalwareClassification,
    CampaignCorrelation, ThreatIntelligenceReport, Evidence,
    RiskLevel, ConfidenceLevel, EvidenceTracker
)


class ThreatIntelligenceCorrelator:
    """
    Main threat intelligence correlation engine that extracts IOCs,
    correlates with threat intelligence sources, and performs attribution analysis.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the threat intelligence correlator"""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # API configurations
        self.virustotal_api_key = self.config.get('virustotal_api_key')
        self.misp_url = self.config.get('misp_url')
        self.misp_key = self.config.get('misp_key')
        
        # Rate limiting
        self.vt_rate_limit = self.config.get('vt_rate_limit', 4)  # requests per minute
        self.last_vt_request = 0
        
        # Evidence tracker
        self.evidence_tracker = EvidenceTracker()
        
        # Initialize IOC patterns
        self._init_ioc_patterns()
        
        # Initialize MITRE ATT&CK data
        self._init_mitre_attack_data()
        
        # Initialize APT signatures
        self._init_apt_signatures()
    
    def _init_ioc_patterns(self):
        """Initialize IOC extraction patterns"""
        self.ioc_patterns = {
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'registry_key': re.compile(r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*', re.IGNORECASE),
            'file_path': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
            'mutex': re.compile(r'Global\\[A-Za-z0-9_\-]+|Local\\[A-Za-z0-9_\-]+'),
            'service_name': re.compile(r'(?:sc|net)\s+(?:create|start)\s+([A-Za-z0-9_\-]+)', re.IGNORECASE),
            'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'cryptocurrency_address': re.compile(r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b')
        }
    
    def _init_mitre_attack_data(self):
        """Initialize MITRE ATT&CK framework data"""
        # This would typically load from the official MITRE ATT&CK JSON data
        # For now, we'll use a subset of common techniques
        self.mitre_techniques = {
            'T1055': {
                'name': 'Process Injection',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may inject code into processes',
                'keywords': ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'SetWindowsHookEx']
            },
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse command and script interpreters',
                'keywords': ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
            },
            'T1082': {
                'name': 'System Information Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get detailed information about the operating system',
                'keywords': ['GetSystemInfo', 'GetVersionEx', 'systeminfo', 'ver']
            },
            'T1083': {
                'name': 'File and Directory Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may enumerate files and directories',
                'keywords': ['FindFirstFile', 'FindNextFile', 'dir', 'ls']
            },
            'T1105': {
                'name': 'Ingress Tool Transfer',
                'tactic': 'Command and Control',
                'description': 'Adversaries may transfer tools or other files from an external system',
                'keywords': ['URLDownloadToFile', 'WinHttpOpen', 'InternetOpen', 'wget', 'curl']
            },
            'T1112': {
                'name': 'Modify Registry',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may interact with the Windows Registry',
                'keywords': ['RegSetValueEx', 'RegCreateKeyEx', 'RegDeleteKey', 'reg add']
            },
            'T1140': {
                'name': 'Deobfuscate/Decode Files or Information',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may use obfuscated files or information',
                'keywords': ['base64', 'xor', 'decrypt', 'decode', 'unpack']
            },
            'T1547': {
                'name': 'Boot or Logon Autostart Execution',
                'tactic': 'Persistence',
                'description': 'Adversaries may configure system settings to automatically execute',
                'keywords': ['Run', 'RunOnce', 'Startup', 'Services', 'WinLogon']
            }
        }
    
    def _init_apt_signatures(self):
        """Initialize APT group signatures and TTPs"""
        self.apt_signatures = {
            'APT1': {
                'aliases': ['Comment Crew', 'PLA Unit 61398'],
                'ttps': ['T1055', 'T1059', 'T1105'],
                'tools': ['WEBC2', 'BACKDOOR.BARKIOFORK', 'TROJAN.ECLTYS'],
                'indicators': ['comment.php', 'login.php', 'index.asp'],
                'c2_patterns': [r'\.blogspot\.com', r'\.wordpress\.com'],
                'file_patterns': [r'temp\.exe', r'svchost\.exe']
            },
            'APT28': {
                'aliases': ['Fancy Bear', 'Sofacy', 'Sednit'],
                'ttps': ['T1055', 'T1112', 'T1140'],
                'tools': ['X-Agent', 'Seduploader', 'CHOPSTICK'],
                'indicators': ['sofacy', 'fancy', 'bear'],
                'c2_patterns': [r'bit\.ly', r'tinyurl\.com'],
                'file_patterns': [r'flash.*\.exe', r'adobe.*\.exe']
            },
            'APT29': {
                'aliases': ['Cozy Bear', 'The Dukes'],
                'ttps': ['T1059', 'T1083', 'T1105'],
                'tools': ['HAMMERTOSS', 'CORESHELL', 'SEADUKE'],
                'indicators': ['cozy', 'duke', 'hammer'],
                'c2_patterns': [r'twitter\.com', r'github\.com'],
                'file_patterns': [r'office.*\.exe', r'word.*\.exe']
            },
            'Lazarus': {
                'aliases': ['Hidden Cobra', 'Guardians of Peace'],
                'ttps': ['T1055', 'T1140', 'T1547'],
                'tools': ['FALLCHILL', 'SHARPKNOT', 'TYPEFRAME'],
                'indicators': ['lazarus', 'cobra', 'fallchill'],
                'c2_patterns': [r'\.tk$', r'\.ml$'],
                'file_patterns': [r'update.*\.exe', r'install.*\.exe']
            }
        }
        
        # Initialize enhanced behavioral pattern database
        self._init_behavioral_patterns()
        
        # Initialize code similarity database
        self._init_code_similarity_database()
    
    def _init_behavioral_patterns(self):
        """Initialize behavioral pattern matching database for APT attribution"""
        self.behavioral_patterns = {
            'lateral_movement_via_rdp': {
                'indicators': ['mstsc.exe', 'rdp', 'terminal services', '3389'],
                'mitre_techniques': ['T1021.001'],
                'confidence_weight': 0.8,
                'apt_associations': ['APT1', 'APT28', 'FIN7']
            },
            'credential_harvesting_mimikatz': {
                'indicators': ['sekurlsa::logonpasswords', 'lsadump::sam', 'mimikatz', 'gentilkiwi'],
                'mitre_techniques': ['T1003.001', 'T1003.002'],
                'confidence_weight': 0.9,
                'apt_associations': ['APT1', 'APT28', 'APT29', 'FIN7']
            },
            'data_staging_rar': {
                'indicators': ['rar.exe', 'winrar', 'archive', 'compress'],
                'mitre_techniques': ['T1560.001'],
                'confidence_weight': 0.7,
                'apt_associations': ['APT1', 'APT40']
            },
            'spear_phishing_attachments': {
                'indicators': ['attachment', 'document', 'macro', 'vba'],
                'mitre_techniques': ['T1566.001'],
                'confidence_weight': 0.8,
                'apt_associations': ['APT28', 'APT29', 'FIN7']
            },
            'supply_chain_compromise': {
                'indicators': ['update', 'patch', 'installer', 'signed certificate'],
                'mitre_techniques': ['T1195.002'],
                'confidence_weight': 0.9,
                'apt_associations': ['APT29', 'Lazarus']
            },
            'destructive_attacks': {
                'indicators': ['format', 'delete', 'wipe', 'destroy', 'mbr'],
                'mitre_techniques': ['T1485', 'T1561'],
                'confidence_weight': 0.95,
                'apt_associations': ['Lazarus']
            },
            'cryptocurrency_theft': {
                'indicators': ['bitcoin', 'ethereum', 'wallet', 'cryptocurrency', 'mining'],
                'mitre_techniques': ['T1496'],
                'confidence_weight': 0.85,
                'apt_associations': ['Lazarus']
            },
            'web_shell_deployment': {
                'indicators': ['aspx', 'php', 'jsp', 'web shell', 'backdoor'],
                'mitre_techniques': ['T1505.003'],
                'confidence_weight': 0.8,
                'apt_associations': ['APT40', 'APT1']
            },
            'maritime_industry_targeting': {
                'indicators': ['maritime', 'shipping', 'vessel', 'port', 'navigation'],
                'mitre_techniques': ['T1083', 'T1005'],
                'confidence_weight': 0.9,
                'apt_associations': ['APT40']
            },
            'financial_institution_targeting': {
                'indicators': ['bank', 'swift', 'payment', 'financial', 'atm', 'pos'],
                'mitre_techniques': ['T1005', 'T1083'],
                'confidence_weight': 0.85,
                'apt_associations': ['FIN7', 'Lazarus']
            }
        }
    
    def _init_code_similarity_database(self):
        """Initialize code similarity analysis database for malware variant detection"""
        self.code_similarity_signatures = {
            'mutex_patterns': {
                'comment_crew': [r'Global\\[A-Z0-9]{8}-comment', r'Local\\CommentMutex'],
                'fancy_bear': [r'Global\\[A-Z0-9]{8}-fancy', r'Local\\SofacyMutex'],
                'cozy_bear': [r'Global\\[A-Z0-9]{8}-cozy', r'Local\\DukeMutex'],
                'lazarus_group': [r'Global\\[A-Z0-9]{8}-lazarus', r'Local\\HiddenCobraMutex'],
                'leviathan': [r'Global\\[A-Z0-9]{8}-leviathan', r'Local\\MaritimeMutex'],
                'carbanak': [r'Global\\[A-Z0-9]{8}-carbanak', r'Local\\FinancialMutex']
            },
            'encryption_patterns': {
                'xor_keys': {
                    'apt28': ['0x99', '0xAA', '0x55'],
                    'apt29': ['0x42', '0x13', '0x37'],
                    'lazarus': ['0xFF', '0x00', '0x88'],
                    'apt40': ['0x33', '0x66', '0xCC'],
                    'fin7': ['0x77', '0xBB', '0xDD']
                },
                'rc4_keys': {
                    'apt1': ['comment_crew_key', 'shanghai_key'],
                    'apt40': ['leviathan_key', 'maritime_key'],
                    'fin7': ['carbanak_key', 'financial_key']
                }
            },
            'network_patterns': {
                'user_agents': {
                    'apt28': ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko - Fancy'],
                    'apt29': ['Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) - Cozy'],
                    'lazarus': ['Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0) - Hidden'],
                    'apt40': ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 - Maritime'],
                    'fin7': ['Mozilla/5.0 (Windows NT 6.3; WOW64; rv:36.0) Gecko/20100101 - Financial']
                },
                'c2_protocols': {
                    'http_post_patterns': {
                        'apt1': [r'POST /comment\.php', r'POST /login\.asp'],
                        'apt28': [r'POST /flash/.*\.php', r'POST /adobe/.*\.asp'],
                        'apt40': [r'POST /maritime/.*\.php', r'POST /shipping/.*\.asp'],
                        'fin7': [r'POST /invoice/.*\.php', r'POST /payment/.*\.asp']
                    }
                }
            },
            'file_structure_patterns': {
                'pe_sections': {
                    'apt28': ['.fancy', '.sofacy', '.sednit'],
                    'apt29': ['.cozy', '.duke', '.hammer'],
                    'lazarus': ['.cobra', '.hidden', '.fallchill'],
                    'apt40': ['.leviathan', '.maritime', '.kryptonite'],
                    'fin7': ['.carbanak', '.financial', '.navigator']
                },
                'resource_patterns': {
                    'version_info': {
                        'apt1': ['Comment Crew Tools', 'Shanghai Software'],
                        'apt40': ['Maritime Solutions', 'Leviathan Tools'],
                        'fin7': ['Financial Software', 'Payment Solutions']
                    }
                }
            },
            'string_patterns': {
                'debug_strings': {
                    'apt28': ['fancy_bear_debug', 'sofacy_module'],
                    'apt29': ['cozy_bear_debug', 'duke_module'],
                    'lazarus': ['hidden_cobra_debug', 'lazarus_module'],
                    'apt40': ['leviathan_debug', 'maritime_module'],
                    'fin7': ['carbanak_debug', 'financial_module']
                },
                'error_messages': {
                    'apt1': ['Comment system error', 'Shanghai connection failed'],
                    'apt28': ['Fancy connection error', 'Sofacy module failed'],
                    'apt29': ['Cozy system error', 'Duke connection failed']
                }
            }
        }
    
    def extract_iocs_from_binary(self, file_path: str, decompiled_code: str = None, 
                                strings_data: List[str] = None) -> List[IOC]:
        """
        Extract Indicators of Compromise from binary analysis results
        
        Args:
            file_path: Path to the analyzed binary
            decompiled_code: Decompiled source code
            strings_data: Extracted strings from the binary
            
        Returns:
            List of extracted IOCs
        """
        iocs = []
        
        try:
            # Extract IOCs from file content
            if decompiled_code:
                iocs.extend(self._extract_iocs_from_text(decompiled_code, "decompiled_code"))
            
            if strings_data:
                for string_item in strings_data:
                    iocs.extend(self._extract_iocs_from_text(string_item, "strings"))
            
            # Extract file-based IOCs
            file_iocs = self._extract_file_iocs(file_path)
            iocs.extend(file_iocs)
            
            # Deduplicate IOCs
            unique_iocs = self._deduplicate_iocs(iocs)
            
            # Add evidence for IOC extraction
            evidence = Evidence(
                type="ioc_extraction",
                description=f"Extracted {len(unique_iocs)} unique IOCs from binary analysis",
                source="threat_intelligence_correlator",
                confidence=0.8,
                metadata={"file_path": file_path, "ioc_count": len(unique_iocs)}
            )
            self.evidence_tracker.add_evidence(
                "ioc_extraction",
                evidence.description,
                evidence.source,
                evidence.confidence,
                evidence.metadata
            )
            
            self.logger.info(f"Extracted {len(unique_iocs)} IOCs from {file_path}")
            return unique_iocs
            
        except Exception as e:
            self.logger.error(f"Error extracting IOCs: {str(e)}")
            return []
    
    def _extract_iocs_from_text(self, text: str, source: str) -> List[IOC]:
        """Extract IOCs from text content"""
        iocs = []
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                # Filter out common false positives
                if self._is_valid_ioc(ioc_type, match):
                    ioc = IOC(
                        type=ioc_type,
                        value=match,
                        description=f"{ioc_type.replace('_', ' ').title()} found in {source}",
                        confidence=self._calculate_ioc_confidence(ioc_type, match),
                        source=source,
                        first_seen=datetime.now().timestamp()
                    )
                    iocs.append(ioc)
        
        return iocs
    
    def _extract_file_iocs(self, file_path: str) -> List[IOC]:
        """Extract file-based IOCs (hashes, etc.)"""
        iocs = []
        
        try:
            # Calculate file hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            
            iocs.extend([
                IOC(
                    type="md5",
                    value=md5_hash,
                    description="MD5 hash of analyzed file",
                    confidence=1.0,
                    source="file_analysis"
                ),
                IOC(
                    type="sha1",
                    value=sha1_hash,
                    description="SHA1 hash of analyzed file",
                    confidence=1.0,
                    source="file_analysis"
                ),
                IOC(
                    type="sha256",
                    value=sha256_hash,
                    description="SHA256 hash of analyzed file",
                    confidence=1.0,
                    source="file_analysis"
                )
            ])
            
        except Exception as e:
            self.logger.error(f"Error calculating file hashes: {str(e)}")
        
        return iocs
    
    def _is_valid_ioc(self, ioc_type: str, value: str) -> bool:
        """Validate IOC to filter false positives"""
        # Common false positive filters
        false_positives = {
            'ip_address': ['0.0.0.0', '127.0.0.1', '255.255.255.255'],
            'domain': ['localhost', 'example.com', 'test.com', 'microsoft.com', 'google.com'],
            'email': ['test@test.com', 'admin@admin.com'],
            'file_path': ['C:\\Windows\\System32', 'C:\\Program Files']
        }
        
        if ioc_type in false_positives:
            for fp in false_positives[ioc_type]:
                if fp.lower() in value.lower():
                    return False
        
        # Additional validation rules
        if ioc_type == 'domain' and len(value) < 4:
            return False
        
        if ioc_type == 'ip_address':
            parts = value.split('.')
            if any(int(part) > 255 for part in parts):
                return False
        
        return True
    
    def _calculate_ioc_confidence(self, ioc_type: str, value: str) -> float:
        """Calculate confidence score for IOC"""
        base_confidence = {
            'md5': 1.0,
            'sha1': 1.0,
            'sha256': 1.0,
            'ip_address': 0.7,
            'domain': 0.8,
            'url': 0.9,
            'email': 0.6,
            'registry_key': 0.8,
            'file_path': 0.6,
            'mutex': 0.9,
            'service_name': 0.7,
            'bitcoin_address': 0.95,
            'cryptocurrency_address': 0.9
        }
        
        confidence = base_confidence.get(ioc_type, 0.5)
        
        # Adjust confidence based on value characteristics
        if ioc_type == 'domain':
            # Suspicious TLDs increase confidence
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            if any(value.endswith(tld) for tld in suspicious_tlds):
                confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _deduplicate_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """Remove duplicate IOCs"""
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            key = (ioc.type, ioc.value.lower())
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        return unique_iocs
    
    def correlate_with_virustotal(self, iocs: List[IOC]) -> Dict[str, Any]:
        """
        Correlate IOCs with VirusTotal threat intelligence
        
        Args:
            iocs: List of IOCs to check
            
        Returns:
            Dictionary containing VirusTotal correlation results
        """
        if not self.virustotal_api_key:
            self.logger.warning("VirusTotal API key not configured")
            return {"error": "API key not configured"}
        
        vt_results = {}
        
        for ioc in iocs:
            if ioc.type in ['md5', 'sha1', 'sha256', 'ip_address', 'domain', 'url']:
                try:
                    # Rate limiting
                    self._enforce_rate_limit()
                    
                    result = self._query_virustotal(ioc)
                    if result:
                        vt_results[ioc.value] = result
                        
                        # Update IOC confidence based on VT results
                        if result.get('positives', 0) > 0:
                            ioc.confidence = min(ioc.confidence + 0.2, 1.0)
                            ioc.tags.append('virustotal_detected')
                        
                        # Add evidence
                        evidence = Evidence(
                            type="virustotal_correlation",
                            description=f"VirusTotal detection: {result.get('positives', 0)}/{result.get('total', 0)}",
                            source="virustotal_api",
                            confidence=0.9,
                            metadata={"ioc_value": ioc.value, "vt_result": result}
                        )
                        self.evidence_tracker.add_evidence(
                            evidence.type,
                            evidence.description,
                            evidence.source,
                            evidence.confidence,
                            evidence.metadata
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error querying VirusTotal for {ioc.value}: {str(e)}")
        
        return vt_results
    
    def _query_virustotal(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API for IOC information"""
        base_url = "https://www.virustotal.com/vtapi/v2"
        
        if ioc.type in ['md5', 'sha1', 'sha256']:
            url = f"{base_url}/file/report"
            params = {
                'apikey': self.virustotal_api_key,
                'resource': ioc.value
            }
        elif ioc.type == 'ip_address':
            url = f"{base_url}/ip-address/report"
            params = {
                'apikey': self.virustotal_api_key,
                'ip': ioc.value
            }
        elif ioc.type == 'domain':
            url = f"{base_url}/domain/report"
            params = {
                'apikey': self.virustotal_api_key,
                'domain': ioc.value
            }
        elif ioc.type == 'url':
            url = f"{base_url}/url/report"
            params = {
                'apikey': self.virustotal_api_key,
                'resource': ioc.value
            }
        else:
            return None
        
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if data.get('response_code') == 1:
                return data
            else:
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal API request failed: {str(e)}")
            return None
    
    def _enforce_rate_limit(self):
        """Enforce VirusTotal API rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_vt_request
        min_interval = 60.0 / self.vt_rate_limit  # seconds between requests
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_vt_request = time.time()
    
    def integrate_with_misp(self, iocs: List[IOC], event_info: str = None) -> Dict[str, Any]:
        """
        Integrate with MISP (Malware Information Sharing Platform)
        
        Args:
            iocs: List of IOCs to share/query
            event_info: Optional event information
            
        Returns:
            Dictionary containing MISP integration results
        """
        if not self.misp_url or not self.misp_key:
            self.logger.warning("MISP configuration not available")
            return {"error": "MISP not configured"}
        
        try:
            # Query existing events for IOCs
            misp_results = self._query_misp_events(iocs)
            
            # Optionally create new event with IOCs
            if event_info and len(iocs) > 0:
                new_event = self._create_misp_event(iocs, event_info)
                misp_results['new_event'] = new_event
            
            # Add evidence for MISP correlation
            evidence = Evidence(
                type="misp_correlation",
                description=f"MISP correlation completed for {len(iocs)} IOCs",
                source="misp_platform",
                confidence=0.8,
                metadata={"ioc_count": len(iocs), "results": misp_results}
            )
            self.evidence_tracker.add_evidence(
                evidence.type,
                evidence.description,
                evidence.source,
                evidence.confidence,
                evidence.metadata
            )
            
            return misp_results
            
        except Exception as e:
            self.logger.error(f"MISP integration error: {str(e)}")
            return {"error": str(e)}
    
    def _query_misp_events(self, iocs: List[IOC]) -> Dict[str, Any]:
        """Query MISP for existing events containing IOCs"""
        headers = {
            'Authorization': self.misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        results = {}
        
        for ioc in iocs[:10]:  # Limit to first 10 IOCs to avoid overwhelming MISP
            try:
                url = f"{self.misp_url}/attributes/restSearch"
                data = {
                    'value': ioc.value,
                    'type': self._map_ioc_type_to_misp(ioc.type)
                }
                
                response = requests.post(url, headers=headers, json=data, timeout=30)
                if response.status_code == 200:
                    results[ioc.value] = response.json()
                
            except Exception as e:
                self.logger.error(f"Error querying MISP for {ioc.value}: {str(e)}")
        
        return results
    
    def _create_misp_event(self, iocs: List[IOC], event_info: str) -> Dict[str, Any]:
        """Create new MISP event with IOCs"""
        headers = {
            'Authorization': self.misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        event_data = {
            'Event': {
                'info': event_info,
                'distribution': '1',  # This community only
                'threat_level_id': '2',  # Medium
                'analysis': '1',  # Ongoing
                'Attribute': []
            }
        }
        
        # Add IOCs as attributes
        for ioc in iocs:
            attribute = {
                'type': self._map_ioc_type_to_misp(ioc.type),
                'value': ioc.value,
                'comment': ioc.description,
                'distribution': '1'
            }
            event_data['Event']['Attribute'].append(attribute)
        
        try:
            url = f"{self.misp_url}/events"
            response = requests.post(url, headers=headers, json=event_data, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Failed to create MISP event: {response.status_code}")
                return {"error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            self.logger.error(f"Error creating MISP event: {str(e)}")
            return {"error": str(e)}
    
    def _map_ioc_type_to_misp(self, ioc_type: str) -> str:
        """Map IOC type to MISP attribute type"""
        mapping = {
            'md5': 'md5',
            'sha1': 'sha1',
            'sha256': 'sha256',
            'ip_address': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'email': 'email-src',
            'registry_key': 'regkey',
            'file_path': 'filename',
            'mutex': 'mutex'
        }
        return mapping.get(ioc_type, 'other')
    
    def map_to_mitre_attack_enhanced(self, decompiled_code: str = None, 
                                   function_calls: List[str] = None,
                                   api_calls: List[str] = None,
                                   file_paths: List[str] = None,
                                   registry_keys: List[str] = None,
                                   network_indicators: List[str] = None) -> MITREMapping:
        """
        Enhanced MITRE ATT&CK technique mapping with comprehensive analysis
        
        Args:
            decompiled_code: Decompiled source code to analyze
            function_calls: List of detected function calls
            api_calls: List of detected API calls
            file_paths: List of file paths found in analysis
            registry_keys: List of registry keys found
            network_indicators: List of network-related indicators
            
        Returns:
            Comprehensive MITRE ATT&CK mapping with confidence scores and attack chain analysis
        """
        mapping = MITREMapping()
        
        try:
            # Build comprehensive analysis context
            analysis_context = self._build_analysis_context_enhanced(
                decompiled_code, function_calls, api_calls, 
                file_paths, registry_keys, network_indicators
            )
            
            # Enhanced technique detection using multiple methods
            technique_matches = {}
            
            # 1. Enhanced keyword-based detection
            keyword_matches = self._detect_by_keywords_enhanced(analysis_context)
            self._merge_technique_matches(technique_matches, keyword_matches)
            
            # 2. API call pattern detection with sequences
            if api_calls:
                api_matches = self._detect_by_api_patterns_enhanced(api_calls)
                self._merge_technique_matches(technique_matches, api_matches)
            
            # 3. Behavioral pattern detection
            behavioral_matches = self._detect_by_behavioral_patterns_enhanced(analysis_context)
            self._merge_technique_matches(technique_matches, behavioral_matches)
            
            # 4. Registry pattern detection
            if registry_keys:
                registry_matches = self._detect_by_registry_patterns_enhanced(registry_keys)
                self._merge_technique_matches(technique_matches, registry_matches)
            
            # 5. File pattern detection
            if file_paths:
                file_matches = self._detect_by_file_patterns_enhanced(file_paths)
                self._merge_technique_matches(technique_matches, file_matches)
            
            # Build enhanced mapping with attack chain analysis
            mapping = self._build_enhanced_mapping(technique_matches)
            
            # Generate attack chain visualization
            attack_chain = self._analyze_attack_chain_enhanced(mapping)
            mapping.attack_chain = attack_chain
            
            # Add comprehensive evidence
            evidence = Evidence(
                type="mitre_attack_mapping_enhanced",
                description=f"Enhanced mapping of {len(mapping.techniques)} MITRE ATT&CK techniques with confidence scoring and attack chain analysis",
                source="threat_intelligence_correlator_enhanced",
                confidence=0.9,
                metadata={
                    "techniques_count": len(mapping.techniques),
                    "tactics_count": len(mapping.tactics),
                    "kill_chain_phases": len(mapping.kill_chain_phases),
                    "avg_confidence": sum(mapping.confidence_scores.values()) / len(mapping.confidence_scores) if mapping.confidence_scores else 0,
                    "detection_methods": ["keyword_matching", "api_pattern_analysis", "behavioral_analysis", "registry_analysis", "file_analysis"]
                }
            )
            self.evidence_tracker.add_evidence(
                evidence.type,
                evidence.description,
                evidence.source,
                evidence.confidence,
                evidence.metadata
            )
            
            self.logger.info(f"Enhanced MITRE ATT&CK mapping completed: {len(mapping.techniques)} techniques mapped")
            return mapping
            
        except Exception as e:
            self.logger.error(f"Error in enhanced MITRE ATT&CK mapping: {str(e)}")
            return mapping

    def map_to_mitre_attack(self, decompiled_code: str, function_calls: List[str] = None,
                           api_calls: List[str] = None) -> MITREMapping:
        """
        Map detected behaviors to MITRE ATT&CK techniques
        
        Args:
            decompiled_code: Decompiled source code to analyze
            function_calls: List of detected function calls
            api_calls: List of detected API calls
            
        Returns:
            MITRE ATT&CK mapping with techniques and confidence scores
        """
        mapping = MITREMapping()
        
        try:
            # Combine all analysis sources
            analysis_text = decompiled_code or ""
            if function_calls:
                analysis_text += " " + " ".join(function_calls)
            if api_calls:
                analysis_text += " " + " ".join(api_calls)
            
            analysis_text = analysis_text.lower()
            
            # Map techniques based on keywords
            for technique_id, technique_data in self.mitre_techniques.items():
                confidence = 0.0
                matched_keywords = []
                
                for keyword in technique_data['keywords']:
                    if keyword.lower() in analysis_text:
                        confidence += 0.2
                        matched_keywords.append(keyword)
                
                # Normalize confidence
                confidence = min(confidence, 1.0)
                
                if confidence > 0.3:  # Threshold for inclusion
                    mapping.techniques.append(technique_id)
                    mapping.confidence_scores[technique_id] = confidence
                    
                    # Add tactic if not already present
                    tactic = technique_data['tactic']
                    if tactic not in mapping.tactics:
                        mapping.tactics.append(tactic)
                    
                    # Store technique details
                    mapping.technique_details[technique_id] = {
                        'name': technique_data['name'],
                        'tactic': tactic,
                        'description': technique_data['description'],
                        'matched_keywords': matched_keywords,
                        'confidence': confidence
                    }
            
            # Determine kill chain phases based on tactics
            kill_chain_mapping = {
                'Initial Access': 'initial-access',
                'Execution': 'execution',
                'Persistence': 'persistence',
                'Privilege Escalation': 'privilege-escalation',
                'Defense Evasion': 'defense-evasion',
                'Credential Access': 'credential-access',
                'Discovery': 'discovery',
                'Lateral Movement': 'lateral-movement',
                'Collection': 'collection',
                'Command and Control': 'command-and-control',
                'Exfiltration': 'exfiltration',
                'Impact': 'impact'
            }
            
            for tactic in mapping.tactics:
                if tactic in kill_chain_mapping:
                    phase = kill_chain_mapping[tactic]
                    if phase not in mapping.kill_chain_phases:
                        mapping.kill_chain_phases.append(phase)
            
            # Add evidence for MITRE mapping
            evidence = Evidence(
                type="mitre_attack_mapping",
                description=f"Mapped {len(mapping.techniques)} MITRE ATT&CK techniques",
                source="mitre_attack_analyzer",
                confidence=0.8,
                metadata={
                    "techniques": mapping.techniques,
                    "tactics": mapping.tactics,
                    "confidence_scores": mapping.confidence_scores
                }
            )
            self.evidence_tracker.add_evidence(
                evidence.type,
                evidence.description,
                evidence.source,
                evidence.confidence,
                evidence.metadata
            )
            
            self.logger.info(f"Mapped {len(mapping.techniques)} MITRE ATT&CK techniques")
            return mapping
            
        except Exception as e:
            self.logger.error(f"Error mapping to MITRE ATT&CK: {str(e)}")
            return mapping
    
    def _build_analysis_context_enhanced(self, decompiled_code: str, function_calls: List[str],
                                       api_calls: List[str], file_paths: List[str],
                                       registry_keys: List[str], network_indicators: List[str]) -> Dict[str, str]:
        """Build comprehensive analysis context for enhanced MITRE mapping"""
        context = {}
        
        if decompiled_code:
            context['code'] = decompiled_code.lower()
        
        if function_calls:
            context['functions'] = ' '.join(function_calls).lower()
        
        if api_calls:
            context['apis'] = ' '.join(api_calls).lower()
        
        if file_paths:
            context['files'] = ' '.join(file_paths).lower()
        
        if registry_keys:
            context['registry'] = ' '.join(registry_keys).lower()
        
        if network_indicators:
            context['network'] = ' '.join(network_indicators).lower()
        
        # Combined context for general analysis
        all_text = []
        for key, value in context.items():
            if value:
                all_text.append(value)
        context['combined'] = ' '.join(all_text)
        
        return context
    
    def _detect_by_keywords_enhanced(self, analysis_context: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Enhanced keyword-based technique detection"""
        matches = {}
        combined_text = analysis_context.get('combined', '')
        
        for technique_id, technique_data in self.mitre_techniques.items():
            confidence = 0.0
            matched_keywords = []
            
            for keyword in technique_data['keywords']:
                if keyword.lower() in combined_text:
                    confidence += 0.15
                    matched_keywords.append(keyword)
            
            if confidence > 0:
                matches[technique_id] = {
                    'confidence': min(confidence, 1.0),
                    'evidence': f"Keywords matched: {', '.join(matched_keywords)}",
                    'detection_method': 'enhanced_keyword_matching',
                    'matched_keywords': matched_keywords
                }
        
        return matches
    
    def _detect_by_api_patterns_enhanced(self, api_calls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enhanced API call pattern detection with sequence analysis"""
        matches = {}
        api_text = ' '.join(api_calls).lower()
        
        # Enhanced API call sequences for specific techniques
        api_sequences = {
            'T1055': [  # Process Injection
                ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
                ['NtOpenProcess', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx']
            ],
            'T1003': [  # OS Credential Dumping
                ['OpenProcess', 'ReadProcessMemory'],  # LSASS access
                ['LsaEnumerateLogonSessions', 'LsaGetLogonSessionData']
            ],
            'T1112': [  # Registry Modification
                ['RegOpenKeyEx', 'RegSetValueEx'],
                ['RegCreateKeyEx', 'RegSetValueEx']
            ]
        }
        
        for technique_id, technique_data in self.mitre_techniques.items():
            confidence = 0.0
            matched_apis = []
            
            # Check individual API calls
            for keyword in technique_data.get('keywords', []):
                if keyword.lower() in api_text:
                    confidence += 0.2
                    matched_apis.append(keyword)
            
            # Check for API call sequences
            if technique_id in api_sequences:
                for sequence in api_sequences[technique_id]:
                    sequence_found = True
                    for api in sequence:
                        if api.lower() not in api_text:
                            sequence_found = False
                            break
                    
                    if sequence_found:
                        confidence += 0.4  # Higher confidence for sequences
                        matched_apis.extend(sequence)
                        break
            
            if confidence > 0:
                matches[technique_id] = {
                    'confidence': min(confidence, 1.0),
                    'evidence': f"API patterns matched: {', '.join(set(matched_apis))}",
                    'detection_method': 'enhanced_api_pattern_matching',
                    'matched_apis': list(set(matched_apis))
                }
        
        return matches
    
    def _detect_by_behavioral_patterns_enhanced(self, analysis_context: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Enhanced behavioral pattern detection"""
        matches = {}
        
        # Enhanced behavioral patterns
        behavioral_patterns = {
            'network_communication': {
                'patterns': [
                    r'InternetOpen.*HttpOpenRequest.*HttpSendRequest',
                    r'socket.*connect.*send',
                    r'WinHttpOpen.*WinHttpConnect.*WinHttpSendRequest'
                ],
                'techniques': ['T1071', 'T1105']  # Application Layer Protocol, Ingress Tool Transfer
            },
            'file_operations': {
                'patterns': [
                    r'CreateFile.*WriteFile.*CloseHandle',
                    r'fopen.*fwrite.*fclose',
                    r'CopyFile.*MoveFile'
                ],
                'techniques': ['T1005', 'T1083']  # Data from Local System, File Discovery
            },
            'registry_modification': {
                'patterns': [
                    r'RegOpenKey.*RegSetValue',
                    r'RegCreateKey.*RegSetValue'
                ],
                'techniques': ['T1112', 'T1547']  # Modify Registry, Boot/Logon Autostart
            },
            'process_manipulation': {
                'patterns': [
                    r'OpenProcess.*WriteProcessMemory.*CreateRemoteThread',
                    r'CreateProcess.*ResumeThread'
                ],
                'techniques': ['T1055', 'T1059']  # Process Injection, Command Execution
            }
        }
        
        for pattern_name, pattern_data in behavioral_patterns.items():
            for pattern in pattern_data['patterns']:
                for context_type, context_text in analysis_context.items():
                    if re.search(pattern, context_text, re.IGNORECASE):
                        for technique_id in pattern_data['techniques']:
                            if technique_id not in matches:
                                matches[technique_id] = {
                                    'confidence': 0.3,
                                    'evidence': f"Behavioral pattern '{pattern_name}' detected",
                                    'detection_method': 'enhanced_behavioral_pattern',
                                    'pattern': pattern_name
                                }
                            else:
                                matches[technique_id]['confidence'] += 0.1
                                matches[technique_id]['confidence'] = min(matches[technique_id]['confidence'], 1.0)
        
        return matches
    
    def _detect_by_registry_patterns_enhanced(self, registry_keys: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enhanced registry pattern detection"""
        matches = {}
        
        # Enhanced registry patterns for specific techniques
        registry_patterns = {
            'T1547': [  # Boot/Logon Autostart Execution
                r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ],
            'T1112': [  # Modify Registry
                r'HKEY_.*',  # Any registry modification
                r'SOFTWARE\\Classes\\',
                r'SYSTEM\\CurrentControlSet\\Services'
            ],
            'T1543': [  # Create or Modify System Process
                r'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services'
            ]
        }
        
        for technique_id, patterns in registry_patterns.items():
            confidence = 0.0
            matched_patterns = []
            
            for pattern in patterns:
                for reg_key in registry_keys:
                    if re.search(pattern, reg_key, re.IGNORECASE):
                        confidence += 0.3
                        matched_patterns.append(pattern)
            
            if confidence > 0:
                matches[technique_id] = {
                    'confidence': min(confidence, 1.0),
                    'evidence': f"Registry patterns matched: {', '.join(set(matched_patterns))}",
                    'detection_method': 'enhanced_registry_pattern_matching',
                    'matched_patterns': list(set(matched_patterns))
                }
        
        return matches
    
    def _detect_by_file_patterns_enhanced(self, file_paths: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enhanced file pattern detection"""
        matches = {}
        
        # Enhanced file patterns for specific techniques
        file_patterns = {
            'T1059': [  # Command and Scripting Interpreter
                r'\.bat$', r'\.cmd$', r'\.ps1$', r'\.vbs$', r'\.js$'
            ],
            'T1566': [  # Phishing
                r'\.doc[xm]?$', r'\.pdf$', r'\.zip$', r'\.rar$'
            ],
            'T1105': [  # Ingress Tool Transfer
                r'\.exe$', r'\.dll$', r'\.scr$'
            ],
            'T1027': [  # Obfuscated Files or Information
                r'\.tmp$', r'\.dat$', r'[a-f0-9]{32}', r'[a-f0-9]{40}'  # Suspicious extensions and hashes
            ]
        }
        
        for technique_id, patterns in file_patterns.items():
            confidence = 0.0
            matched_files = []
            
            for pattern in patterns:
                for file_path in file_paths:
                    if re.search(pattern, file_path, re.IGNORECASE):
                        confidence += 0.2
                        matched_files.append(file_path)
            
            if confidence > 0:
                matches[technique_id] = {
                    'confidence': min(confidence, 1.0),
                    'evidence': f"File patterns matched: {', '.join(set(matched_files))}",
                    'detection_method': 'enhanced_file_pattern_matching',
                    'matched_files': list(set(matched_files))
                }
        
        return matches
    
    def _merge_technique_matches(self, target: Dict[str, Dict[str, Any]], 
                                source: Dict[str, Dict[str, Any]]):
        """Merge technique matches from different detection methods"""
        for technique_id, match_data in source.items():
            if technique_id in target:
                # Combine confidence scores (weighted average)
                existing_conf = target[technique_id]['confidence']
                new_conf = match_data['confidence']
                combined_conf = (existing_conf + new_conf) / 2
                target[technique_id]['confidence'] = min(combined_conf, 1.0)
                
                # Combine evidence
                target[technique_id]['evidence'] += f"; {match_data['evidence']}"
                
                # Add detection methods
                if 'detection_methods' not in target[technique_id]:
                    target[technique_id]['detection_methods'] = [target[technique_id]['detection_method']]
                target[technique_id]['detection_methods'].append(match_data['detection_method'])
            else:
                target[technique_id] = match_data.copy()
    
    def _build_enhanced_mapping(self, technique_matches: Dict[str, Dict[str, Any]]) -> MITREMapping:
        """Build enhanced MITRE mapping from technique matches"""
        mapping = MITREMapping()
        
        # Enhanced confidence threshold
        confidence_threshold = 0.25
        
        for technique_id, match_data in technique_matches.items():
            if match_data['confidence'] >= confidence_threshold:
                technique_data = self.mitre_techniques.get(technique_id)
                if technique_data:
                    mapping.techniques.append(technique_id)
                    mapping.confidence_scores[technique_id] = match_data['confidence']
                    
                    # Add tactic if not already present
                    tactic = technique_data['tactic']
                    if tactic not in mapping.tactics:
                        mapping.tactics.append(tactic)
                    
                    # Store enhanced technique information
                    mapping.technique_details[technique_id] = {
                        'name': technique_data['name'],
                        'tactic': tactic,
                        'description': technique_data['description'],
                        'confidence': match_data['confidence'],
                        'evidence': match_data['evidence'],
                        'detection_methods': match_data.get('detection_methods', [match_data.get('detection_method', 'unknown')]),
                        'matched_indicators': {
                            'keywords': match_data.get('matched_keywords', []),
                            'apis': match_data.get('matched_apis', []),
                            'patterns': match_data.get('matched_patterns', []),
                            'files': match_data.get('matched_files', [])
                        }
                    }
        
        # Enhanced kill chain phase mapping
        kill_chain_mapping = {
            'Initial Access': 'initial-access',
            'Execution': 'execution',
            'Persistence': 'persistence',
            'Privilege Escalation': 'privilege-escalation',
            'Defense Evasion': 'defense-evasion',
            'Credential Access': 'credential-access',
            'Discovery': 'discovery',
            'Lateral Movement': 'lateral-movement',
            'Collection': 'collection',
            'Command and Control': 'command-and-control',
            'Exfiltration': 'exfiltration',
            'Impact': 'impact'
        }
        
        for tactic in mapping.tactics:
            if tactic in kill_chain_mapping:
                phase = kill_chain_mapping[tactic]
                if phase not in mapping.kill_chain_phases:
                    mapping.kill_chain_phases.append(phase)
        
        return mapping
    
    def _analyze_attack_chain_enhanced(self, mapping: MITREMapping):
        """Enhanced attack chain analysis with timeline and progression"""
        from .ai_enhanced_data_models import AttackChain
        
        attack_chain = AttackChain()
        
        # Phase ordering for logical attack progression
        phase_order = [
            'initial-access', 'execution', 'persistence', 'privilege-escalation',
            'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
            'collection', 'command-and-control', 'exfiltration', 'impact'
        ]
        
        # Group techniques by kill chain phase
        techniques_by_phase = {}
        for technique_id in mapping.techniques:
            technique_data = self.mitre_techniques.get(technique_id)
            if technique_data:
                tactic = technique_data['tactic']
                kill_chain_mapping = {
                    'Initial Access': 'initial-access',
                    'Execution': 'execution',
                    'Persistence': 'persistence',
                    'Privilege Escalation': 'privilege-escalation',
                    'Defense Evasion': 'defense-evasion',
                    'Credential Access': 'credential-access',
                    'Discovery': 'discovery',
                    'Lateral Movement': 'lateral-movement',
                    'Collection': 'collection',
                    'Command and Control': 'command-and-control',
                    'Exfiltration': 'exfiltration',
                    'Impact': 'impact'
                }
                
                if tactic in kill_chain_mapping:
                    phase = kill_chain_mapping[tactic]
                    if phase not in techniques_by_phase:
                        techniques_by_phase[phase] = []
                    techniques_by_phase[phase].append(technique_id)
        
        # Order phases according to attack progression
        ordered_phases = []
        for phase in phase_order:
            if phase in techniques_by_phase:
                ordered_phases.append(phase)
        
        attack_chain.phases = ordered_phases
        attack_chain.techniques_by_phase = techniques_by_phase
        
        # Calculate confidence by phase
        for phase, techniques in techniques_by_phase.items():
            phase_confidence = 0.0
            for technique_id in techniques:
                phase_confidence += mapping.confidence_scores.get(technique_id, 0.0)
            attack_chain.confidence_by_phase[phase] = phase_confidence / len(techniques) if techniques else 0.0
        
        # Create enhanced timeline with progression analysis
        timestamp = datetime.now().timestamp()
        for i, phase in enumerate(ordered_phases):
            for technique_id in techniques_by_phase[phase]:
                attack_chain.timeline.append((
                    phase, 
                    technique_id, 
                    timestamp + (i * 300)  # 5-minute intervals between phases
                ))
        
        return attack_chain
    
    def generate_mitre_attack_report(self, mapping: MITREMapping) -> Dict[str, Any]:
        """Generate comprehensive MITRE ATT&CK analysis report"""
        report = {
            'summary': {},
            'techniques': [],
            'tactics': [],
            'kill_chain_analysis': {},
            'attack_progression': {},
            'recommendations': []
        }
        
        try:
            # Enhanced summary statistics
            report['summary'] = {
                'total_techniques': len(mapping.techniques),
                'total_tactics': len(mapping.tactics),
                'kill_chain_phases': len(mapping.kill_chain_phases),
                'avg_confidence': sum(mapping.confidence_scores.values()) / len(mapping.confidence_scores) if mapping.confidence_scores else 0.0,
                'confidence_distribution': self._calculate_confidence_distribution_enhanced(mapping.confidence_scores),
                'coverage_score': len(mapping.kill_chain_phases) / 12 * 100  # Percentage of kill chain covered
            }
            
            # Enhanced technique analysis
            for technique_id in mapping.techniques:
                technique_data = self.mitre_techniques.get(technique_id)
                technique_details = mapping.technique_details.get(technique_id, {})
                
                if technique_data:
                    technique_info = {
                        'id': technique_id,
                        'name': technique_data['name'],
                        'tactic': technique_data['tactic'],
                        'description': technique_data['description'],
                        'confidence': mapping.confidence_scores.get(technique_id, 0.0),
                        'evidence': technique_details.get('evidence', 'No evidence available'),
                        'detection_methods': technique_details.get('detection_methods', []),
                        'matched_indicators': technique_details.get('matched_indicators', {}),
                        'risk_level': self._calculate_technique_risk_level(technique_id, mapping.confidence_scores.get(technique_id, 0.0))
                    }
                    report['techniques'].append(technique_info)
            
            # Enhanced tactic analysis
            tactic_stats = {}
            for technique_id in mapping.techniques:
                technique_data = self.mitre_techniques.get(technique_id)
                if technique_data:
                    tactic = technique_data['tactic']
                    if tactic not in tactic_stats:
                        tactic_stats[tactic] = {
                            'technique_count': 0,
                            'avg_confidence': 0.0,
                            'techniques': [],
                            'max_confidence': 0.0
                        }
                    tactic_stats[tactic]['technique_count'] += 1
                    tactic_stats[tactic]['techniques'].append(technique_id)
                    
                    confidence = mapping.confidence_scores.get(technique_id, 0.0)
                    tactic_stats[tactic]['max_confidence'] = max(tactic_stats[tactic]['max_confidence'], confidence)
            
            # Calculate average confidence per tactic
            for tactic, stats in tactic_stats.items():
                confidences = [mapping.confidence_scores.get(tid, 0.0) for tid in stats['techniques']]
                stats['avg_confidence'] = sum(confidences) / len(confidences) if confidences else 0.0
            
            report['tactics'] = [
                {
                    'name': tactic,
                    'technique_count': stats['technique_count'],
                    'avg_confidence': stats['avg_confidence'],
                    'max_confidence': stats['max_confidence'],
                    'techniques': stats['techniques'],
                    'kill_chain_phase': self._get_kill_chain_phase_for_tactic(tactic)
                }
                for tactic, stats in tactic_stats.items()
            ]
            
            # Kill chain analysis
            if hasattr(mapping, 'attack_chain') and mapping.attack_chain:
                report['kill_chain_analysis'] = {
                    'phases_covered': mapping.attack_chain.phases,
                    'phase_confidence': mapping.attack_chain.confidence_by_phase,
                    'techniques_by_phase': mapping.attack_chain.techniques_by_phase,
                    'attack_progression_score': self._calculate_attack_progression_score(mapping.attack_chain)
                }
                
                # Attack progression analysis
                report['attack_progression'] = {
                    'timeline': mapping.attack_chain.timeline,
                    'critical_path': self._identify_critical_attack_path(mapping.attack_chain, mapping.confidence_scores),
                    'progression_completeness': len(mapping.attack_chain.phases) / 12 * 100
                }
            
            # Enhanced recommendations
            report['recommendations'] = self._generate_enhanced_mitre_recommendations(mapping, tactic_stats)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating MITRE ATT&CK report: {str(e)}")
            return report
    
    def _calculate_confidence_distribution_enhanced(self, confidence_scores: Dict[str, float]) -> Dict[str, Any]:
        """Calculate enhanced confidence score distribution"""
        distribution = {
            'very_high': 0,  # >= 0.8
            'high': 0,       # 0.6 - 0.79
            'medium': 0,     # 0.4 - 0.59
            'low': 0,        # 0.2 - 0.39
            'very_low': 0    # < 0.2
        }
        
        for confidence in confidence_scores.values():
            if confidence >= 0.8:
                distribution['very_high'] += 1
            elif confidence >= 0.6:
                distribution['high'] += 1
            elif confidence >= 0.4:
                distribution['medium'] += 1
            elif confidence >= 0.2:
                distribution['low'] += 1
            else:
                distribution['very_low'] += 1
        
        # Add percentages
        total = sum(distribution.values())
        if total > 0:
            distribution['percentages'] = {
                level: (count / total) * 100 
                for level, count in distribution.items() 
                if level != 'percentages'
            }
        
        return distribution
    
    def _calculate_technique_risk_level(self, technique_id: str, confidence: float) -> str:
        """Calculate risk level for a technique based on ID and confidence"""
        # High-risk techniques (commonly used in advanced attacks)
        high_risk_techniques = ['T1055', 'T1003', 'T1112', 'T1140', 'T1486']
        
        if technique_id in high_risk_techniques and confidence >= 0.7:
            return 'CRITICAL'
        elif technique_id in high_risk_techniques and confidence >= 0.5:
            return 'HIGH'
        elif confidence >= 0.8:
            return 'HIGH'
        elif confidence >= 0.6:
            return 'MEDIUM'
        elif confidence >= 0.4:
            return 'LOW'
        else:
            return 'INFO'
    
    def _get_kill_chain_phase_for_tactic(self, tactic: str) -> str:
        """Get kill chain phase for a given tactic"""
        kill_chain_mapping = {
            'Initial Access': 'initial-access',
            'Execution': 'execution',
            'Persistence': 'persistence',
            'Privilege Escalation': 'privilege-escalation',
            'Defense Evasion': 'defense-evasion',
            'Credential Access': 'credential-access',
            'Discovery': 'discovery',
            'Lateral Movement': 'lateral-movement',
            'Collection': 'collection',
            'Command and Control': 'command-and-control',
            'Exfiltration': 'exfiltration',
            'Impact': 'impact'
        }
        return kill_chain_mapping.get(tactic, 'unknown')
    
    def _calculate_attack_progression_score(self, attack_chain) -> float:
        """Calculate attack progression score based on kill chain coverage"""
        if not attack_chain or not attack_chain.phases:
            return 0.0
        
        # Weight phases by their position in the attack chain
        phase_weights = {
            'initial-access': 1.0,
            'execution': 0.9,
            'persistence': 0.8,
            'privilege-escalation': 0.9,
            'defense-evasion': 0.7,
            'credential-access': 0.8,
            'discovery': 0.6,
            'lateral-movement': 0.8,
            'collection': 0.7,
            'command-and-control': 0.9,
            'exfiltration': 0.8,
            'impact': 1.0
        }
        
        total_weight = 0.0
        covered_weight = 0.0
        
        for phase, weight in phase_weights.items():
            total_weight += weight
            if phase in attack_chain.phases:
                phase_confidence = attack_chain.confidence_by_phase.get(phase, 0.0)
                covered_weight += weight * phase_confidence
        
        return (covered_weight / total_weight) * 100 if total_weight > 0 else 0.0
    
    def _identify_critical_attack_path(self, attack_chain, confidence_scores: Dict[str, float]) -> List[Dict[str, Any]]:
        """Identify the most critical attack path based on confidence and progression"""
        critical_path = []
        
        if not attack_chain or not attack_chain.phases:
            return critical_path
        
        for phase in attack_chain.phases:
            techniques = attack_chain.techniques_by_phase.get(phase, [])
            if techniques:
                # Find the highest confidence technique in this phase
                best_technique = max(techniques, key=lambda t: confidence_scores.get(t, 0.0))
                best_confidence = confidence_scores.get(best_technique, 0.0)
                
                technique_data = self.mitre_techniques.get(best_technique)
                if technique_data:
                    critical_path.append({
                        'phase': phase,
                        'technique_id': best_technique,
                        'technique_name': technique_data['name'],
                        'confidence': best_confidence,
                        'tactic': technique_data['tactic']
                    })
        
        return critical_path
    
    def _generate_enhanced_mitre_recommendations(self, mapping: MITREMapping, tactic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate enhanced mitigation recommendations based on MITRE ATT&CK analysis"""
        recommendations = []
        
        # Enhanced tactic-specific recommendations
        enhanced_tactic_recommendations = {
            'Initial Access': {
                'mitigations': [
                    'Implement network segmentation and zero-trust architecture',
                    'Deploy advanced email security with sandboxing and URL analysis',
                    'Regularly update and patch external-facing services and applications',
                    'Implement multi-factor authentication for all external access points',
                    'Deploy endpoint detection and response (EDR) solutions'
                ],
                'priority_multiplier': 1.2  # Higher priority for initial access
            },
            'Execution': {
                'mitigations': [
                    'Implement application whitelisting and code signing verification',
                    'Restrict PowerShell execution policies and enable logging',
                    'Monitor and log all script execution activities',
                    'Deploy behavioral analysis and anomaly detection',
                    'Implement just-in-time (JIT) administrative access'
                ],
                'priority_multiplier': 1.1
            },
            'Persistence': {
                'mitigations': [
                    'Monitor registry modifications and startup folder changes',
                    'Implement scheduled task auditing and alerting',
                    'Use Windows Defender Application Control (WDAC)',
                    'Deploy file integrity monitoring (FIM)',
                    'Regularly audit and clean up scheduled tasks and services'
                ],
                'priority_multiplier': 1.0
            },
            'Privilege Escalation': {
                'mitigations': [
                    'Implement least privilege principles and role-based access control',
                    'Monitor process injection attempts and memory modifications',
                    'Use token manipulation detection and prevention',
                    'Deploy privileged access management (PAM) solutions',
                    'Implement kernel-level protection mechanisms'
                ],
                'priority_multiplier': 1.3  # Very high priority
            },
            'Defense Evasion': {
                'mitigations': [
                    'Deploy advanced behavioral analysis and machine learning detection',
                    'Monitor file and registry modifications in real-time',
                    'Implement code signing verification and certificate validation',
                    'Use memory protection and control flow integrity',
                    'Deploy deception technologies and honeypots'
                ],
                'priority_multiplier': 1.0
            },
            'Credential Access': {
                'mitigations': [
                    'Implement credential protection (LSA Protection, Credential Guard)',
                    'Monitor LSASS access attempts and memory dumps',
                    'Use multi-factor authentication and passwordless solutions',
                    'Deploy privileged identity management (PIM)',
                    'Implement credential rotation and vault solutions'
                ],
                'priority_multiplier': 1.4  # Highest priority
            },
            'Discovery': {
                'mitigations': [
                    'Monitor system information queries and enumeration activities',
                    'Implement network segmentation and micro-segmentation',
                    'Log file and directory enumeration attempts',
                    'Deploy network traffic analysis and anomaly detection',
                    'Use deception technologies to detect reconnaissance'
                ],
                'priority_multiplier': 0.8
            },
            'Lateral Movement': {
                'mitigations': [
                    'Implement network monitoring and east-west traffic inspection',
                    'Restrict administrative shares and remote access protocols',
                    'Monitor remote service usage and authentication attempts',
                    'Deploy network access control (NAC) solutions',
                    'Implement just-in-time network access'
                ],
                'priority_multiplier': 1.1
            },
            'Collection': {
                'mitigations': [
                    'Implement data loss prevention (DLP) and data classification',
                    'Monitor file access patterns and data aggregation activities',
                    'Use screen capture detection and prevention',
                    'Deploy user and entity behavior analytics (UEBA)',
                    'Implement data encryption at rest and in transit'
                ],
                'priority_multiplier': 1.0
            },
            'Command and Control': {
                'mitigations': [
                    'Implement network traffic analysis and DNS monitoring',
                    'Block known malicious domains and IP addresses',
                    'Monitor DNS queries and network communication patterns',
                    'Deploy SSL/TLS inspection and certificate analysis',
                    'Use threat intelligence feeds for proactive blocking'
                ],
                'priority_multiplier': 1.2
            },
            'Exfiltration': {
                'mitigations': [
                    'Implement network egress filtering and data loss prevention',
                    'Monitor large data transfers and unusual network activity',
                    'Use data classification and protection policies',
                    'Deploy cloud access security brokers (CASB)',
                    'Implement bandwidth monitoring and alerting'
                ],
                'priority_multiplier': 1.3
            },
            'Impact': {
                'mitigations': [
                    'Implement comprehensive backup and recovery procedures',
                    'Monitor file encryption activities and ransomware indicators',
                    'Use system recovery protection and immutable backups',
                    'Deploy endpoint protection with anti-ransomware capabilities',
                    'Implement business continuity and disaster recovery plans'
                ],
                'priority_multiplier': 1.5  # Critical for business continuity
            }
        }
        
        for tactic, stats in tactic_stats.items():
            if tactic in enhanced_tactic_recommendations:
                tactic_data = enhanced_tactic_recommendations[tactic]
                
                # Calculate enhanced priority score
                base_priority = stats['avg_confidence'] * stats['technique_count']
                priority_multiplier = tactic_data['priority_multiplier']
                final_priority = base_priority * priority_multiplier
                
                recommendation = {
                    'tactic': tactic,
                    'affected_techniques': stats['techniques'],
                    'technique_count': stats['technique_count'],
                    'avg_confidence': stats['avg_confidence'],
                    'max_confidence': stats['max_confidence'],
                    'priority_score': final_priority,
                    'risk_level': self._calculate_tactic_risk_level(stats),
                    'mitigations': tactic_data['mitigations'],
                    'implementation_priority': self._get_implementation_priority(final_priority),
                    'estimated_effort': self._estimate_implementation_effort(tactic, stats['technique_count']),
                    'business_impact': self._assess_business_impact(tactic, stats['max_confidence'])
                }
                recommendations.append(recommendation)
        
        # Sort by priority score (highest first)
        recommendations.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return recommendations
    
    def _calculate_tactic_risk_level(self, tactic_stats: Dict[str, Any]) -> str:
        """Calculate risk level for a tactic based on its statistics"""
        max_confidence = tactic_stats['max_confidence']
        technique_count = tactic_stats['technique_count']
        
        if max_confidence >= 0.8 and technique_count >= 3:
            return 'CRITICAL'
        elif max_confidence >= 0.7 or technique_count >= 4:
            return 'HIGH'
        elif max_confidence >= 0.5 or technique_count >= 2:
            return 'MEDIUM'
        elif max_confidence >= 0.3:
            return 'LOW'
        else:
            return 'INFO'
    
    def _get_implementation_priority(self, priority_score: float) -> str:
        """Get implementation priority based on priority score"""
        if priority_score >= 3.0:
            return 'IMMEDIATE'
        elif priority_score >= 2.0:
            return 'HIGH'
        elif priority_score >= 1.0:
            return 'MEDIUM'
        elif priority_score >= 0.5:
            return 'LOW'
        else:
            return 'FUTURE'
    
    def _estimate_implementation_effort(self, tactic: str, technique_count: int) -> str:
        """Estimate implementation effort for tactic mitigations"""
        # Base effort by tactic complexity
        tactic_complexity = {
            'Initial Access': 'MEDIUM',
            'Execution': 'HIGH',
            'Persistence': 'MEDIUM',
            'Privilege Escalation': 'HIGH',
            'Defense Evasion': 'HIGH',
            'Credential Access': 'HIGH',
            'Discovery': 'LOW',
            'Lateral Movement': 'MEDIUM',
            'Collection': 'MEDIUM',
            'Command and Control': 'MEDIUM',
            'Exfiltration': 'MEDIUM',
            'Impact': 'LOW'
        }
        
        base_effort = tactic_complexity.get(tactic, 'MEDIUM')
        
        # Adjust based on technique count
        if technique_count >= 4:
            if base_effort == 'LOW':
                return 'MEDIUM'
            elif base_effort == 'MEDIUM':
                return 'HIGH'
            else:
                return 'VERY_HIGH'
        
        return base_effort
    
    def _assess_business_impact(self, tactic: str, max_confidence: float) -> str:
        """Assess business impact of tactic-based attacks"""
        # High business impact tactics
        high_impact_tactics = ['Credential Access', 'Impact', 'Exfiltration', 'Initial Access']
        medium_impact_tactics = ['Privilege Escalation', 'Lateral Movement', 'Command and Control']
        
        if tactic in high_impact_tactics and max_confidence >= 0.7:
            return 'CRITICAL'
        elif tactic in high_impact_tactics and max_confidence >= 0.5:
            return 'HIGH'
        elif tactic in medium_impact_tactics and max_confidence >= 0.6:
            return 'HIGH'
        elif tactic in medium_impact_tactics:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def correlate_with_apt_groups(self, iocs: List[IOC], mitre_mapping: MITREMapping,
                                 decompiled_code: str = None) -> APTAttribution:
        """
        Correlate findings with known APT groups based on TTPs and code patterns
        
        Args:
            iocs: List of extracted IOCs
            mitre_mapping: MITRE ATT&CK technique mapping
            decompiled_code: Decompiled source code for pattern matching
            
        Returns:
            APT attribution analysis
        """
        attribution = APTAttribution()
        
        try:
            best_match_score = 0.0
            best_match_group = None
            
            for group_name, group_data in self.apt_signatures.items():
                score = self._calculate_apt_match_score(
                    group_data, iocs, mitre_mapping, decompiled_code
                )
                
                if score > best_match_score:
                    best_match_score = score
                    best_match_group = group_name
            
            if best_match_group and best_match_score > 0.3:  # Threshold for attribution
                group_data = self.apt_signatures[best_match_group]
                
                attribution.group_name = best_match_group
                attribution.confidence = best_match_score
                attribution.matching_ttps = [ttp for ttp in group_data['ttps'] 
                                           if ttp in mitre_mapping.techniques]
                attribution.campaign_name = f"Potential {best_match_group} Campaign"
                
                # Build attribution reasons
                reasons = []
                if attribution.matching_ttps:
                    reasons.append(f"Matching TTPs: {', '.join(attribution.matching_ttps)}")
                
                # Check for tool indicators
                matching_tools = self._find_matching_tools(group_data, decompiled_code, iocs)
                if matching_tools:
                    reasons.append(f"Tool indicators: {', '.join(matching_tools)}")
                
                # Check for C&C patterns
                matching_c2 = self._find_matching_c2_patterns(group_data, iocs)
                if matching_c2:
                    reasons.append(f"C&C patterns: {', '.join(matching_c2)}")
                
                attribution.attribution_reasons = reasons
                
                # Add evidence
                evidence = Evidence(
                    type="apt_attribution",
                    description=f"Attributed to {best_match_group} with {best_match_score:.2f} confidence",
                    source="apt_correlator",
                    confidence=best_match_score,
                    metadata={
                        "group": best_match_group,
                        "score": best_match_score,
                        "reasons": reasons
                    }
                )
                attribution.evidence.append(evidence)
                self.evidence_tracker.add_evidence(
                    evidence.type,
                    evidence.description,
                    evidence.source,
                    evidence.confidence,
                    evidence.metadata
                )
            
            self.logger.info(f"APT attribution: {attribution.group_name or 'Unknown'} "
                           f"(confidence: {attribution.confidence:.2f})")
            return attribution
            
        except Exception as e:
            self.logger.error(f"Error in APT attribution: {str(e)}")
            return attribution
    
    def _calculate_apt_match_score(self, group_data: Dict[str, Any], iocs: List[IOC],
                                  mitre_mapping: MITREMapping, decompiled_code: str) -> float:
        """Calculate enhanced match score for APT group with behavioral and code similarity analysis"""
        score = 0.0
        total_weight = 0.0
        
        # TTP matching (30% weight)
        ttp_weight = 0.3
        matching_ttps = [ttp for ttp in group_data['ttps'] if ttp in mitre_mapping.techniques]
        if group_data['ttps']:
            ttp_score = len(matching_ttps) / len(group_data['ttps'])
            score += ttp_score * ttp_weight
        total_weight += ttp_weight
        
        # Tool indicators (20% weight)
        tool_weight = 0.2
        if decompiled_code:
            tool_matches = self._find_matching_tools(group_data, decompiled_code, iocs)
            if group_data['tools']:
                tool_score = len(tool_matches) / len(group_data['tools'])
                score += tool_score * tool_weight
        total_weight += tool_weight
        
        # C&C patterns (15% weight)
        c2_weight = 0.15
        c2_matches = self._find_matching_c2_patterns(group_data, iocs)
        if group_data['c2_patterns']:
            c2_score = min(len(c2_matches) / len(group_data['c2_patterns']), 1.0)
            score += c2_score * c2_weight
        total_weight += c2_weight
        
        # File patterns (10% weight)
        file_weight = 0.1
        file_matches = self._find_matching_file_patterns(group_data, iocs)
        if group_data['file_patterns']:
            file_score = min(len(file_matches) / len(group_data['file_patterns']), 1.0)
            score += file_score * file_weight
        total_weight += file_weight
        
        # Behavioral patterns (15% weight)
        behavioral_weight = 0.15
        behavioral_score = self._calculate_behavioral_pattern_score(group_data, decompiled_code, iocs)
        score += behavioral_score * behavioral_weight
        total_weight += behavioral_weight
        
        # Code similarity analysis (10% weight)
        similarity_weight = 0.1
        similarity_score = self._calculate_code_similarity_score(group_data, decompiled_code, iocs)
        score += similarity_score * similarity_weight
        total_weight += similarity_weight
        
        return score / total_weight if total_weight > 0 else 0.0
    
    def _find_matching_tools(self, group_data: Dict[str, Any], decompiled_code: str,
                           iocs: List[IOC]) -> List[str]:
        """Find matching tool indicators"""
        matches = []
        
        if decompiled_code:
            code_lower = decompiled_code.lower()
            for tool in group_data['tools']:
                if tool.lower() in code_lower:
                    matches.append(tool)
        
        # Check IOCs for tool indicators
        for ioc in iocs:
            for tool in group_data['tools']:
                if tool.lower() in ioc.value.lower():
                    matches.append(tool)
        
        return list(set(matches))  # Remove duplicates
    
    def _find_matching_c2_patterns(self, group_data: Dict[str, Any], iocs: List[IOC]) -> List[str]:
        """Find matching C&C patterns"""
        matches = []
        
        for ioc in iocs:
            if ioc.type in ['domain', 'url', 'ip_address']:
                for pattern in group_data['c2_patterns']:
                    if re.search(pattern, ioc.value, re.IGNORECASE):
                        matches.append(pattern)
        
        return list(set(matches))
    
    def _find_matching_file_patterns(self, group_data: Dict[str, Any], iocs: List[IOC]) -> List[str]:
        """Find matching file patterns"""
        matches = []
        
        for ioc in iocs:
            if ioc.type == 'file_path':
                for pattern in group_data['file_patterns']:
                    if re.search(pattern, ioc.value, re.IGNORECASE):
                        matches.append(pattern)
        
        return list(set(matches))
    
    def _calculate_behavioral_pattern_score(self, group_data: Dict[str, Any], 
                                          decompiled_code: str, iocs: List[IOC]) -> float:
        """Calculate behavioral pattern matching score for APT attribution"""
        if not decompiled_code and not iocs:
            return 0.0
        
        behavioral_patterns = group_data.get('behavioral_patterns', [])
        if not behavioral_patterns:
            return 0.0
        
        matched_patterns = 0
        total_patterns = len(behavioral_patterns)
        
        # Combine all analysis text
        analysis_text = (decompiled_code or "").lower()
        if iocs:
            ioc_text = " ".join([ioc.value.lower() for ioc in iocs])
            analysis_text += " " + ioc_text
        
        for pattern_name in behavioral_patterns:
            if pattern_name in self.behavioral_patterns:
                pattern_data = self.behavioral_patterns[pattern_name]
                indicators = pattern_data['indicators']
                
                # Check if any indicators are present
                pattern_found = False
                for indicator in indicators:
                    if indicator.lower() in analysis_text:
                        pattern_found = True
                        break
                
                if pattern_found:
                    matched_patterns += 1
        
        return matched_patterns / total_patterns if total_patterns > 0 else 0.0
    
    def _calculate_code_similarity_score(self, group_data: Dict[str, Any], 
                                       decompiled_code: str, iocs: List[IOC]) -> float:
        """Calculate code similarity score for malware variant detection"""
        if not decompiled_code:
            return 0.0
        
        group_name = None
        for apt_name, apt_data in self.apt_signatures.items():
            if apt_data == group_data:
                group_name = apt_name.lower()
                break
        
        if not group_name:
            return 0.0
        
        similarity_score = 0.0
        total_checks = 0
        
        # Check mutex patterns
        mutex_patterns = self.code_similarity_signatures['mutex_patterns']
        group_mutex_key = self._get_group_mutex_key(group_name)
        if group_mutex_key and group_mutex_key in mutex_patterns:
            total_checks += 1
            for pattern in mutex_patterns[group_mutex_key]:
                if re.search(pattern, decompiled_code, re.IGNORECASE):
                    similarity_score += 0.3
                    break
        
        # Check encryption patterns
        encryption_patterns = self.code_similarity_signatures['encryption_patterns']
        
        # XOR key patterns
        xor_keys = encryption_patterns['xor_keys']
        group_xor_key = self._get_group_xor_key(group_name)
        if group_xor_key and group_xor_key in xor_keys:
            total_checks += 1
            for key in xor_keys[group_xor_key]:
                if key in decompiled_code:
                    similarity_score += 0.2
                    break
        
        # RC4 key patterns
        rc4_keys = encryption_patterns['rc4_keys']
        group_rc4_key = self._get_group_rc4_key(group_name)
        if group_rc4_key and group_rc4_key in rc4_keys:
            total_checks += 1
            for key in rc4_keys[group_rc4_key]:
                if key in decompiled_code:
                    similarity_score += 0.2
                    break
        
        # Check network patterns
        network_patterns = self.code_similarity_signatures['network_patterns']
        
        # User agent patterns
        user_agents = network_patterns['user_agents']
        group_ua_key = self._get_group_ua_key(group_name)
        if group_ua_key and group_ua_key in user_agents:
            total_checks += 1
            for ua in user_agents[group_ua_key]:
                if ua.lower() in decompiled_code.lower():
                    similarity_score += 0.15
                    break
        
        # HTTP POST patterns
        http_patterns = network_patterns['c2_protocols']['http_post_patterns']
        group_http_key = self._get_group_http_key(group_name)
        if group_http_key and group_http_key in http_patterns:
            total_checks += 1
            for pattern in http_patterns[group_http_key]:
                if re.search(pattern, decompiled_code, re.IGNORECASE):
                    similarity_score += 0.15
                    break
        
        return min(similarity_score, 1.0) if total_checks > 0 else 0.0
    
    def _get_group_mutex_key(self, group_name: str) -> str:
        """Map APT group name to mutex pattern key"""
        mapping = {
            'apt1': 'comment_crew',
            'apt28': 'fancy_bear',
            'apt29': 'cozy_bear',
            'lazarus': 'lazarus_group',
            'apt40': 'leviathan',
            'fin7': 'carbanak'
        }
        return mapping.get(group_name)
    
    def _get_group_xor_key(self, group_name: str) -> str:
        """Map APT group name to XOR key pattern"""
        mapping = {
            'apt28': 'apt28',
            'apt29': 'apt29',
            'lazarus': 'lazarus',
            'apt40': 'apt40',
            'fin7': 'fin7'
        }
        return mapping.get(group_name)
    
    def _get_group_rc4_key(self, group_name: str) -> str:
        """Map APT group name to RC4 key pattern"""
        mapping = {
            'apt1': 'apt1',
            'apt40': 'apt40',
            'fin7': 'fin7'
        }
        return mapping.get(group_name)
    
    def _get_group_ua_key(self, group_name: str) -> str:
        """Map APT group name to user agent pattern"""
        mapping = {
            'apt28': 'apt28',
            'apt29': 'apt29',
            'lazarus': 'lazarus',
            'apt40': 'apt40',
            'fin7': 'fin7'
        }
        return mapping.get(group_name)
    
    def _get_group_http_key(self, group_name: str) -> str:
        """Map APT group name to HTTP pattern"""
        mapping = {
            'apt1': 'apt1',
            'apt28': 'apt28',
            'apt40': 'apt40',
            'fin7': 'fin7'
        }
        return mapping.get(group_name)
    
    def analyze_malware_variant_similarity(self, decompiled_code: str, 
                                         known_malware_family: str = None) -> Dict[str, Any]:
        """
        Analyze code similarity to detect malware variants and family relationships
        
        Args:
            decompiled_code: Decompiled source code to analyze
            known_malware_family: Optional known malware family for comparison
            
        Returns:
            Dictionary containing similarity analysis results
        """
        similarity_results = {
            'family_matches': {},
            'variant_confidence': 0.0,
            'similar_samples': [],
            'code_reuse_indicators': [],
            'evolutionary_markers': []
        }
        
        try:
            if not decompiled_code:
                return similarity_results
            
            # Analyze against all known APT groups
            for group_name, group_data in self.apt_signatures.items():
                similarity_score = self._calculate_code_similarity_score(
                    group_data, decompiled_code, []
                )
                
                if similarity_score > 0.3:  # Threshold for potential variant
                    similarity_results['family_matches'][group_name] = {
                        'similarity_score': similarity_score,
                        'confidence_level': self._get_confidence_level(similarity_score),
                        'matching_patterns': self._get_matching_patterns(
                            group_name, decompiled_code
                        )
                    }
            
            # Determine overall variant confidence
            if similarity_results['family_matches']:
                max_score = max(
                    match['similarity_score'] 
                    for match in similarity_results['family_matches'].values()
                )
                similarity_results['variant_confidence'] = max_score
            
            # Identify code reuse indicators
            similarity_results['code_reuse_indicators'] = self._identify_code_reuse(
                decompiled_code
            )
            
            # Identify evolutionary markers
            similarity_results['evolutionary_markers'] = self._identify_evolutionary_markers(
                decompiled_code
            )
            
            # Add evidence
            evidence = Evidence(
                type="malware_variant_analysis",
                description=f"Analyzed code similarity for malware variant detection",
                source="code_similarity_analyzer",
                confidence=similarity_results['variant_confidence'],
                metadata={
                    "family_matches": len(similarity_results['family_matches']),
                    "max_similarity": similarity_results['variant_confidence'],
                    "code_reuse_count": len(similarity_results['code_reuse_indicators'])
                }
            )
            self.evidence_tracker.add_evidence(
                evidence.type,
                evidence.description,
                evidence.source,
                evidence.confidence,
                evidence.metadata
            )
            
            self.logger.info(f"Malware variant analysis completed: "
                           f"{len(similarity_results['family_matches'])} potential matches")
            return similarity_results
            
        except Exception as e:
            self.logger.error(f"Error in malware variant analysis: {str(e)}")
            return similarity_results
    
    def _get_confidence_level(self, similarity_score: float) -> str:
        """Convert similarity score to confidence level"""
        if similarity_score >= 0.8:
            return 'HIGH'
        elif similarity_score >= 0.6:
            return 'MEDIUM'
        elif similarity_score >= 0.4:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _get_matching_patterns(self, group_name: str, decompiled_code: str) -> List[str]:
        """Get list of matching patterns for a group"""
        matching_patterns = []
        
        # Check various pattern types
        group_mutex_key = self._get_group_mutex_key(group_name.lower())
        if group_mutex_key:
            mutex_patterns = self.code_similarity_signatures['mutex_patterns'].get(group_mutex_key, [])
            for pattern in mutex_patterns:
                if re.search(pattern, decompiled_code, re.IGNORECASE):
                    matching_patterns.append(f"mutex_pattern: {pattern}")
        
        # Check encryption patterns
        group_xor_key = self._get_group_xor_key(group_name.lower())
        if group_xor_key:
            xor_keys = self.code_similarity_signatures['encryption_patterns']['xor_keys'].get(group_xor_key, [])
            for key in xor_keys:
                if key in decompiled_code:
                    matching_patterns.append(f"xor_key: {key}")
        
        return matching_patterns
    
    def _identify_code_reuse(self, decompiled_code: str) -> List[str]:
        """Identify code reuse indicators"""
        indicators = []
        
        # Common code reuse patterns
        reuse_patterns = [
            r'function_[0-9a-f]{8}',  # Generic function names
            r'sub_[0-9a-f]{8}',       # IDA Pro style function names
            r'loc_[0-9a-f]{8}',       # Location labels
            r'var_[0-9a-f]{2,8}',     # Variable names
            r'dword_[0-9a-f]{8}',     # Data references
        ]
        
        for pattern in reuse_patterns:
            matches = re.findall(pattern, decompiled_code, re.IGNORECASE)
            if len(matches) > 5:  # Threshold for significant reuse
                indicators.append(f"Generic naming pattern: {pattern} ({len(matches)} instances)")
        
        return indicators
    
    def _identify_evolutionary_markers(self, decompiled_code: str) -> List[str]:
        """Identify evolutionary markers in malware code"""
        markers = []
        
        # Version indicators
        version_patterns = [
            r'version\s*[=:]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'v[0-9]+\.[0-9]+',
            r'build\s*[=:]\s*["\']?([0-9]+)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, decompiled_code, re.IGNORECASE)
            for match in matches:
                markers.append(f"Version indicator: {match}")
        
        # Development markers
        dev_patterns = [
            r'debug',
            r'test',
            r'beta',
            r'alpha',
            r'dev',
            r'experimental'
        ]
        
        for pattern in dev_patterns:
            if re.search(pattern, decompiled_code, re.IGNORECASE):
                markers.append(f"Development marker: {pattern}")
        
        return markers
    
    def correlate_campaign(self, iocs: List[IOC], apt_attribution: APTAttribution,
                          file_path: str) -> CampaignCorrelation:
        """
        Correlate with known campaigns based on IOCs and attribution
        
        Args:
            iocs: List of IOCs
            apt_attribution: APT attribution result
            file_path: Path to analyzed file
            
        Returns:
            Campaign correlation analysis
        """
        correlation = CampaignCorrelation()
        
        try:
            if apt_attribution.group_name:
                # Generate campaign ID based on group and timeframe
                current_date = datetime.now().strftime("%Y-%m")
                correlation.campaign_id = f"{apt_attribution.group_name}_{current_date}"
                correlation.campaign_name = f"{apt_attribution.group_name} Campaign {current_date}"
                correlation.confidence = apt_attribution.confidence * 0.8  # Slightly lower confidence
                
                # Add current sample to related samples
                correlation.related_samples = [file_path]
                
                # Build timeline
                correlation.timeline = {
                    'first_seen': datetime.now().isoformat(),
                    'last_activity': datetime.now().isoformat(),
                    'sample_count': 1
                }
                
                # Extract infrastructure IOCs
                infrastructure = []
                for ioc in iocs:
                    if ioc.type in ['domain', 'ip_address', 'url']:
                        infrastructure.append(ioc.value)
                correlation.infrastructure = infrastructure
                
                # Add evidence
                evidence = Evidence(
                    type="campaign_correlation",
                    description=f"Correlated with {correlation.campaign_name}",
                    source="campaign_correlator",
                    confidence=correlation.confidence,
                    metadata={
                        "campaign_id": correlation.campaign_id,
                        "infrastructure_count": len(infrastructure)
                    }
                )
                self.evidence_tracker.add_evidence(
                    evidence.type,
                    evidence.description,
                    evidence.source,
                    evidence.confidence,
                    evidence.metadata
                )
            
            self.logger.info(f"Campaign correlation: {correlation.campaign_name or 'Unknown'}")
            return correlation
            
        except Exception as e:
            self.logger.error(f"Error in campaign correlation: {str(e)}")
            return correlation
    
    def assess_threat_level(self, iocs: List[IOC], vulnerabilities: List[Any],
                           apt_attribution: APTAttribution) -> RiskLevel:
        """
        Assess overall threat level based on analysis results
        
        Args:
            iocs: List of IOCs
            vulnerabilities: List of vulnerabilities
            apt_attribution: APT attribution result
            
        Returns:
            Overall threat risk level
        """
        try:
            risk_score = 0.0
            
            # IOC-based risk (30% weight)
            high_risk_iocs = len([ioc for ioc in iocs if ioc.confidence > 0.8])
            ioc_risk = min(high_risk_iocs / 10.0, 1.0)  # Normalize to 0-1
            risk_score += ioc_risk * 0.3
            
            # Vulnerability-based risk (40% weight)
            if vulnerabilities:
                critical_vulns = len([v for v in vulnerabilities if getattr(v, 'severity', None) == 'CRITICAL'])
                high_vulns = len([v for v in vulnerabilities if getattr(v, 'severity', None) == 'HIGH'])
                vuln_risk = min((critical_vulns * 0.5 + high_vulns * 0.3) / 5.0, 1.0)
                risk_score += vuln_risk * 0.4
            
            # APT attribution risk (30% weight)
            if apt_attribution.group_name and apt_attribution.confidence > 0.5:
                apt_risk = apt_attribution.confidence
                risk_score += apt_risk * 0.3
            
            # Convert to risk level
            if risk_score >= 0.8:
                return RiskLevel.CRITICAL
            elif risk_score >= 0.6:
                return RiskLevel.HIGH
            elif risk_score >= 0.4:
                return RiskLevel.MEDIUM
            elif risk_score >= 0.2:
                return RiskLevel.LOW
            else:
                return RiskLevel.INFO
                
        except Exception as e:
            self.logger.error(f"Error assessing threat level: {str(e)}")
            return RiskLevel.UNKNOWN
    
    def generate_comprehensive_report(self, file_path: str, decompiled_code: str = None,
                                    function_calls: List[str] = None, api_calls: List[str] = None,
                                    strings_data: List[str] = None, vulnerabilities: List[Any] = None) -> ThreatIntelligenceReport:
        """
        Generate comprehensive threat intelligence report
        
        Args:
            file_path: Path to analyzed file
            decompiled_code: Decompiled source code
            function_calls: List of function calls
            api_calls: List of API calls
            strings_data: Extracted strings
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Comprehensive threat intelligence report
        """
        report = ThreatIntelligenceReport()
        
        try:
            # Extract IOCs
            iocs = self.extract_iocs_from_binary(file_path, decompiled_code, strings_data)
            report.iocs_extracted = iocs
            
            # Correlate with VirusTotal
            vt_results = self.correlate_with_virustotal(iocs)
            
            # Map to MITRE ATT&CK
            mitre_mapping = self.map_to_mitre_attack(decompiled_code, function_calls, api_calls)
            report.mitre_attack_mapping = mitre_mapping
            
            # APT attribution
            apt_attribution = self.correlate_with_apt_groups(iocs, mitre_mapping, decompiled_code)
            report.apt_attribution = apt_attribution
            
            # Campaign correlation
            campaign_correlation = self.correlate_campaign(iocs, apt_attribution, file_path)
            report.campaign_correlation = campaign_correlation
            
            # Malware classification
            malware_classification = self._classify_malware(iocs, mitre_mapping, apt_attribution)
            report.malware_classification = malware_classification
            
            # Assess threat level
            threat_level = self.assess_threat_level(iocs, vulnerabilities or [], apt_attribution)
            report.threat_level = threat_level
            
            # Generate recommendations
            report.recommended_actions = self._generate_recommendations(
                report, vt_results, vulnerabilities
            )
            
            # Calculate overall confidence
            confidence_scores = []
            if iocs:
                confidence_scores.append(sum(ioc.confidence for ioc in iocs) / len(iocs))
            if apt_attribution.confidence > 0:
                confidence_scores.append(apt_attribution.confidence)
            if mitre_mapping.confidence_scores:
                confidence_scores.append(sum(mitre_mapping.confidence_scores.values()) / len(mitre_mapping.confidence_scores))
            
            report.confidence_score = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
            
            # Set analysis timestamp
            report.analysis_timestamp = datetime.now().timestamp()
            
            self.logger.info(f"Generated threat intelligence report for {file_path}")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating threat intelligence report: {str(e)}")
            return report
    
    def _classify_malware(self, iocs: List[IOC], mitre_mapping: MITREMapping,
                         apt_attribution: APTAttribution) -> Optional[MalwareClassification]:
        """Classify malware based on analysis results"""
        if not iocs and not mitre_mapping.techniques:
            return None
        
        classification = MalwareClassification()
        
        # Basic classification based on MITRE techniques
        if 'T1055' in mitre_mapping.techniques:  # Process Injection
            classification.capabilities.append('Process Injection')
        if 'T1105' in mitre_mapping.techniques:  # Ingress Tool Transfer
            classification.capabilities.append('Remote Access')
        if 'T1112' in mitre_mapping.techniques:  # Modify Registry
            classification.capabilities.append('Persistence')
        if 'T1140' in mitre_mapping.techniques:  # Deobfuscate/Decode
            classification.capabilities.append('Evasion')
        
        # Family classification based on APT attribution
        if apt_attribution.group_name:
            classification.family = f"{apt_attribution.group_name} Malware"
            classification.confidence = apt_attribution.confidence
        else:
            classification.family = "Unknown"
            classification.confidence = 0.3
        
        # Behavior tags
        classification.behavior_tags = [
            f"mitre_{technique.lower()}" for technique in mitre_mapping.techniques
        ]
        
        return classification
    
    def _generate_recommendations(self, report: ThreatIntelligenceReport,
                                vt_results: Dict[str, Any], vulnerabilities: List[Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # IOC-based recommendations
        if report.iocs_extracted:
            recommendations.append("Block identified IOCs in network security controls")
            recommendations.append("Monitor for additional IOCs from the same campaign")
        
        # APT-based recommendations
        if report.apt_attribution and report.apt_attribution.group_name:
            recommendations.append(f"Implement defenses against {report.apt_attribution.group_name} TTPs")
            recommendations.append("Review historical logs for similar attack patterns")
        
        # MITRE-based recommendations
        if report.mitre_attack_mapping.techniques:
            recommendations.append("Implement MITRE ATT&CK-based detection rules")
            recommendations.append("Conduct threat hunting for identified techniques")
        
        # Threat level recommendations
        if report.threat_level == RiskLevel.CRITICAL:
            recommendations.append("Immediate incident response required")
            recommendations.append("Isolate affected systems")
        elif report.threat_level == RiskLevel.HIGH:
            recommendations.append("Prioritize investigation and containment")
            recommendations.append("Enhance monitoring for related activities")
        
        # Vulnerability recommendations
        if vulnerabilities:
            recommendations.append("Patch identified vulnerabilities immediately")
            recommendations.append("Implement additional security controls")
        
        return recommendations


# Utility functions for threat intelligence operations
def defang_ioc(ioc_value: str, ioc_type: str) -> str:
    """Defang IOC for safe sharing"""
    if ioc_type == 'domain':
        return ioc_value.replace('.', '[.]')
    elif ioc_type == 'url':
        return ioc_value.replace('http', 'hxxp').replace('.', '[.]')
    elif ioc_type == 'ip_address':
        return ioc_value.replace('.', '[.]')
    elif ioc_type == 'email':
        return ioc_value.replace('@', '[@]').replace('.', '[.]')
    else:
        return ioc_value


def create_yara_rule(iocs: List[IOC], rule_name: str = "generated_rule") -> str:
    """Generate YARA rule from IOCs"""
    strings_section = []
    condition_parts = []
    
    for i, ioc in enumerate(iocs):
        if ioc.type in ['md5', 'sha1', 'sha256']:
            continue  # Skip hashes for YARA strings
        
        var_name = f"$s{i}"
        if ioc.type == 'domain':
            strings_section.append(f'    {var_name} = "{ioc.value}" nocase')
        elif ioc.type == 'ip_address':
            strings_section.append(f'    {var_name} = "{ioc.value}"')
        elif ioc.type in ['file_path', 'registry_key', 'mutex']:
            strings_section.append(f'    {var_name} = "{ioc.value}" nocase')
        
        if strings_section and len(strings_section) == len(condition_parts) + 1:
            condition_parts.append(var_name)
    
    if not strings_section:
        return f"// No suitable IOCs found for YARA rule generation"
    
    yara_rule = f"""rule {rule_name}
{{
    meta:
        description = "Generated from threat intelligence analysis"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        
    strings:
{chr(10).join(strings_section)}
    
    condition:
        any of them
}}"""
    
    return yara_rule


# Example usage and testing
if __name__ == "__main__":
    # Initialize correlator
    config = {
        'virustotal_api_key': 'your_vt_api_key_here',
        'misp_url': 'https://your-misp-instance.com',
        'misp_key': 'your_misp_key_here'
    }
    
    correlator = ThreatIntelligenceCorrelator(config)
    
    # Test IOC extraction
    test_code = """
    char* c2_server = "malicious-domain.com";
    char* backup_c2 = "192.168.1.100";
    CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, lpParameter, 0, &dwThreadId);
    """
    
    iocs = correlator.extract_iocs_from_binary("test.exe", test_code, ["malicious-domain.com"])
    print(f"Extracted {len(iocs)} IOCs")
    
    # Test MITRE mapping
    mitre_mapping = correlator.map_to_mitre_attack(test_code)
    print(f"Mapped {len(mitre_mapping.techniques)} MITRE techniques")
    
    # Test APT attribution
    apt_attribution = correlator.correlate_with_apt_groups(iocs, mitre_mapping, test_code)
    print(f"APT attribution: {apt_attribution.group_name or 'Unknown'}")
    
    # Generate comprehensive report
    report = correlator.generate_comprehensive_report("test.exe", test_code)
    print(f"Generated report with threat level: {report.threat_level}")
    
    print("Threat Intelligence Correlator validation completed!")