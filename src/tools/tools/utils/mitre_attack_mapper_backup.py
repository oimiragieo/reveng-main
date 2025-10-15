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
from .ai_enhanced_data_models import (
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
            return mapping    def 
correlate_with_apt_groups(self, iocs: List[IOC], mitre_mapping: MITREMapping,
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
        """Calculate match score for APT group"""
        score = 0.0
        total_weight = 0.0
        
        # TTP matching (40% weight)
        ttp_weight = 0.4
        matching_ttps = [ttp for ttp in group_data['ttps'] if ttp in mitre_mapping.techniques]
        if group_data['ttps']:
            ttp_score = len(matching_ttps) / len(group_data['ttps'])
            score += ttp_score * ttp_weight
        total_weight += ttp_weight
        
        # Tool indicators (30% weight)
        tool_weight = 0.3
        if decompiled_code:
            tool_matches = self._find_matching_tools(group_data, decompiled_code, iocs)
            if group_data['tools']:
                tool_score = len(tool_matches) / len(group_data['tools'])
                score += tool_score * tool_weight
        total_weight += tool_weight
        
        # C&C patterns (20% weight)
        c2_weight = 0.2
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