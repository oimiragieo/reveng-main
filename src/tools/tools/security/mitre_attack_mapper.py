#!/usr/bin/env python3
"""
MITRE ATT&CK Mapping Engine
===========================

Enhanced MITRE ATT&CK framework mapping for detected behaviors with
technique confidence scoring and attack chain visualization.

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import json
import re
import logging
import sys
import os
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime

# Import our data models
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from ai_enhanced_data_models import MITREMapping, Evidence, EvidenceTracker


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique information"""
    id: str
    name: str
    tactic: str
    description: str
    keywords: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)


class MITREAttackMapper:
    """Enhanced MITRE ATT&CK mapping engine"""
    
    def __init__(self):
        """Initialize the mapper"""
        self.logger = logging.getLogger(__name__)
        self.evidence_tracker = EvidenceTracker()
        self._init_techniques()
    
    def _init_techniques(self):
        """Initialize technique database"""
        self.techniques = {
            'T1055': MITRETechnique(
                id='T1055',
                name='Process Injection',
                tactic='Privilege Escalation',
                description='Adversaries may inject code into processes',
                keywords=['inject', 'hollowing'],
                api_calls=['CreateRemoteThread', 'WriteProcessMemory']
            ),
            'T1112': MITRETechnique(
                id='T1112',
                name='Modify Registry',
                tactic='Defense Evasion',
                description='Adversaries may interact with the Windows Registry',
                keywords=['registry', 'reg'],
                api_calls=['RegSetValueEx', 'RegCreateKeyEx']
            )
        }
    
    def map_techniques_comprehensive(self, decompiled_code: str = None, 
                                   api_calls: List[str] = None) -> MITREMapping:
        """Map behaviors to MITRE ATT&CK techniques"""
        mapping = MITREMapping()
        
        try:
            analysis_text = (decompiled_code or "").lower()
            if api_calls:
                analysis_text += " " + " ".join(api_calls).lower()
            
            for technique_id, technique in self.techniques.items():
                confidence = 0.0
                
                # Check keywords
                for keyword in technique.keywords:
                    if keyword in analysis_text:
                        confidence += 0.3
                
                # Check API calls
                if api_calls:
                    for api_call in technique.api_calls:
                        if any(api_call.lower() in call.lower() for call in api_calls):
                            confidence += 0.4
                
                if confidence >= 0.3:
                    mapping.techniques.append(technique_id)
                    mapping.confidence_scores[technique_id] = min(confidence, 1.0)
                    mapping.technique_details[technique_id] = {
                        'name': technique.name,
                        'tactic': technique.tactic,
                        'confidence': min(confidence, 1.0)
                    }
                    if technique.tactic not in mapping.tactics:
                        mapping.tactics.append(technique.tactic)
            
            return mapping
            
        except Exception as e:
            self.logger.error(f"Error in mapping: {str(e)}")
            return mapping


def main():
    """Test function"""
    logging.basicConfig(level=logging.INFO)
    
    mapper = MITREAttackMapper()
    
    # Test
    mapping = mapper.map_techniques_comprehensive(
        decompiled_code="CreateRemoteThread WriteProcessMemory RegSetValueEx",
        api_calls=["CreateRemoteThread", "RegSetValueEx"]
    )
    
    print(f"Mapped {len(mapping.techniques)} techniques:")
    for tid in mapping.techniques:
        details = mapping.technique_details.get(tid, {})
        print(f"  {tid}: {details.get('name')} (Confidence: {mapping.confidence_scores.get(tid, 0):.2f})")


if __name__ == "__main__":
    main()