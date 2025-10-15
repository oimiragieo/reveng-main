#!/usr/bin/env python3
"""
Multi-Format Export and Integration Engine

This module implements STIX/TAXII export for threat intelligence sharing,
creates SIEM integration APIs for automated security tool ingestion, and
builds custom report templates and branding options.

Requirements: 7.1, 7.3, 7.4
"""

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import requests
from jinja2 import Template, Environment, FileSystemLoader
import yaml
from stix2 import (
    Indicator, Malware, ThreatActor, AttackPattern, Vulnerability,
    Bundle, Identity, Report, Relationship, TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
)
import pandas as pd
from xml.dom import minidom
import base64
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExportFormat(Enum):
    """Supported export formats"""
    STIX2_JSON = "stix2_json"
    STIX2_XML = "stix2_xml"
    MISP_JSON = "misp_json"
    YARA_RULES = "yara"
    IOC_CSV = "ioc_csv"
    SPLUNK_JSON = "splunk_json"
    ELASTIC_JSON = "elastic_json"
    QRadar_XML = "qradar_xml"
    SENTINEL_JSON = "sentinel_json"
    CUSTOM_JSON = "custom_json"
    CUSTOM_XML = "custom_xml"

class TLPLevel(Enum):
    """Traffic Light Protocol levels"""
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"

class SIEMType(Enum):
    """Supported SIEM systems"""
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    QRADAR = "qradar"
    SENTINEL = "sentinel"
    ARCSIGHT = "arcsight"
    LOGRHYTHM = "logrhythm"

@dataclass
class IOCData:
    """Indicator of Compromise data structure"""
    type: str  # ip, domain, hash, url, etc.
    value: str
    description: str
    confidence: float
    tlp_level: TLPLevel
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    source: str
    context: Dict[str, Any]

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure"""
    id: str
    name: str
    description: str
    threat_actor: Optional[str]
    malware_family: Optional[str]
    attack_patterns: List[str]
    iocs: List[IOCData]
    vulnerabilities: List[str]
    confidence: float
    tlp_level: TLPLevel
    created: datetime
    modified: datetime

@dataclass
class CustomBranding:
    """Custom branding configuration"""
    organization_name: str
    logo_path: Optional[str]
    color_scheme: Dict[str, str]
    header_template: Optional[str]
    footer_template: Optional[str]
    css_overrides: Optional[str]

class ExportIntegrationEngine:
    """
    Multi-format export and integration engine for threat intelligence sharing,
    SIEM integration, and custom report generation.
    """
    
    def __init__(self, output_dir: str = "exports"):
        """Initialize the export integration engine"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize template directories
        self.template_dir = Path("templates/exports")
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(loader=FileSystemLoader(str(self.template_dir)))
        
        # Create default templates
        self._create_default_templates()
        
        # STIX2 identity for organization
        self.organization_identity = Identity(
            name="Security Research Organization",
            identity_class="organization"
        )
        
        logger.info(f"Export integration engine initialized with output directory: {self.output_dir}")
    
    def export_stix2(self, threat_intel: ThreatIntelligence, 
                     format_type: ExportFormat = ExportFormat.STIX2_JSON) -> str:
        """
        Export threat intelligence to STIX 2.x format
        
        Args:
            threat_intel: Threat intelligence data
            format_type: STIX2 format (JSON or XML)
            
        Returns:
            Path to exported STIX file
        """
        # Create STIX objects
        stix_objects = [self.organization_identity]
        
        # Create indicators from IOCs
        indicators = []
        for ioc in threat_intel.iocs:
            indicator = Indicator(
                pattern=self._create_stix_pattern(ioc),
                labels=self._get_stix_labels(ioc.type),
                confidence=int(ioc.confidence * 100),
                created_by_ref=self.organization_identity.id,
                object_marking_refs=[self._get_tlp_marking(ioc.tlp_level)]
            )
            indicators.append(indicator)
            stix_objects.append(indicator)
        
        # Create malware object if applicable
        if threat_intel.malware_family:
            malware = Malware(
                name=threat_intel.malware_family,
                labels=["trojan"],  # Default label
                created_by_ref=self.organization_identity.id
            )
            stix_objects.append(malware)
        
        # Create threat actor if applicable
        if threat_intel.threat_actor:
            actor = ThreatActor(
                name=threat_intel.threat_actor,
                labels=["hacker"],  # Default label
                created_by_ref=self.organization_identity.id
            )
            stix_objects.append(actor)
        
        # Create attack patterns
        for pattern_name in threat_intel.attack_patterns:
            attack_pattern = AttackPattern(
                name=pattern_name,
                created_by_ref=self.organization_identity.id
            )
            stix_objects.append(attack_pattern)
        
        # Create vulnerabilities
        for vuln_id in threat_intel.vulnerabilities:
            vulnerability = Vulnerability(
                name=vuln_id,
                created_by_ref=self.organization_identity.id
            )
            stix_objects.append(vulnerability)
        
        # Create report
        report = Report(
            name=threat_intel.name,
            description=threat_intel.description,
            published=threat_intel.created,
            object_refs=[obj.id for obj in stix_objects[1:]],  # Exclude identity
            created_by_ref=self.organization_identity.id
        )
        stix_objects.append(report)
        
        # Create bundle
        bundle = Bundle(*stix_objects)
        
        # Export based on format
        if format_type == ExportFormat.STIX2_JSON:
            return self._export_stix_json(bundle, threat_intel.id)
        elif format_type == ExportFormat.STIX2_XML:
            return self._export_stix_xml(bundle, threat_intel.id)
        else:
            raise ValueError(f"Unsupported STIX format: {format_type}")
    
    def export_misp(self, threat_intel: ThreatIntelligence) -> str:
        """
        Export threat intelligence to MISP format
        
        Args:
            threat_intel: Threat intelligence data
            
        Returns:
            Path to exported MISP JSON file
        """
        misp_event = {
            "Event": {
                "id": str(uuid.uuid4()),
                "orgc_id": "1",
                "org_id": "1",
                "date": threat_intel.created.strftime("%Y-%m-%d"),
                "threat_level_id": self._get_misp_threat_level(threat_intel.confidence),
                "info": threat_intel.name,
                "published": True,
                "uuid": str(uuid.uuid4()),
                "attribute_count": len(threat_intel.iocs),
                "analysis": "2",  # Completed
                "timestamp": str(int(threat_intel.modified.timestamp())),
                "distribution": "3",  # All communities
                "proposal_email_lock": False,
                "locked": False,
                "publish_timestamp": str(int(threat_intel.created.timestamp())),
                "sharing_group_id": "0",
                "disable_correlation": False,
                "extends_uuid": "",
                "Attribute": []
            }
        }
        
        # Add IOCs as attributes
        for ioc in threat_intel.iocs:
            attribute = {
                "id": str(uuid.uuid4()),
                "type": self._get_misp_type(ioc.type),
                "category": self._get_misp_category(ioc.type),
                "to_ids": True,
                "uuid": str(uuid.uuid4()),
                "event_id": misp_event["Event"]["id"],
                "distribution": "5",
                "timestamp": str(int(ioc.first_seen.timestamp())),
                "comment": ioc.description,
                "sharing_group_id": "0",
                "deleted": False,
                "disable_correlation": False,
                "object_id": "0",
                "object_relation": None,
                "value": ioc.value,
                "Tag": [{"name": tag} for tag in ioc.tags]
            }
            misp_event["Event"]["Attribute"].append(attribute)
        
        # Export to file
        export_path = self.output_dir / f"misp_event_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(misp_event, f, indent=2, default=str)
        
        logger.info(f"MISP event exported: {export_path}")
        return str(export_path)
    
    def export_yara_rules(self, threat_intel: ThreatIntelligence, 
                         additional_patterns: List[Dict[str, str]] = None) -> str:
        """
        Export YARA rules for threat detection
        
        Args:
            threat_intel: Threat intelligence data
            additional_patterns: Additional YARA patterns
            
        Returns:
            Path to exported YARA file
        """
        rule_name = f"threat_{threat_intel.id.replace('-', '_')}"
        
        yara_rule = f"""/*
    YARA Rule: {rule_name}
    Description: {threat_intel.description}
    Author: Security Research Team
    Date: {datetime.now().strftime('%Y-%m-%d')}
    TLP: {threat_intel.tlp_level.value.upper()}
*/

rule {rule_name} {{
    meta:
        description = "{threat_intel.description}"
        author = "Security Research Team"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        threat_actor = "{threat_intel.threat_actor or 'Unknown'}"
        malware_family = "{threat_intel.malware_family or 'Unknown'}"
        confidence = "{threat_intel.confidence}"
        tlp = "{threat_intel.tlp_level.value}"
        
    strings:
"""
        
        # Add IOC-based strings
        string_count = 0
        for ioc in threat_intel.iocs:
            if ioc.type in ['hash', 'filename', 'registry_key']:
                string_count += 1
                yara_rule += f'        $s{string_count} = "{ioc.value}"\n'
        
        # Add additional patterns
        if additional_patterns:
            for pattern in additional_patterns:
                string_count += 1
                yara_rule += f'        $s{string_count} = {pattern["pattern"]}\n'
        
        # Add condition
        if string_count > 0:
            yara_rule += f"""
    condition:
        any of ($s*)
}}
"""
        else:
            yara_rule += """
    condition:
        false  // No patterns available
}
"""
        
        # Export to file
        export_path = self.output_dir / f"yara_rules_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yar"
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write(yara_rule)
        
        logger.info(f"YARA rules exported: {export_path}")
        return str(export_path)
    
    def export_ioc_csv(self, threat_intel: ThreatIntelligence) -> str:
        """
        Export IOCs to CSV format
        
        Args:
            threat_intel: Threat intelligence data
            
        Returns:
            Path to exported CSV file
        """
        ioc_data = []
        for ioc in threat_intel.iocs:
            ioc_data.append({
                'Type': ioc.type,
                'Value': ioc.value,
                'Description': ioc.description,
                'Confidence': ioc.confidence,
                'TLP_Level': ioc.tlp_level.value,
                'First_Seen': ioc.first_seen.isoformat(),
                'Last_Seen': ioc.last_seen.isoformat(),
                'Tags': ','.join(ioc.tags),
                'Source': ioc.source,
                'Threat_Actor': threat_intel.threat_actor or '',
                'Malware_Family': threat_intel.malware_family or ''
            })
        
        df = pd.DataFrame(ioc_data)
        export_path = self.output_dir / f"iocs_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(export_path, index=False)
        
        logger.info(f"IOC CSV exported: {export_path}")
        return str(export_path)
    
    def export_siem_format(self, threat_intel: ThreatIntelligence, 
                          siem_type: SIEMType) -> str:
        """
        Export threat intelligence in SIEM-specific format
        
        Args:
            threat_intel: Threat intelligence data
            siem_type: Target SIEM system
            
        Returns:
            Path to exported SIEM file
        """
        if siem_type == SIEMType.SPLUNK:
            return self._export_splunk_format(threat_intel)
        elif siem_type == SIEMType.ELASTIC:
            return self._export_elastic_format(threat_intel)
        elif siem_type == SIEMType.QRADAR:
            return self._export_qradar_format(threat_intel)
        elif siem_type == SIEMType.SENTINEL:
            return self._export_sentinel_format(threat_intel)
        else:
            raise ValueError(f"Unsupported SIEM type: {siem_type}")
    
    def create_custom_template(self, template_name: str, 
                             template_content: str,
                             branding: Optional[CustomBranding] = None) -> str:
        """
        Create custom export template
        
        Args:
            template_name: Name of the template
            template_content: Jinja2 template content
            branding: Custom branding configuration
            
        Returns:
            Path to created template file
        """
        # Apply branding if provided
        if branding:
            template_content = self._apply_branding(template_content, branding)
        
        template_path = self.template_dir / f"{template_name}.j2"
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        
        logger.info(f"Custom template created: {template_path}")
        return str(template_path)
    
    def export_custom_format(self, threat_intel: ThreatIntelligence,
                           template_name: str,
                           output_format: str = "json") -> str:
        """
        Export using custom template
        
        Args:
            threat_intel: Threat intelligence data
            template_name: Name of the template to use
            output_format: Output format (json, xml, yaml, etc.)
            
        Returns:
            Path to exported file
        """
        template = self.jinja_env.get_template(f"{template_name}.j2")
        
        # Prepare data for template
        template_data = {
            'threat_intel': threat_intel,
            'iocs': threat_intel.iocs,
            'generation_date': datetime.now().isoformat(),
            'export_format': output_format
        }
        
        # Render template
        rendered_content = template.render(**template_data)
        
        # Export to file
        file_extension = output_format.lower()
        export_path = self.output_dir / f"custom_{template_name}_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}"
        
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write(rendered_content)
        
        logger.info(f"Custom format exported: {export_path}")
        return str(export_path)    
   
 def push_to_taxii_server(self, stix_bundle_path: str, 
                            taxii_server_url: str,
                            collection_id: str,
                            username: str = None,
                            password: str = None) -> bool:
        """
        Push STIX bundle to TAXII server
        
        Args:
            stix_bundle_path: Path to STIX bundle file
            taxii_server_url: TAXII server URL
            collection_id: Target collection ID
            username: Authentication username
            password: Authentication password
            
        Returns:
            Success status
        """
        try:
            with open(stix_bundle_path, 'r') as f:
                stix_data = json.load(f)
            
            # Prepare TAXII request
            headers = {
                'Content-Type': 'application/stix+json;version=2.1',
                'Accept': 'application/stix+json;version=2.1'
            }
            
            # Add authentication if provided
            auth = None
            if username and password:
                auth = (username, password)
            
            # Push to TAXII server
            url = f"{taxii_server_url}/collections/{collection_id}/objects/"
            response = requests.post(url, json=stix_data, headers=headers, auth=auth)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Successfully pushed STIX data to TAXII server: {response.status_code}")
                return True
            else:
                logger.error(f"Failed to push STIX data: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error pushing to TAXII server: {e}")
            return False
    
    def create_siem_integration_api(self, threat_intel: ThreatIntelligence,
                                  api_endpoint: str,
                                  api_key: str = None,
                                  siem_type: SIEMType = SIEMType.SPLUNK) -> bool:
        """
        Push threat intelligence to SIEM via API
        
        Args:
            threat_intel: Threat intelligence data
            api_endpoint: SIEM API endpoint
            api_key: API authentication key
            siem_type: Target SIEM system
            
        Returns:
            Success status
        """
        try:
            # Format data for specific SIEM
            if siem_type == SIEMType.SPLUNK:
                payload = self._format_for_splunk_api(threat_intel)
                headers = {'Authorization': f'Splunk {api_key}', 'Content-Type': 'application/json'}
            elif siem_type == SIEMType.ELASTIC:
                payload = self._format_for_elastic_api(threat_intel)
                headers = {'Authorization': f'ApiKey {api_key}', 'Content-Type': 'application/json'}
            elif siem_type == SIEMType.SENTINEL:
                payload = self._format_for_sentinel_api(threat_intel)
                headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
            else:
                raise ValueError(f"API integration not implemented for {siem_type}")
            
            # Send to SIEM
            response = requests.post(api_endpoint, json=payload, headers=headers)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Successfully pushed threat intel to {siem_type.value}: {response.status_code}")
                return True
            else:
                logger.error(f"Failed to push to {siem_type.value}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error pushing to SIEM API: {e}")
            return False
    
    # Helper methods for STIX export
    def _create_stix_pattern(self, ioc: IOCData) -> str:
        """Create STIX pattern from IOC"""
        if ioc.type == 'ip':
            return f"[ipv4-addr:value = '{ioc.value}']"
        elif ioc.type == 'domain':
            return f"[domain-name:value = '{ioc.value}']"
        elif ioc.type == 'url':
            return f"[url:value = '{ioc.value}']"
        elif ioc.type == 'hash':
            if len(ioc.value) == 32:
                return f"[file:hashes.MD5 = '{ioc.value}']"
            elif len(ioc.value) == 40:
                return f"[file:hashes.SHA-1 = '{ioc.value}']"
            elif len(ioc.value) == 64:
                return f"[file:hashes.SHA-256 = '{ioc.value}']"
        elif ioc.type == 'email':
            return f"[email-addr:value = '{ioc.value}']"
        elif ioc.type == 'filename':
            return f"[file:name = '{ioc.value}']"
        else:
            return f"[x-custom-ioc:value = '{ioc.value}']"
    
    def _get_stix_labels(self, ioc_type: str) -> List[str]:
        """Get STIX labels for IOC type"""
        label_map = {
            'ip': ['malicious-activity'],
            'domain': ['malicious-activity'],
            'url': ['malicious-activity'],
            'hash': ['malicious-activity'],
            'email': ['malicious-activity'],
            'filename': ['malicious-activity']
        }
        return label_map.get(ioc_type, ['anomalous-activity'])
    
    def _get_tlp_marking(self, tlp_level: TLPLevel):
        """Get STIX TLP marking"""
        tlp_map = {
            TLPLevel.WHITE: TLP_WHITE,
            TLPLevel.GREEN: TLP_GREEN,
            TLPLevel.AMBER: TLP_AMBER,
            TLPLevel.RED: TLP_RED
        }
        return tlp_map.get(tlp_level, TLP_WHITE)
    
    def _export_stix_json(self, bundle: Bundle, threat_id: str) -> str:
        """Export STIX bundle as JSON"""
        export_path = self.output_dir / f"stix2_{threat_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write(bundle.serialize(pretty=True))
        
        logger.info(f"STIX2 JSON exported: {export_path}")
        return str(export_path)
    
    def _export_stix_xml(self, bundle: Bundle, threat_id: str) -> str:
        """Export STIX bundle as XML"""
        # Convert JSON to XML (simplified approach)
        stix_dict = json.loads(bundle.serialize())
        
        root = ET.Element("stix:Bundle")
        root.set("xmlns:stix", "http://stix.mitre.org/stix-1")
        
        for obj in stix_dict.get("objects", []):
            obj_elem = ET.SubElement(root, "stix:Object")
            obj_elem.set("type", obj.get("type", "unknown"))
            obj_elem.set("id", obj.get("id", ""))
            
            for key, value in obj.items():
                if key not in ["type", "id"]:
                    prop_elem = ET.SubElement(obj_elem, f"stix:{key}")
                    prop_elem.text = str(value)
        
        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        
        export_path = self.output_dir / f"stix2_{threat_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write(xml_str)
        
        logger.info(f"STIX2 XML exported: {export_path}")
        return str(export_path)
    
    # Helper methods for MISP export
    def _get_misp_threat_level(self, confidence: float) -> str:
        """Get MISP threat level from confidence"""
        if confidence >= 0.8:
            return "1"  # High
        elif confidence >= 0.6:
            return "2"  # Medium
        elif confidence >= 0.4:
            return "3"  # Low
        else:
            return "4"  # Undefined
    
    def _get_misp_type(self, ioc_type: str) -> str:
        """Get MISP attribute type"""
        type_map = {
            'ip': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'hash': 'sha256',
            'email': 'email-dst',
            'filename': 'filename'
        }
        return type_map.get(ioc_type, 'other')
    
    def _get_misp_category(self, ioc_type: str) -> str:
        """Get MISP attribute category"""
        category_map = {
            'ip': 'Network activity',
            'domain': 'Network activity',
            'url': 'Network activity',
            'hash': 'Payload delivery',
            'email': 'Network activity',
            'filename': 'Payload delivery'
        }
        return category_map.get(ioc_type, 'Other')
    
    # Helper methods for SIEM export
    def _export_splunk_format(self, threat_intel: ThreatIntelligence) -> str:
        """Export in Splunk format"""
        splunk_data = []
        
        for ioc in threat_intel.iocs:
            event = {
                'timestamp': ioc.first_seen.isoformat(),
                'threat_id': threat_intel.id,
                'threat_name': threat_intel.name,
                'threat_actor': threat_intel.threat_actor,
                'malware_family': threat_intel.malware_family,
                'ioc_type': ioc.type,
                'ioc_value': ioc.value,
                'confidence': ioc.confidence,
                'tlp_level': ioc.tlp_level.value,
                'description': ioc.description,
                'tags': ','.join(ioc.tags),
                'source': ioc.source
            }
            splunk_data.append(event)
        
        export_path = self.output_dir / f"splunk_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(export_path, 'w', encoding='utf-8') as f:
            for event in splunk_data:
                f.write(json.dumps(event) + '\n')
        
        logger.info(f"Splunk format exported: {export_path}")
        return str(export_path)
    
    def _export_elastic_format(self, threat_intel: ThreatIntelligence) -> str:
        """Export in Elasticsearch format"""
        elastic_data = []
        
        for ioc in threat_intel.iocs:
            doc = {
                '@timestamp': ioc.first_seen.isoformat(),
                'threat': {
                    'id': threat_intel.id,
                    'name': threat_intel.name,
                    'actor': threat_intel.threat_actor,
                    'malware_family': threat_intel.malware_family,
                    'confidence': threat_intel.confidence
                },
                'indicator': {
                    'type': ioc.type,
                    'value': ioc.value,
                    'confidence': ioc.confidence,
                    'tlp_level': ioc.tlp_level.value,
                    'description': ioc.description,
                    'tags': ioc.tags,
                    'source': ioc.source,
                    'first_seen': ioc.first_seen.isoformat(),
                    'last_seen': ioc.last_seen.isoformat()
                }
            }
            
            # Add index metadata for bulk import
            index_meta = {'index': {'_index': 'threat-intelligence', '_type': '_doc'}}
            elastic_data.append(json.dumps(index_meta))
            elastic_data.append(json.dumps(doc))
        
        export_path = self.output_dir / f"elastic_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(elastic_data) + '\n')
        
        logger.info(f"Elasticsearch format exported: {export_path}")
        return str(export_path)
    
    def _export_qradar_format(self, threat_intel: ThreatIntelligence) -> str:
        """Export in QRadar XML format"""
        root = ET.Element("ThreatIntelligence")
        
        threat_elem = ET.SubElement(root, "Threat")
        threat_elem.set("id", threat_intel.id)
        threat_elem.set("name", threat_intel.name)
        
        if threat_intel.threat_actor:
            threat_elem.set("actor", threat_intel.threat_actor)
        if threat_intel.malware_family:
            threat_elem.set("malware", threat_intel.malware_family)
        
        indicators_elem = ET.SubElement(threat_elem, "Indicators")
        
        for ioc in threat_intel.iocs:
            ioc_elem = ET.SubElement(indicators_elem, "Indicator")
            ioc_elem.set("type", ioc.type)
            ioc_elem.set("value", ioc.value)
            ioc_elem.set("confidence", str(ioc.confidence))
            ioc_elem.set("tlp", ioc.tlp_level.value)
            ioc_elem.text = ioc.description
        
        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        
        export_path = self.output_dir / f"qradar_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write(xml_str)
        
        logger.info(f"QRadar format exported: {export_path}")
        return str(export_path)
    
    def _export_sentinel_format(self, threat_intel: ThreatIntelligence) -> str:
        """Export in Microsoft Sentinel format"""
        sentinel_data = {
            'ThreatIntelligenceIndicator': []
        }
        
        for ioc in threat_intel.iocs:
            indicator = {
                'TimeGenerated': ioc.first_seen.isoformat(),
                'SourceSystem': 'Custom',
                'ThreatType': threat_intel.malware_family or 'Unknown',
                'IndicatorId': str(uuid.uuid4()),
                'ThreatActor': threat_intel.threat_actor or 'Unknown',
                'IndicatorType': ioc.type,
                'IndicatorValue': ioc.value,
                'Confidence': int(ioc.confidence * 100),
                'TLPLevel': ioc.tlp_level.value,
                'Description': ioc.description,
                'Tags': ioc.tags,
                'Source': ioc.source,
                'FirstSeen': ioc.first_seen.isoformat(),
                'LastSeen': ioc.last_seen.isoformat()
            }
            sentinel_data['ThreatIntelligenceIndicator'].append(indicator)
        
        export_path = self.output_dir / f"sentinel_{threat_intel.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(sentinel_data, f, indent=2, default=str)
        
        logger.info(f"Sentinel format exported: {export_path}")
        return str(export_path)
    
    # Helper methods for API integration
    def _format_for_splunk_api(self, threat_intel: ThreatIntelligence) -> Dict[str, Any]:
        """Format data for Splunk API"""
        events = []
        for ioc in threat_intel.iocs:
            event = {
                'event': {
                    'threat_id': threat_intel.id,
                    'threat_name': threat_intel.name,
                    'ioc_type': ioc.type,
                    'ioc_value': ioc.value,
                    'confidence': ioc.confidence,
                    'source': ioc.source
                },
                'sourcetype': 'threat_intelligence',
                'index': 'security'
            }
            events.append(event)
        return {'events': events}
    
    def _format_for_elastic_api(self, threat_intel: ThreatIntelligence) -> Dict[str, Any]:
        """Format data for Elasticsearch API"""
        docs = []
        for ioc in threat_intel.iocs:
            doc = {
                '@timestamp': ioc.first_seen.isoformat(),
                'threat_id': threat_intel.id,
                'threat_name': threat_intel.name,
                'ioc_type': ioc.type,
                'ioc_value': ioc.value,
                'confidence': ioc.confidence,
                'source': ioc.source
            }
            docs.append(doc)
        return {'docs': docs}
    
    def _format_for_sentinel_api(self, threat_intel: ThreatIntelligence) -> Dict[str, Any]:
        """Format data for Microsoft Sentinel API"""
        indicators = []
        for ioc in threat_intel.iocs:
            indicator = {
                'kind': 'indicator',
                'properties': {
                    'displayName': f"{threat_intel.name} - {ioc.type}",
                    'description': ioc.description,
                    'pattern': f"[{ioc.type}:value = '{ioc.value}']",
                    'patternType': 'stix',
                    'source': ioc.source,
                    'confidence': int(ioc.confidence * 100),
                    'threatTypes': [threat_intel.malware_family or 'malicious-activity']
                }
            }
            indicators.append(indicator)
        return {'value': indicators}
    
    def _apply_branding(self, template_content: str, branding: CustomBranding) -> str:
        """Apply custom branding to template"""
        # Replace branding placeholders
        branded_content = template_content.replace('{{ORGANIZATION_NAME}}', branding.organization_name)
        
        if branding.header_template:
            branded_content = branding.header_template + '\n' + branded_content
        
        if branding.footer_template:
            branded_content = branded_content + '\n' + branding.footer_template
        
        if branding.css_overrides:
            branded_content = branded_content.replace('{{CUSTOM_CSS}}', branding.css_overrides)
        
        return branded_content
    
    def _create_default_templates(self):
        """Create default export templates"""
        
        # Custom JSON template
        json_template = """{
    "threat_intelligence": {
        "id": "{{ threat_intel.id }}",
        "name": "{{ threat_intel.name }}",
        "description": "{{ threat_intel.description }}",
        "threat_actor": "{{ threat_intel.threat_actor }}",
        "malware_family": "{{ threat_intel.malware_family }}",
        "confidence": {{ threat_intel.confidence }},
        "tlp_level": "{{ threat_intel.tlp_level.value }}",
        "created": "{{ threat_intel.created.isoformat() }}",
        "modified": "{{ threat_intel.modified.isoformat() }}",
        "indicators": [
            {% for ioc in iocs %}
            {
                "type": "{{ ioc.type }}",
                "value": "{{ ioc.value }}",
                "description": "{{ ioc.description }}",
                "confidence": {{ ioc.confidence }},
                "tlp_level": "{{ ioc.tlp_level.value }}",
                "first_seen": "{{ ioc.first_seen.isoformat() }}",
                "last_seen": "{{ ioc.last_seen.isoformat() }}",
                "tags": {{ ioc.tags | tojson }},
                "source": "{{ ioc.source }}"
            }{% if not loop.last %},{% endif %}
            {% endfor %}
        ]
    },
    "metadata": {
        "generated": "{{ generation_date }}",
        "format": "{{ export_format }}"
    }
}"""
        
        with open(self.template_dir / "custom_json.j2", 'w') as f:
            f.write(json_template)
        
        # Custom XML template
        xml_template = """<?xml version="1.0" encoding="UTF-8"?>
<ThreatIntelligence>
    <Threat id="{{ threat_intel.id }}" name="{{ threat_intel.name }}">
        <Description>{{ threat_intel.description }}</Description>
        <ThreatActor>{{ threat_intel.threat_actor }}</ThreatActor>
        <MalwareFamily>{{ threat_intel.malware_family }}</MalwareFamily>
        <Confidence>{{ threat_intel.confidence }}</Confidence>
        <TLPLevel>{{ threat_intel.tlp_level.value }}</TLPLevel>
        <Created>{{ threat_intel.created.isoformat() }}</Created>
        <Modified>{{ threat_intel.modified.isoformat() }}</Modified>
        <Indicators>
            {% for ioc in iocs %}
            <Indicator type="{{ ioc.type }}" value="{{ ioc.value }}">
                <Description>{{ ioc.description }}</Description>
                <Confidence>{{ ioc.confidence }}</Confidence>
                <TLPLevel>{{ ioc.tlp_level.value }}</TLPLevel>
                <FirstSeen>{{ ioc.first_seen.isoformat() }}</FirstSeen>
                <LastSeen>{{ ioc.last_seen.isoformat() }}</LastSeen>
                <Tags>
                    {% for tag in ioc.tags %}
                    <Tag>{{ tag }}</Tag>
                    {% endfor %}
                </Tags>
                <Source>{{ ioc.source }}</Source>
            </Indicator>
            {% endfor %}
        </Indicators>
    </Threat>
    <Metadata>
        <Generated>{{ generation_date }}</Generated>
        <Format>{{ export_format }}</Format>
    </Metadata>
</ThreatIntelligence>"""
        
        with open(self.template_dir / "custom_xml.j2", 'w') as f:
            f.write(xml_template)
        
        logger.info("Default export templates created")

# Example usage and testing
if __name__ == "__main__":
    # Initialize the engine
    engine = ExportIntegrationEngine()
    
    # Create sample threat intelligence data
    sample_iocs = [
        IOCData(
            type="ip",
            value="192.168.1.100",
            description="Command and control server",
            confidence=0.9,
            tlp_level=TLPLevel.AMBER,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            tags=["malware", "c2"],
            source="Security Research Lab",
            context={"country": "Unknown", "asn": "AS12345"}
        ),
        IOCData(
            type="hash",
            value="d41d8cd98f00b204e9800998ecf8427e",
            description="Malicious executable hash",
            confidence=0.95,
            tlp_level=TLPLevel.AMBER,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            tags=["malware", "executable"],
            source="Security Research Lab",
            context={"file_type": "PE", "size": 1024}
        )
    ]
    
    sample_threat_intel = ThreatIntelligence(
        id=str(uuid.uuid4()),
        name="Sample Threat Campaign",
        description="Advanced persistent threat campaign targeting financial institutions",
        threat_actor="APT29",
        malware_family="Cozy Bear",
        attack_patterns=["T1566.001", "T1055"],
        iocs=sample_iocs,
        vulnerabilities=["CVE-2023-1234"],
        confidence=0.85,
        tlp_level=TLPLevel.AMBER,
        created=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc)
    )
    
    # Test exports
    try:
        # STIX2 export
        stix_path = engine.export_stix2(sample_threat_intel)
        print(f"STIX2 export: {stix_path}")
        
        # MISP export
        misp_path = engine.export_misp(sample_threat_intel)
        print(f"MISP export: {misp_path}")
        
        # YARA rules export
        yara_path = engine.export_yara_rules(sample_threat_intel)
        print(f"YARA rules export: {yara_path}")
        
        # IOC CSV export
        csv_path = engine.export_ioc_csv(sample_threat_intel)
        print(f"IOC CSV export: {csv_path}")
        
        # SIEM exports
        splunk_path = engine.export_siem_format(sample_threat_intel, SIEMType.SPLUNK)
        print(f"Splunk export: {splunk_path}")
        
        elastic_path = engine.export_siem_format(sample_threat_intel, SIEMType.ELASTIC)
        print(f"Elasticsearch export: {elastic_path}")
        
        # Custom format export
        custom_path = engine.export_custom_format(sample_threat_intel, "custom_json", "json")
        print(f"Custom JSON export: {custom_path}")
        
    except Exception as e:
        logger.error(f"Error during export testing: {e}")
        print(f"Error: {e}")