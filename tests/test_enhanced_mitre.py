#!/usr/bin/env python3
import sys
sys.path.append('tools')

from threat_intelligence_correlator import ThreatIntelligenceCorrelator

def test_enhanced_mitre_mapping():
    """Test the enhanced MITRE ATT&CK mapping functionality"""
    
    # Initialize correlator
    correlator = ThreatIntelligenceCorrelator()
    
    # Test data
    sample_code = """
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, NULL);
    WriteProcessMemory(hProcess, lpBaseAddress, shellcode, shellcode_size, NULL);
    RegSetValueEx(hKey, "TestValue", 0, REG_SZ, (BYTE*)data, strlen(data));
    InternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HttpOpenRequest(hConnect, "GET", "/malware.exe", NULL, NULL, NULL, 0, 0);
    """
    
    sample_apis = [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "RegSetValueEx", "RegCreateKeyEx", "InternetOpen", "HttpOpenRequest",
        "URLDownloadToFile", "CreateProcess"
    ]
    
    sample_registry = [
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MalwareService"
    ]
    
    sample_files = [
        "C:\\Windows\\Temp\\malware.exe",
        "C:\\Users\\victim\\AppData\\Roaming\\update.bat",
        "C:\\ProgramData\\suspicious.dll"
    ]
    
    sample_network = [
        "http://malicious-domain.com/payload.exe",
        "192.168.1.100:4444",
        "evil.com"
    ]
    
    print("Testing Enhanced MITRE ATT&CK Mapping...")
    print("=" * 50)
    
    # Test enhanced mapping
    mapping = correlator.map_to_mitre_attack_enhanced(
        decompiled_code=sample_code,
        api_calls=sample_apis,
        registry_keys=sample_registry,
        file_paths=sample_files,
        network_indicators=sample_network
    )
    
    print(f"\nEnhanced Mapping Results:")
    print(f"Techniques mapped: {len(mapping.techniques)}")
    print(f"Tactics covered: {len(mapping.tactics)}")
    print(f"Kill chain phases: {len(mapping.kill_chain_phases)}")
    
    print(f"\nDetected Techniques:")
    for technique_id in mapping.techniques:
        confidence = mapping.confidence_scores.get(technique_id, 0.0)
        details = mapping.technique_details.get(technique_id, {})
        print(f"  {technique_id}: {details.get('name', 'Unknown')} (Confidence: {confidence:.2f})")
        print(f"    Evidence: {details.get('evidence', 'No evidence')}")
        print(f"    Detection Methods: {details.get('detection_methods', [])}")
        print()
    
    print(f"Tactics: {', '.join(mapping.tactics)}")
    print(f"Kill Chain Phases: {', '.join(mapping.kill_chain_phases)}")
    
    # Test report generation
    print("\nGenerating Enhanced MITRE ATT&CK Report...")
    report = correlator.generate_mitre_attack_report(mapping)
    
    print(f"\nReport Summary:")
    summary = report.get('summary', {})
    print(f"  Total Techniques: {summary.get('total_techniques', 0)}")
    print(f"  Total Tactics: {summary.get('total_tactics', 0)}")
    print(f"  Average Confidence: {summary.get('avg_confidence', 0):.2f}")
    print(f"  Kill Chain Coverage: {summary.get('coverage_score', 0):.1f}%")
    
    confidence_dist = summary.get('confidence_distribution', {})
    print(f"\nConfidence Distribution:")
    for level, count in confidence_dist.items():
        if level != 'percentages':
            percentage = confidence_dist.get('percentages', {}).get(level, 0)
            print(f"  {level.replace('_', ' ').title()}: {count} ({percentage:.1f}%)")
    
    print(f"\nTop Recommendations:")
    recommendations = report.get('recommendations', [])[:3]  # Top 3
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec.get('tactic')} (Priority: {rec.get('implementation_priority')})")
        print(f"     Risk Level: {rec.get('risk_level')}")
        print(f"     Techniques: {len(rec.get('affected_techniques', []))}")
        print(f"     Top Mitigation: {rec.get('mitigations', ['N/A'])[0]}")
        print()
    
    print("Enhanced MITRE ATT&CK mapping test completed successfully!")

if __name__ == "__main__":
    test_enhanced_mitre_mapping()