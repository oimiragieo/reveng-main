#!/usr/bin/env python3
"""
Test script for network topology discovery functionality
"""

import sys
import os
sys.path.append('tools')

from corporate_exposure_detector import CorporateExposureDetector, ExposureType

def test_network_topology_discovery():
    """Test the network topology discovery functionality"""
    
    # Sample code with various network patterns
    test_code = """
    # API endpoints
    API_BASE_URL = "https://api.example.com/v1"
    INTERNAL_API = "http://10.0.1.100:8080/api"
    WEBSOCKET_URL = "wss://ws.example.com/chat"
    
    # Database connections
    DATABASE_URL = "postgresql://user:pass@db.internal.com:5432/mydb"
    MONGO_URL = "mongodb://admin:secret@192.168.1.50:27017/app"
    
    # Authentication
    API_KEY = "Bearer sk-1234567890abcdef"
    CLIENT_ID = "oauth_client_12345"
    CLIENT_SECRET = "oauth_secret_abcdef123456"
    
    # Network configuration
    SERVER_HOST = "internal-service.local"
    SERVER_PORT = 9000
    TIMEOUT = 30
    SSL_ENABLED = true
    
    # Service dependencies
    def call_user_service():
        response = requests.get("https://users.internal.com/api/v2/users")
        return response.json()
    
    def connect_to_cache():
        redis_client = redis.Redis(host='cache.internal.com', port=6379)
        return redis_client
    
    # Load balancer config
    upstream backend {
        server 10.0.1.10:8080;
        server 10.0.1.11:8080;
        server 10.0.1.12:8080;
    }
    
    proxy_pass http://backend;
    """
    
    print("Testing Network Topology Discovery...")
    print("=" * 50)
    
    detector = CorporateExposureDetector()
    exposures = detector.analyze_code(test_code, "test_network_config.py")
    
    # Categorize exposures
    api_endpoints = [e for e in exposures if e.exposure_type == ExposureType.API_ENDPOINT]
    network_topology = [e for e in exposures if e.exposure_type == ExposureType.NETWORK_TOPOLOGY]
    credentials = [e for e in exposures if e.exposure_type == ExposureType.CREDENTIAL]
    db_connections = [e for e in exposures if e.exposure_type == ExposureType.DATABASE_CONNECTION]
    
    print(f"Total exposures found: {len(exposures)}")
    print(f"API endpoints: {len(api_endpoints)}")
    print(f"Network topology: {len(network_topology)}")
    print(f"Credentials: {len(credentials)}")
    print(f"Database connections: {len(db_connections)}")
    print()
    
    # Display API endpoint discoveries
    if api_endpoints:
        print("API Endpoints Discovered:")
        print("-" * 30)
        for exposure in api_endpoints:
            print(f"  • {exposure.title}")
            print(f"    Value: {exposure.value}")
            print(f"    Severity: {exposure.severity.value}")
            print(f"    Confidence: {exposure.confidence:.2f}")
            if exposure.metadata.get('analysis'):
                analysis = exposure.metadata['analysis']
                print(f"    Protocol: {analysis.get('protocol', 'unknown')}")
                print(f"    Internal: {analysis.get('is_internal', False)}")
                print(f"    Secure: {analysis.get('is_secure', False)}")
            print()
    
    # Display network topology discoveries
    if network_topology:
        print("Network Topology Discovered:")
        print("-" * 30)
        for exposure in network_topology:
            print(f"  • {exposure.title}")
            print(f"    Description: {exposure.description}")
            print(f"    Value: {exposure.value}")
            print(f"    Business Impact: {exposure.business_impact}")
            if exposure.metadata:
                metadata = exposure.metadata
                print(f"    Internal Services: {metadata.get('internal_services', 0)}")
                print(f"    External Dependencies: {metadata.get('external_dependencies', 0)}")
            print()
    
    # Display authentication mechanisms
    auth_mechanisms = [e for e in api_endpoints if 'auth' in e.title.lower() or 'oauth' in e.title.lower()]
    if auth_mechanisms:
        print("Authentication Mechanisms:")
        print("-" * 30)
        for exposure in auth_mechanisms:
            print(f"  • {exposure.title}")
            print(f"    Value: {exposure.value}")
            print(f"    Remediation: {exposure.remediation}")
            print()
    
    # Generate summary report
    report = detector.generate_exposure_report(exposures)
    print("Summary Report:")
    print("-" * 30)
    print(f"Risk Score: {report['risk_score']:.1f}/10")
    print(f"Business Impact: {report['business_impact_assessment']}")
    print()
    print("Recommended Actions:")
    for i, action in enumerate(report['recommended_actions'][:5], 1):
        print(f"  {i}. {action}")
    
    return len(exposures) > 0

def test_specific_patterns():
    """Test specific network patterns"""
    
    test_cases = [
        # Internal IP addresses
        ("config = {'host': '192.168.1.100', 'port': 8080}", "Internal IP"),
        
        # API endpoints with authentication
        ("headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9'}", "JWT Auth"),
        
        # Service discovery
        ("consul_url = 'consul://consul.service.consul:8500'", "Service Discovery"),
        
        # WebSocket connections
        ("ws = new WebSocket('wss://realtime.app.com/ws')", "WebSocket"),
        
        # Database with credentials
        ("conn = 'mysql://root:password123@db.local:3306/app'", "DB with Creds"),
    ]
    
    print("\nTesting Specific Patterns:")
    print("=" * 50)
    
    detector = CorporateExposureDetector()
    
    for code, description in test_cases:
        print(f"\nTesting: {description}")
        print(f"Code: {code}")
        
        exposures = detector.analyze_code(code, f"test_{description.lower().replace(' ', '_')}.py")
        
        if exposures:
            print(f"✓ Found {len(exposures)} exposure(s)")
            for exp in exposures:
                print(f"  - {exp.title} (Confidence: {exp.confidence:.2f})")
        else:
            print("✗ No exposures detected")

if __name__ == "__main__":
    print("Network Topology Discovery Test")
    print("=" * 60)
    
    success = test_network_topology_discovery()
    test_specific_patterns()
    
    if success:
        print("\n✓ Network topology discovery functionality is working!")
    else:
        print("\n✗ Network topology discovery needs debugging")