#!/usr/bin/env python3
import sys
sys.path.append('tools')

try:
    from ai_enhanced_data_models import MITREMapping, Evidence, ConfidenceLevel, EvidenceTracker
    print("Data models imported successfully")
    
    class TestMapper:
        def __init__(self):
            self.evidence_tracker = EvidenceTracker()
            print("TestMapper initialized")
    
    mapper = TestMapper()
    print("Test completed successfully")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()