#!/usr/bin/env python3
"""
Ghidra script to analyze PE import table and API usage

This script analyzes a PE binary's import table and:
- Lists all imported DLLs and functions
- Categorizes APIs by functionality
- Identifies suspicious API usage
- Maps API calls to behavioral patterns
- Generates API usage statistics

Usage:
    ghidraRun headless analyze_imports.py <binary_path>
"""

import json
import sys
from ghidra.program.model.listing import Program
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor

# API categorization mappings
API_CATEGORIES = {
    'file_io': [
        'CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'CopyFile',
        'MoveFile', 'FindFirstFile', 'FindNextFile', 'GetFileAttributes',
        'SetFileAttributes', 'CreateDirectory', 'RemoveDirectory'
    ],
    'network': [
        'WSAStartup', 'WSACleanup', 'socket', 'connect', 'bind', 'listen',
        'accept', 'send', 'recv', 'closesocket', 'gethostbyname',
        'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'HttpSendRequest'
    ],
    'process': [
        'CreateProcess', 'TerminateProcess', 'OpenProcess', 'GetProcessId',
        'GetCurrentProcessId', 'ExitProcess', 'CreateThread', 'TerminateThread',
        'SuspendThread', 'ResumeThread'
    ],
    'registry': [
        'RegOpenKey', 'RegCreateKey', 'RegDeleteKey', 'RegQueryValue',
        'RegSetValue', 'RegCloseKey', 'RegEnumKey', 'RegEnumValue'
    ],
    'crypto': [
        'CryptAcquireContext', 'CryptCreateHash', 'CryptHashData',
        'CryptGetHashParam', 'CryptDestroyHash', 'CryptEncrypt', 'CryptDecrypt'
    ],
    'memory': [
        'VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'VirtualQuery',
        'HeapAlloc', 'HeapFree', 'GlobalAlloc', 'GlobalFree'
    ],
    'gui': [
        'CreateWindow', 'ShowWindow', 'UpdateWindow', 'GetMessage',
        'DispatchMessage', 'SendMessage', 'PostMessage', 'RegisterClass'
    ],
    'system': [
        'GetSystemTime', 'SetSystemTime', 'GetTickCount', 'Sleep',
        'GetComputerName', 'GetUserName', 'GetVersion', 'GetSystemInfo'
    ]
}

# Suspicious API patterns
SUSPICIOUS_APIS = [
    'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory',
    'ReadProcessMemory', 'OpenProcess', 'SetWindowsHookEx', 'SetTimer',
    'CreateService', 'StartService', 'RegSetValue', 'RegCreateKey',
    'InternetOpen', 'HttpOpenRequest', 'CryptEncrypt', 'CryptDecrypt'
]

def analyze_imports():
    """Analyze PE import table and API usage"""

    # Get current program
    program = getCurrentProgram()
    if not program:
        print("Error: No program loaded")
        return

    # Get symbol table
    symbol_table = program.getSymbolTable()

    # Results storage
    results = {
        'program_name': program.getName(),
        'imported_dlls': {},
        'api_categories': {},
        'suspicious_apis': [],
        'behavioral_indicators': [],
        'statistics': {
            'total_imports': 0,
            'dll_count': 0,
            'suspicious_count': 0
        }
    }

    print(f"Analyzing imports for {program.getName()}...")

    # Get all imported symbols
    imported_symbols = []
    for symbol in symbol_table.getSymbols():
        if symbol.getSymbolType() == SymbolType.IMPORT:
            imported_symbols.append(symbol)

    print(f"Found {len(imported_symbols)} imported symbols")

    # Group by DLL
    dll_groups = {}
    for symbol in imported_symbols:
        dll_name = get_dll_name(symbol)
        if dll_name not in dll_groups:
            dll_groups[dll_name] = []
        dll_groups[dll_name].append(symbol)

    # Analyze each DLL
    for dll_name, symbols in dll_groups.items():
        dll_info = analyze_dll_imports(dll_name, symbols)
        results['imported_dlls'][dll_name] = dll_info
        results['statistics']['dll_count'] += 1

    # Categorize APIs
    results['api_categories'] = categorize_apis(imported_symbols)

    # Find suspicious APIs
    results['suspicious_apis'] = find_suspicious_apis(imported_symbols)
    results['statistics']['suspicious_count'] = len(results['suspicious_apis'])

    # Generate behavioral indicators
    results['behavioral_indicators'] = generate_behavioral_indicators(results)

    # Calculate statistics
    results['statistics']['total_imports'] = len(imported_symbols)

    # Output results
    output_file = f"{program.getName()}_imports.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results saved to {output_file}")
    print(f"Analyzed {results['statistics']['dll_count']} DLLs")
    print(f"Found {results['statistics']['suspicious_count']} suspicious APIs")

def get_dll_name(symbol):
    """Extract DLL name from import symbol"""
    symbol_name = symbol.getName()
    if '::' in symbol_name:
        return symbol_name.split('::')[0]
    return 'Unknown'

def analyze_dll_imports(dll_name, symbols):
    """Analyze imports for a specific DLL"""

    dll_info = {
        'dll_name': dll_name,
        'function_count': len(symbols),
        'functions': [],
        'categories': {},
        'suspicious_functions': []
    }

    # Analyze each function
    for symbol in symbols:
        func_name = symbol.getName()
        if '::' in func_name:
            func_name = func_name.split('::')[1]

        func_info = {
            'name': func_name,
            'address': str(symbol.getAddress()),
            'is_suspicious': func_name in SUSPICIOUS_APIS
        }

        dll_info['functions'].append(func_info)

        if func_info['is_suspicious']:
            dll_info['suspicious_functions'].append(func_name)

    # Categorize functions in this DLL
    dll_info['categories'] = categorize_dll_functions(dll_info['functions'])

    return dll_info

def categorize_apis(imported_symbols):
    """Categorize all imported APIs"""

    categories = {}
    for category, apis in API_CATEGORIES.items():
        categories[category] = []

    for symbol in imported_symbols:
        symbol_name = symbol.getName()
        if '::' in symbol_name:
            symbol_name = symbol_name.split('::')[1]

        # Find category for this API
        for category, apis in API_CATEGORIES.items():
            if symbol_name in apis:
                categories[category].append({
                    'name': symbol_name,
                    'address': str(symbol.getAddress()),
                    'dll': get_dll_name(symbol)
                })
                break

    return categories

def categorize_dll_functions(functions):
    """Categorize functions within a DLL"""

    categories = {}
    for category, apis in API_CATEGORIES.items():
        categories[category] = []

    for func in functions:
        func_name = func['name']
        for category, apis in API_CATEGORIES.items():
            if func_name in apis:
                categories[category].append(func_name)
                break

    return categories

def find_suspicious_apis(imported_symbols):
    """Find suspicious API usage"""

    suspicious = []
    for symbol in imported_symbols:
        symbol_name = symbol.getName()
        if '::' in symbol_name:
            symbol_name = symbol_name.split('::')[1]

        if symbol_name in SUSPICIOUS_APIS:
            suspicious.append({
                'name': symbol_name,
                'address': str(symbol.getAddress()),
                'dll': get_dll_name(symbol),
                'risk_level': get_risk_level(symbol_name)
            })

    return suspicious

def get_risk_level(api_name):
    """Get risk level for suspicious API"""

    high_risk = [
        'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory',
        'SetWindowsHookEx', 'CreateService', 'StartService'
    ]

    medium_risk = [
        'ReadProcessMemory', 'OpenProcess', 'RegSetValue', 'RegCreateKey',
        'InternetOpen', 'HttpOpenRequest'
    ]

    if api_name in high_risk:
        return 'high'
    elif api_name in medium_risk:
        return 'medium'
    else:
        return 'low'

def generate_behavioral_indicators(results):
    """Generate behavioral indicators from API analysis"""

    indicators = []

    # File operations
    if results['api_categories'].get('file_io'):
        indicators.append({
            'type': 'file_operations',
            'description': 'Performs file I/O operations',
            'apis': [api['name'] for api in results['api_categories']['file_io']]
        })

    # Network operations
    if results['api_categories'].get('network'):
        indicators.append({
            'type': 'network_operations',
            'description': 'Makes network connections',
            'apis': [api['name'] for api in results['api_categories']['network']]
        })

    # Process manipulation
    if results['api_categories'].get('process'):
        indicators.append({
            'type': 'process_manipulation',
            'description': 'Manipulates processes',
            'apis': [api['name'] for api in results['api_categories']['process']]
        })

    # Registry operations
    if results['api_categories'].get('registry'):
        indicators.append({
            'type': 'registry_operations',
            'description': 'Modifies registry',
            'apis': [api['name'] for api in results['api_categories']['registry']]
        })

    # Cryptographic operations
    if results['api_categories'].get('crypto'):
        indicators.append({
            'type': 'cryptographic_operations',
            'description': 'Uses cryptographic functions',
            'apis': [api['name'] for api in results['api_categories']['crypto']]
        })

    # Memory manipulation
    if results['api_categories'].get('memory'):
        indicators.append({
            'type': 'memory_manipulation',
            'description': 'Manipulates memory',
            'apis': [api['name'] for api in results['api_categories']['memory']]
        })

    # GUI operations
    if results['api_categories'].get('gui'):
        indicators.append({
            'type': 'gui_operations',
            'description': 'Creates GUI elements',
            'apis': [api['name'] for api in results['api_categories']['gui']]
        })

    return indicators

def main():
    """Main script entry point"""
    try:
        analyze_imports()
    except Exception as e:
        print(f"Script error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
