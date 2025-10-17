"""
Windows API to Python mappings database.

Contains comprehensive mappings of common Windows APIs to their Python
equivalents, including examples, required imports, and usage notes.
"""

from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class APIMapping:
    """Represents a Windows API to Python translation mapping."""

    windows_api: str
    python_equivalent: str
    example: str
    imports: List[str]
    notes: str
    category: str


# Comprehensive Windows API → Python mapping database
API_MAPPINGS: Dict[str, APIMapping] = {
    # File I/O APIs
    "CreateFileW": APIMapping(
        windows_api="CreateFileW",
        python_equivalent="open(path, mode)",
        example="# Windows: CreateFileW(path, GENERIC_READ, ...)\nwith open(filepath, 'rb') as f:\n    data = f.read()",
        imports=["pathlib"],
        notes="Use pathlib.Path for cross-platform paths. 'rb' for binary, 'r' for text",
        category="file_io",
    ),
    "CreateFileA": APIMapping(
        windows_api="CreateFileA",
        python_equivalent="open(path, mode)",
        example="# Windows: CreateFileA(path, GENERIC_WRITE, ...)\nwith open(filepath, 'wb') as f:\n    f.write(data)",
        imports=["pathlib"],
        notes="ASCII version of CreateFile. Same mapping as CreateFileW",
        category="file_io",
    ),
    "ReadFile": APIMapping(
        windows_api="ReadFile",
        python_equivalent="file.read()",
        example="# Windows: ReadFile(hFile, buffer, bytesToRead, &bytesRead, NULL)\ndata = f.read(size)  # Returns bytes",
        imports=[],
        notes="Returns bytes object. Use .decode() for text",
        category="file_io",
    ),
    "WriteFile": APIMapping(
        windows_api="WriteFile",
        python_equivalent="file.write()",
        example="# Windows: WriteFile(hFile, buffer, bytesToWrite, &bytesWritten, NULL)\nbytes_written = f.write(data)",
        imports=[],
        notes="Accepts bytes or str. Returns number of bytes written",
        category="file_io",
    ),
    "CloseHandle": APIMapping(
        windows_api="CloseHandle",
        python_equivalent="file.close() or context manager",
        example="# Windows: CloseHandle(hFile)\nf.close()  # Or use 'with' statement for automatic cleanup",
        imports=[],
        notes="Prefer 'with' statement for automatic resource management",
        category="file_io",
    ),
    "DeleteFileW": APIMapping(
        windows_api="DeleteFileW",
        python_equivalent="os.remove(path)",
        example="# Windows: DeleteFileW(path)\nos.remove(filepath)",
        imports=["os"],
        notes="Raises FileNotFoundError if file doesn't exist",
        category="file_io",
    ),
    "GetFileSize": APIMapping(
        windows_api="GetFileSize",
        python_equivalent="os.path.getsize(path)",
        example="# Windows: GetFileSize(hFile, NULL)\nfile_size = os.path.getsize(filepath)",
        imports=["os"],
        notes="Or use Path(filepath).stat().st_size",
        category="file_io",
    ),
    # HTTP/Network APIs
    "WinHttpOpen": APIMapping(
        windows_api="WinHttpOpen",
        python_equivalent="requests.Session()",
        example="# Windows: WinHttpOpen(userAgent, ...)\nsession = requests.Session()\nsession.headers['User-Agent'] = user_agent",
        imports=["requests"],
        notes="requests library handles HTTP/HTTPS automatically",
        category="network",
    ),
    "WinHttpConnect": APIMapping(
        windows_api="WinHttpConnect",
        python_equivalent="session.get(url) or session.post(url)",
        example="# Windows: WinHttpConnect(hSession, server, port, 0)\nresponse = session.get(f'https://{server}:{port}/path')",
        imports=["requests"],
        notes="Connection is implicit in requests library",
        category="network",
    ),
    "WinHttpOpenRequest": APIMapping(
        windows_api="WinHttpOpenRequest",
        python_equivalent="session.request(method, url)",
        example="# Windows: WinHttpOpenRequest(hConnect, 'GET', path, ...)\nresponse = session.get(url, headers=headers)",
        imports=["requests"],
        notes="Supports GET, POST, PUT, DELETE methods",
        category="network",
    ),
    "WinHttpSendRequest": APIMapping(
        windows_api="WinHttpSendRequest",
        python_equivalent="session.request() executes automatically",
        example="# Windows: WinHttpSendRequest(hRequest, headers, ...)\nresponse = session.post(url, headers=headers, data=data)",
        imports=["requests"],
        notes="requests combines send and receive into single call",
        category="network",
    ),
    "WinHttpReceiveResponse": APIMapping(
        windows_api="WinHttpReceiveResponse",
        python_equivalent="response object",
        example="# Windows: WinHttpReceiveResponse(hRequest, NULL)\n# Response is already available after session.get/post",
        imports=["requests"],
        notes="Access response.status_code, response.text, response.content",
        category="network",
    ),
    "WinHttpReadData": APIMapping(
        windows_api="WinHttpReadData",
        python_equivalent="response.content or response.text",
        example="# Windows: WinHttpReadData(hRequest, buffer, size, &bytesRead)\ndata = response.content  # bytes\ntext = response.text     # str",
        imports=["requests"],
        notes="Use .content for binary, .text for decoded string",
        category="network",
    ),
    "InternetOpenW": APIMapping(
        windows_api="InternetOpenW",
        python_equivalent="requests.Session()",
        example="# Windows: InternetOpen(agent, INTERNET_OPEN_TYPE_DIRECT, ...)\nsession = requests.Session()\nsession.headers.update({'User-Agent': agent})",
        imports=["requests"],
        notes="WinINet alternative to WinHTTP, same Python mapping",
        category="network",
    ),
    "InternetOpenUrlW": APIMapping(
        windows_api="InternetOpenUrlW",
        python_equivalent="requests.get(url)",
        example="# Windows: InternetOpenUrl(hInternet, url, ...)\nresponse = requests.get(url)",
        imports=["requests"],
        notes="Simple URL fetch, use session for multiple requests",
        category="network",
    ),
    # Registry APIs
    "RegOpenKeyExW": APIMapping(
        windows_api="RegOpenKeyExW",
        python_equivalent="winreg.OpenKey()",
        example="# Windows: RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, ...)\nimport winreg\nkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ)",
        imports=["winreg"],
        notes="winreg is standard library on Windows",
        category="registry",
    ),
    "RegQueryValueExW": APIMapping(
        windows_api="RegQueryValueExW",
        python_equivalent="winreg.QueryValueEx()",
        example="# Windows: RegQueryValueEx(hKey, valueName, ...)\nvalue, type = winreg.QueryValueEx(key, value_name)",
        imports=["winreg"],
        notes="Returns (value, type) tuple. Type is REG_SZ, REG_DWORD, etc.",
        category="registry",
    ),
    "RegSetValueExW": APIMapping(
        windows_api="RegSetValueExW",
        python_equivalent="winreg.SetValueEx()",
        example="# Windows: RegSetValueEx(hKey, valueName, 0, type, data, size)\nwinreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value)",
        imports=["winreg"],
        notes="Type: REG_SZ (string), REG_DWORD (int), REG_BINARY (bytes)",
        category="registry",
    ),
    "RegCloseKey": APIMapping(
        windows_api="RegCloseKey",
        python_equivalent="winreg.CloseKey() or context manager",
        example="# Windows: RegCloseKey(hKey)\nwinreg.CloseKey(key)  # Or use context manager",
        imports=["winreg"],
        notes="Prefer context manager for automatic cleanup",
        category="registry",
    ),
    # Process/Thread APIs
    "CreateProcessW": APIMapping(
        windows_api="CreateProcessW",
        python_equivalent="subprocess.Popen()",
        example="# Windows: CreateProcess(NULL, cmdline, ...)\nimport subprocess\nproc = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE)",
        imports=["subprocess"],
        notes="Use subprocess module for process management",
        category="process",
    ),
    "CreateThread": APIMapping(
        windows_api="CreateThread",
        python_equivalent="threading.Thread()",
        example="# Windows: CreateThread(NULL, 0, threadFunc, param, ...)\nimport threading\nthread = threading.Thread(target=thread_func, args=(param,))\nthread.start()",
        imports=["threading"],
        notes="Python handles thread creation and synchronization",
        category="process",
    ),
    "TerminateProcess": APIMapping(
        windows_api="TerminateProcess",
        python_equivalent="process.terminate() or process.kill()",
        example="# Windows: TerminateProcess(hProcess, exitCode)\nproc.terminate()  # Graceful\nproc.kill()       # Forceful",
        imports=["subprocess"],
        notes="terminate() sends SIGTERM, kill() sends SIGKILL",
        category="process",
    ),
    "WaitForSingleObject": APIMapping(
        windows_api="WaitForSingleObject",
        python_equivalent="thread.join() or process.wait()",
        example="# Windows: WaitForSingleObject(hObject, INFINITE)\nthread.join()      # Wait for thread\nproc.wait()        # Wait for process",
        imports=["threading", "subprocess"],
        notes="Blocks until thread/process completes",
        category="process",
    ),
    # Memory APIs
    "VirtualAlloc": APIMapping(
        windows_api="VirtualAlloc",
        python_equivalent="bytearray() or ctypes.create_string_buffer()",
        example="# Windows: VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE)\nbuffer = bytearray(size)  # Simple case\n# Or for C interop:\nimport ctypes\nbuffer = ctypes.create_string_buffer(size)",
        imports=["ctypes"],
        notes="Python manages memory automatically. Use ctypes only for C interop",
        category="memory",
    ),
    "VirtualFree": APIMapping(
        windows_api="VirtualFree",
        python_equivalent="del buffer or automatic garbage collection",
        example="# Windows: VirtualFree(buffer, 0, MEM_RELEASE)\ndel buffer  # Python handles deallocation automatically",
        imports=[],
        notes="Python garbage collector frees memory automatically",
        category="memory",
    ),
    "HeapAlloc": APIMapping(
        windows_api="HeapAlloc",
        python_equivalent="bytes() or bytearray()",
        example="# Windows: HeapAlloc(hHeap, 0, size)\nbuffer = bytearray(size)",
        imports=[],
        notes="Use bytes for immutable, bytearray for mutable buffers",
        category="memory",
    ),
    "memcpy": APIMapping(
        windows_api="memcpy",
        python_equivalent="buffer[offset:offset+size] = data",
        example="# Windows: memcpy(dest, src, size)\ndest_buffer[offset:offset+len(data)] = data",
        imports=[],
        notes="Python slice assignment is safe and Pythonic",
        category="memory",
    ),
    # Cryptography APIs
    "CryptAcquireContextW": APIMapping(
        windows_api="CryptAcquireContextW",
        python_equivalent="from cryptography import hazmat",
        example="# Windows: CryptAcquireContext(&hProv, ...)\n# Use cryptography library instead\nfrom cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.backends import default_backend",
        imports=["cryptography"],
        notes="cryptography library is cross-platform and secure",
        category="crypto",
    ),
    "CryptCreateHash": APIMapping(
        windows_api="CryptCreateHash",
        python_equivalent="hashlib or cryptography",
        example="# Windows: CryptCreateHash(hProv, CALG_SHA256, ...)\nimport hashlib\nhasher = hashlib.sha256()\n# Or:\nfrom cryptography.hazmat.primitives import hashes\nhasher = hashes.Hash(hashes.SHA256())",
        imports=["hashlib", "cryptography"],
        notes="hashlib for simple hashing, cryptography for advanced crypto",
        category="crypto",
    ),
    "CryptHashData": APIMapping(
        windows_api="CryptHashData",
        python_equivalent="hasher.update(data)",
        example="# Windows: CryptHashData(hHash, data, dataLen, 0)\nhasher.update(data)",
        imports=["hashlib"],
        notes="Can call update() multiple times for streaming",
        category="crypto",
    ),
    "CryptGetHashParam": APIMapping(
        windows_api="CryptGetHashParam",
        python_equivalent="hasher.digest() or hasher.hexdigest()",
        example="# Windows: CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)\ndigest = hasher.digest()     # bytes\nhex_digest = hasher.hexdigest()  # hex string",
        imports=["hashlib"],
        notes="digest() returns bytes, hexdigest() returns hex string",
        category="crypto",
    ),
}


def get_api_mapping(api_name: str) -> Optional[APIMapping]:
    """
    Get the Python mapping for a Windows API.

    Args:
        api_name: Name of Windows API (e.g., 'CreateFileW')

    Returns:
        APIMapping object if found, None otherwise
    """
    return API_MAPPINGS.get(api_name)


def get_mappings_by_category(category: str) -> Dict[str, APIMapping]:
    """
    Get all API mappings in a specific category.

    Args:
        category: Category name (file_io, network, registry, process, memory, crypto)

    Returns:
        Dictionary of API mappings in that category
    """
    return {name: mapping for name, mapping in API_MAPPINGS.items() if mapping.category == category}


def get_all_categories() -> List[str]:
    """Get list of all API categories."""
    return sorted(set(mapping.category for mapping in API_MAPPINGS.values()))
