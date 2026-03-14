rule trojan_process_injection_apis : trojan injection
{
    meta:
        category = "trojan"
        family = "Injection Trojan"
        severity = "high"
        description = "Process injection API cluster detected"
    strings:
        $a = "WriteProcessMemory" ascii wide
        $b = "CreateRemoteThread" ascii wide
        $c = "OpenProcess" ascii wide
        $d = "VirtualAllocEx" ascii wide
    condition:
        3 of ($a,$b,$c,$d)
}

rule trojan_keylogger_apis : trojan spyware
{
    meta:
        category = "spyware"
        family = "Keylogger Trojan"
        severity = "high"
        description = "Keylogging API cluster detected"
    strings:
        $a = "GetAsyncKeyState" ascii wide
        $b = "SetWindowsHookEx" ascii wide
        $c = "GetForegroundWindow" ascii wide
        $d = "GetWindowText" ascii wide
    condition:
        3 of ($a,$b,$c,$d)
}

rule trojan_downloader_apis : trojan downloader
{
    meta:
        category = "downloader"
        family = "Downloader Trojan"
        severity = "high"
        description = "Downloader API cluster detected"
    strings:
        $a = "URLDownloadToFileA" ascii wide
        $b = "URLDownloadToFileW" ascii wide
        $c = "InternetOpenUrlA" ascii wide
        $d = "WinHttpSendRequest" ascii wide
    condition:
        2 of ($a,$b,$c,$d)
}

rule trojan_c2_beacon_strings : trojan backdoor
{
    meta:
        category = "backdoor"
        family = "Beaconing Trojan"
        severity = "medium"
        description = "Beaconing or command channel strings detected"
    strings:
        $a = "POST /gate.php" ascii nocase
        $b = "cmd=" ascii nocase
        $c = "bot_id=" ascii nocase
        $d = ".onion" ascii nocase
    condition:
        2 of ($a,$b,$c,$d)
}

rule trojan_startup_persistence : trojan persistence
{
    meta:
        category = "trojan"
        family = "Persistence Trojan"
        severity = "medium"
        description = "Startup folder persistence path detected"
    strings:
        $a = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase
        $b = "schtasks /create" ascii nocase
        $c = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
    condition:
        any of ($a,$b,$c)
}
