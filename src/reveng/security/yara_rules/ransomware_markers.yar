rule ransomware_shadowcopy_delete : ransomware destructive
{
    meta:
        category = "ransomware"
        family = "Generic Ransomware"
        severity = "critical"
        description = "Shadow copy deletion command detected"
    strings:
        $a = "vssadmin delete shadows /all /quiet" ascii nocase
        $b = "wmic shadowcopy delete" ascii nocase
    condition:
        any of ($a,$b)
}

rule ransomware_note_strings : ransomware extortion
{
    meta:
        category = "ransomware"
        family = "Generic Ransomware"
        severity = "critical"
        description = "Ransom note language detected"
    strings:
        $a = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $b = "HOW_TO_RESTORE_FILES" ascii wide nocase
        $c = "README_DECRYPT" ascii wide nocase
    condition:
        any of ($a,$b,$c)
}

rule ransomware_extension_markers : ransomware filesystem
{
    meta:
        category = "ransomware"
        family = "Generic Ransomware"
        severity = "high"
        description = "Known ransomware extension markers detected"
    strings:
        $a = ".lockbit" ascii wide nocase
        $b = ".encrypted" ascii wide nocase
        $c = ".crypt" ascii wide nocase
        $d = ".ryk" ascii wide nocase
    condition:
        any of ($a,$b,$c,$d)
}

rule ransomware_encryption_api_cluster : ransomware crypto
{
    meta:
        category = "ransomware"
        family = "Generic Ransomware"
        severity = "high"
        description = "Encryption API cluster found in binary"
    strings:
        $a = "CryptEncrypt" ascii wide
        $b = "BCryptEncrypt" ascii wide
        $c = "CryptGenRandom" ascii wide
        $d = "RSA PUBLIC KEY" ascii wide nocase
    condition:
        2 of ($a,$b,$c,$d)
}
