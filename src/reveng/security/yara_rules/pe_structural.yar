rule pe_mz_header : pe structural
{
    meta:
        category = "structure"
        severity = "low"
        description = "Portable executable MZ header detected"
    condition:
        uint16(0) == 0x5A4D
}

rule pe_dos_stub_string : pe structural
{
    meta:
        category = "structure"
        severity = "low"
        description = "Portable executable DOS stub string detected"
    strings:
        $stub = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) == 0x5A4D and $stub
}

rule pe_rich_header_marker : pe structural
{
    meta:
        category = "structure"
        severity = "low"
        description = "Microsoft Rich header marker present"
    strings:
        $rich = "Rich" ascii
    condition:
        uint16(0) == 0x5A4D and $rich
}

rule pe_embedded_pdb_path : pe structural
{
    meta:
        category = "structure"
        severity = "medium"
        description = "Embedded PDB or debug path string present in PE"
    strings:
        $pdb = /[A-Za-z]:\\[^\x00]{3,}\.pdb/i ascii wide
    condition:
        uint16(0) == 0x5A4D and $pdb
}

rule pe_powershell_launcher_string : pe suspicious
{
    meta:
        category = "loader"
        severity = "medium"
        description = "PowerShell launcher string embedded in PE"
    strings:
        $ps = "powershell.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $ps
}
