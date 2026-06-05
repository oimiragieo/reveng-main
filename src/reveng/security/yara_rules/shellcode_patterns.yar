rule shellcode_nop_sled : shellcode suspicious
{
    meta:
        category = "shellcode"
        severity = "high"
        description = "Large NOP sled commonly used in shellcode staging"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule shellcode_breakpoint_sled : shellcode suspicious
{
    meta:
        category = "shellcode"
        severity = "medium"
        description = "INT3 sled often seen in shellcode or unpacking stubs"
    strings:
        $int3 = { CC CC CC CC CC CC }
    condition:
        $int3
}

rule shellcode_getpc_decoder_stub : shellcode suspicious
{
    meta:
        category = "shellcode"
        severity = "high"
        description = "GetPC decoder stub pattern found"
    strings:
        $decoder = { FC E8 [4-32] 60 89 E5 }
    condition:
        $decoder
}

rule shellcode_api_resolver_strings : shellcode loader
{
    meta:
        category = "loader"
        severity = "high"
        description = "Shellcode-style API resolver strings present"
    strings:
        $a1 = "LoadLibraryA" ascii wide
        $a2 = "GetProcAddress" ascii wide
        $a3 = "VirtualAlloc" ascii wide
    condition:
        2 of ($a*)
}

rule shellcode_command_execution_strings : shellcode suspicious
{
    meta:
        category = "shellcode"
        severity = "medium"
        description = "Command execution strings embedded alongside loader APIs"
    strings:
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "calc.exe" ascii wide nocase
        $cmd3 = "WinExec" ascii wide
    condition:
        2 of ($cmd*)
}
