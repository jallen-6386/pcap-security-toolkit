/*
  PCAP Security Toolkit — Suspicious String Indicators
  Scans carved files and extracted payloads for strings commonly
  associated with C2 frameworks, credential theft, and staged loaders.

  Extend this file or add new .yar files to the rules/ directory.
  Pass the directory with: --yara-rules ./rules
*/

rule CobaltStrike_Beacon_Strings
{
    meta:
        description = "Strings commonly found in Cobalt Strike Beacon payloads"
        severity    = "CRITICAL"
        mitre       = "T1059.003"
        reference   = "https://attack.mitre.org/software/S0154/"
    tags: critical backdoor rat
    strings:
        $s1 = "beacon.dll" nocase
        $s2 = "ReflectiveLoader" ascii
        $s3 = "cobaltstrike" nocase wide ascii
        $s4 = "sleep_mask" ascii
        $s5 = { 68 45 78 69 74 50 72 6F 63 65 73 73 }  // push "ExitProcess"
    condition:
        2 of them
}

rule Meterpreter_Strings
{
    meta:
        description = "Strings associated with Metasploit Meterpreter payloads"
        severity    = "CRITICAL"
        mitre       = "T1059.003"
    tags: critical rat backdoor
    strings:
        $s1 = "metsrv.dll" nocase
        $s2 = "meterpreter" nocase wide ascii
        $s3 = "ReflectiveDll" ascii
        $s4 = "stdapi_" ascii
        $s5 = "core_loadlib" ascii
    condition:
        2 of them
}

rule Mimikatz_Credential_Theft
{
    meta:
        description = "Strings associated with Mimikatz credential dumping"
        severity    = "CRITICAL"
        mitre       = "T1003.001"
        reference   = "https://attack.mitre.org/software/S0002/"
    tags: critical credential
    strings:
        $s1 = "mimikatz" nocase wide ascii
        $s2 = "sekurlsa::" ascii
        $s3 = "lsadump::" ascii
        $s4 = "privilege::debug" nocase ascii
        $s5 = "SamSs" wide
        $s6 = "kerberos::" ascii
    condition:
        2 of them
}

rule PowerShell_Encoded_Dropper
{
    meta:
        description = "PowerShell with base64-encoded payload — common dropper pattern"
        severity    = "HIGH"
        mitre       = "T1059.001"
    tags: high dropper loader
    strings:
        $ps1 = "powershell" nocase ascii wide
        $ps2 = "-EncodedCommand" nocase ascii
        $ps3 = "-enc " nocase ascii
        $ps4 = "FromBase64String" ascii
        $ps5 = "IEX" ascii
        $ps6 = "Invoke-Expression" ascii nocase
    condition:
        $ps1 and (2 of ($ps2, $ps3, $ps4, $ps5, $ps6))
}

rule Suspicious_PE_In_Payload
{
    meta:
        description = "Windows PE executable embedded in network payload"
        severity    = "HIGH"
        mitre       = "T1105"
    tags: high dropper
    strings:
        $mz = { 4D 5A }           // MZ header
        $pe = { 50 45 00 00 }     // PE signature
    condition:
        $mz at 0 and $pe
}

rule Reverse_Shell_Strings
{
    meta:
        description = "Common reverse shell command patterns"
        severity    = "HIGH"
        mitre       = "T1059"
    tags: high backdoor
    strings:
        $s1 = "bash -i >& /dev/tcp/" ascii
        $s2 = "/bin/sh -i" ascii
        $s3 = "nc -e /bin/bash" ascii nocase
        $s4 = "nc -e /bin/sh" ascii nocase
        $s5 = "python -c 'import socket,subprocess" ascii
        $s6 = "ncat --exec" ascii nocase
    condition:
        any of them
}

rule Credential_Keywords_In_Payload
{
    meta:
        description = "Credential-related keywords in extracted HTTP or stream payload"
        severity    = "MEDIUM"
        mitre       = "T1552"
    tags: medium credential
    strings:
        $s1 = "password=" nocase ascii
        $s2 = "passwd=" nocase ascii
        $s3 = "Authorization: Basic" ascii
        $s4 = "api_key=" nocase ascii
        $s5 = "access_token=" nocase ascii
        $s6 = "private_key" nocase ascii
        $s7 = "BEGIN RSA PRIVATE KEY" ascii
        $s8 = "BEGIN OPENSSH PRIVATE KEY" ascii
    condition:
        2 of them
}

rule ELF_Executable_In_Payload
{
    meta:
        description = "ELF binary transferred in network payload (Linux/Unix executable)"
        severity    = "HIGH"
        mitre       = "T1105"
    tags: high dropper
    strings:
        $elf = { 7F 45 4C 46 }    // ELF magic
    condition:
        $elf at 0
}
