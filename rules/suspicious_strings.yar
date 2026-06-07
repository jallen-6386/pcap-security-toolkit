/*
  PCAP Security Toolkit — Suspicious String Indicators
  Scans carved files and extracted payloads for strings commonly
  associated with C2 frameworks, credential theft, and staged loaders.

  Extend this file or add new .yar files to the rules/ directory.
  Pass the directory with: --yara-rules ./rules

  Note: YARA tags go in the rule header (rule Name : tag1 tag2), not in a
  "tags:" section.
*/

rule CobaltStrike_Beacon_Strings : critical backdoor rat
{
    meta:
        description = "Strings commonly found in Cobalt Strike Beacon payloads"
        severity    = "CRITICAL"
        mitre       = "T1059.003"
        reference   = "https://attack.mitre.org/software/S0154/"
    strings:
        $s1 = "beacon.dll" nocase
        $s2 = "ReflectiveLoader" ascii
        $s3 = "cobaltstrike" nocase wide ascii
        $s4 = "sleep_mask" ascii
        $s5 = { 68 45 78 69 74 50 72 6F 63 65 73 73 }  // push "ExitProcess"
    condition:
        2 of them
}

rule Meterpreter_Strings : critical rat backdoor
{
    meta:
        description = "Strings associated with Metasploit Meterpreter payloads"
        severity    = "CRITICAL"
        mitre       = "T1059.003"
    strings:
        $s1 = "metsrv.dll" nocase
        $s2 = "meterpreter" nocase wide ascii
        $s3 = "ReflectiveDll" ascii
        $s4 = "stdapi_" ascii
        $s5 = "core_loadlib" ascii
    condition:
        2 of them
}

rule Mimikatz_Credential_Theft : critical credential
{
    meta:
        description = "Strings associated with Mimikatz credential dumping"
        severity    = "CRITICAL"
        mitre       = "T1003.001"
        reference   = "https://attack.mitre.org/software/S0002/"
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

rule PowerShell_Encoded_Dropper : high dropper loader
{
    meta:
        description = "PowerShell with base64-encoded payload — common dropper pattern"
        severity    = "HIGH"
        mitre       = "T1059.001"
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

rule Suspicious_PE_In_Payload : high dropper
{
    meta:
        description = "Windows PE executable embedded in network payload"
        severity    = "HIGH"
        mitre       = "T1105"
    strings:
        $mz = { 4D 5A }           // MZ header
        $pe = { 50 45 00 00 }     // PE signature
    condition:
        $mz at 0 and $pe
}

rule Reverse_Shell_Strings : high backdoor
{
    meta:
        description = "Common reverse shell command patterns"
        severity    = "HIGH"
        mitre       = "T1059"
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

rule Credential_Keywords_In_Payload : medium credential
{
    meta:
        description = "Credential-related keywords in extracted HTTP or stream payload"
        severity    = "MEDIUM"
        mitre       = "T1552"
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

rule ELF_Executable_In_Payload : high dropper
{
    meta:
        description = "ELF binary transferred in network payload (Linux/Unix executable)"
        severity    = "HIGH"
        mitre       = "T1105"
    strings:
        $elf = { 7F 45 4C 46 }    // ELF magic
    condition:
        $elf at 0
}

rule China_Chopper_Webshell : critical webshell
{
    meta:
        description = "China Chopper webshell one-liner (PHP/ASP/JSP variants)"
        severity    = "CRITICAL"
        mitre       = "T1505.003"
        reference   = "https://attack.mitre.org/software/S0020/"
    strings:
        $php = "<?php @eval($_POST[" ascii nocase
        $asp = "<%eval request(" ascii nocase
        $jsp = "Runtime.getRuntime().exec(request.getParameter(" ascii
    condition:
        any of them
}

rule Webshell_PHP_Indicators : high webshell
{
    meta:
        description = "Generic PHP webshell code-execution patterns on user input"
        severity    = "HIGH"
        mitre       = "T1505.003"
    strings:
        $e1 = "eval($_POST" ascii nocase
        $e2 = "eval($_GET" ascii nocase
        $e3 = "eval($_REQUEST" ascii nocase
        $e4 = "assert($_POST" ascii nocase
        $e5 = "system($_GET" ascii nocase
        $e6 = "shell_exec($_" ascii nocase
        $e7 = "passthru($_" ascii nocase
        $e8 = "base64_decode($_POST" ascii nocase
    condition:
        any of them
}

rule Webshell_ASP_JSP_Indicators : high webshell
{
    meta:
        description = "ASP/JSP webshell executing attacker-supplied input"
        severity    = "HIGH"
        mitre       = "T1505.003"
    strings:
        $jsp1 = "getRuntime().exec(" ascii
        $jsp2 = "request.getParameter(" ascii
        $asp1 = "Server.CreateObject(\"WScript.Shell\")" ascii nocase
        $asp2 = ".Run(" ascii
    condition:
        ($jsp1 and $jsp2) or ($asp1 and $asp2)
}

rule LOLBin_Download_Cradle : high loader lolbin
{
    meta:
        description = "Living-off-the-land download cradle (certutil/bitsadmin/mshta/regsvr32)"
        severity    = "HIGH"
        mitre       = "T1105"
    strings:
        $c1 = "certutil -urlcache" ascii nocase
        $c2 = "certutil.exe -urlcache" ascii nocase
        $c3 = "certutil -decode" ascii nocase
        $b1 = "bitsadmin /transfer" ascii nocase
        $m1 = "mshta http" ascii nocase
        $m2 = "mshta vbscript:" ascii nocase
        $r1 = "regsvr32 /s /n /u /i:http" ascii nocase
        $r2 = "regsvr32.exe /s /u /i:http" ascii nocase
    condition:
        any of them
}

rule PowerShell_Download_Cradle : high loader
{
    meta:
        description = "PowerShell remote download cradle"
        severity    = "HIGH"
        mitre       = "T1059.001"
    strings:
        $w1 = "Net.WebClient" ascii nocase
        $w2 = "DownloadString(" ascii nocase
        $w3 = "DownloadFile(" ascii nocase
        $w4 = "DownloadData(" ascii nocase
        $w5 = "Invoke-WebRequest" ascii nocase
        $w6 = "Start-BitsTransfer" ascii nocase
    condition:
        ($w1 and 1 of ($w2, $w3, $w4)) or $w5 or $w6
}

rule Base64_Encoded_PE : high loader obfuscation
{
    meta:
        description = "Base64-encoded Windows PE (MZ) header — staged/obfuscated payload"
        severity    = "HIGH"
        mitre       = "T1027"
    strings:
        $b1 = "TVqQAAMAAAAEAAAA" ascii   // base64 of the standard PE DOS header
        $b2 = "TVpQAAIAAAAEAA" ascii
        $b3 = "TVqAAAAAAAAA" ascii
    condition:
        any of them
}
