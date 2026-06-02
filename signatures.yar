import "math"

rule SuspiciousAPI_VirtualAlloc {
    meta:
        description = "Detects usage of VirtualAlloc for executable memory allocation"
    strings:
        $s1 = "VirtualAlloc" nocase
        $s2 = "MEM_COMMIT"
        $s3 = "PAGE_EXECUTE_READWRITE"
    condition:
        any of them
}

rule SuspiciousAPI_CreateRemoteThread {
    meta:
        description = "Detects potential process injection using CreateRemoteThread"
    strings:
        $s1 = "CreateRemoteThread" nocase
        $s2 = "WriteProcessMemory" nocase
    condition:
        all of them
}

rule CommonEncoderStub_XOR {
    meta:
        description = "Detects simple XOR encoding loops"
    strings:
        // xor byte [reg], reg
        $xor_loop = { 30 ?? ?? 4? }
    condition:
        $xor_loop
}

rule HighEntropySection {
    meta:
        description = "Detects high entropy sections which may indicate encryption"
    condition:
        filesize < 5000000 and math.entropy(0, filesize) > 7.5
}

rule StringIndicator_CmdExe {
    meta:
        description = "Detects strings related to shell command execution"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "/c start" nocase
    condition:
        any of them
}

rule StringIndicator_PowerShell {
    meta:
        description = "Detects strings related to PowerShell execution"
    strings:
        $s1 = "powershell" nocase
        $s2 = "-ExecutionPolicy Bypass" nocase
        $s3 = "EncodedCommand" nocase
    condition:
        any of them
}

rule SuspiciousImport_NetScan {
    meta:
        description = "Detects imports used in network scanning tools"
    strings:
        $s1 = "socket" nocase
        $s2 = "ipaddress" nocase
        $s3 = "subprocess" nocase
        $s4 = "ping" nocase
    condition:
        3 of them
}

rule Shellcode_Common_Prologue {
    meta:
        description = "Detects common shellcode prologues (e.g., stack alignment)"
    strings:
        $prologue = { 55 48 89 E5 48 81 EC }
    condition:
        $prologue
}

rule Suspicious_Sleep_Loop {
    meta:
        description = "Detects potential anti-sandbox sleep loops"
    strings:
        $s1 = "Sleep" nocase
        $s2 = "GetTickCount" nocase
    condition:
        all of them
}

rule Debugger_Detection_IsDebuggerPresent {
    meta:
        description = "Detects usage of IsDebuggerPresent API"
    strings:
        $s1 = "IsDebuggerPresent" nocase
    condition:
        $s1
}

rule Suspicious_Process_Hollowing {
    meta:
        description = "Detects APIs used for process hollowing"
    strings:
        $s1 = "NtUnmapViewOfSection" nocase
        $s2 = "SetThreadContext" nocase
        $s3 = "ResumeThread" nocase
    condition:
        all of them
}

rule Reflective_DLL_Loader {
    meta:
        description = "Detects common strings in reflective DLL loaders"
    strings:
        $s1 = "ReflectiveLoader"
        $s2 = "GetProcAddress"
        $s3 = "LoadLibraryA"
    condition:
        all of them
}

rule AntiAnalysis_VM_Detection {
    meta:
        description = "Detects strings associated with VM detection (VMware, VirtualBox)"
    strings:
        $v1 = "VMware" nocase
        $v2 = "VBOX" nocase
        $v3 = "QEMU" nocase
    condition:
        any of them
}

rule Suspicious_WMI_Query {
    meta:
        description = "Detects suspicious WMI queries for persistence or reconnaissance"
    strings:
        $s1 = "SELECT * FROM Win32_Process" nocase
        $s2 = "WbemScripting.SWbemLocator" nocase
    condition:
        any of them
}

rule Payload_Persistence_Registry {
    meta:
        description = "Detects registry keys used for persistence"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
    condition:
        any of them
}

rule Obfuscated_Javascript_Indicator {
    meta:
        description = "Detects indicators of obfuscated JS (e.g., in HTML payloads)"
    strings:
        $s1 = "eval(unescape("
        $s2 = "String.fromCharCode("
    condition:
        any of them
}

rule High_Count_of_Nops {
    meta:
        description = "Detects long sequences of NOP instructions (NOP sleds)"
    strings:
        $nops = { 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nops
}
