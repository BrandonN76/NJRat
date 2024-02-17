## Malware Analysis (NJRAT Family - Hacked Botnet)

### Static Analysis

**VirusTotal Results:**
<img src="https://i.imgur.com/YVNOZIz.png">
- Hashes:
  - MD5: 871722db5b9b702357b675e48e491193
  - SHA-1: ec5cf5b57414fa8253a842bb06fc6822b85e399d
  - SHA-256: 6f3d6bf9ee09bd4cd6af117cca33965c33b99a7380d8de14450b7d4a3cd499b8
- Presented Filename: 6f3d6bf9ee09bd4cd6af117cca33965c33b99a7380d8de14450b7d4a3cd499b8.exe
- Filesize: 1568256 bytes
- File Type: PE32
- DLLs:
  - ntdll.dll
  - wow64.dll
  - wow64win.dll
  - wow64cpu.dll
  - kernel32.dll
  - user32.dll
  - mscoree.dll

**Dynamic Analysis:**

**Processes:**
- 6f3d6bf9ee09bd4cd6af117cca33965c33b99a7380d8de14450b7d4a3cd499b8.exe
- ESET Service.exe
- netsh.exe
- taskkill.exe

**DNS:**
- tcp.eu.ngrok.io (3.67.62.142:11024)

**IP addresses:**
- 3.67.62.142
- 3.67.112.102
- 224.0.0.252

**Registry Keys Modified:**
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap
- HKEY_CURRENT_USER
- HKEY_CLASSES_ROOT\Local Settings\MuiCache\15A\52C64B7E
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

**Tools used:**
- Any.Run

**Overview:**
Based on the analysis, this file is suspicious. The file ESET Service.exe was flagged by Suricata as NJRAT, which increases the file's suspicion. When the file's hash is searched for in VirusTotal, it is flagged 60 times. The file creates a file called ESET Service.exe, which uses netsh.exe to modify the firewall rules and then kills the task with taskkill.exe. The file appears to use the registry keys to maintain persistence by using HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run to run ESET Service.exe at logon. Based on the analysis, it seems like the malware is gathering internet and system information or editing it.
