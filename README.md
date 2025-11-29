# FileSentinel
FILE SENTINEL Advanced Hybrid Safety Analysis Tool for Windows Version 2.0
FileSentinel is an independent desktop tool meant to serve power-users, system administrators, or those interested in computer security. It offers multi-level safety analysis for files with .exe or .dll extensions and can help determine if such files can be classified into malicious ones or marked as harmless errors showing false positives. While traditional virus scanners can only alert about malicious files, “FileSentinel offers an innovative solution based on the ’Semantic Analysis Engine.’ It tries to differentiate between malicious files (Trojans, Ransomware, Stealers) and harmless applications commonly misidentified by AV vendors (Keygens, GameTrainers, Admin Tools). It’s built using:”

Online Analysis: Utilizes VirusTotal API for global consensus.

Local Analysis: It employs an internal heuristic engine for analyzing the structure of files off-line.

Hybrid Analysis Engine It integrates cloud intelligence with local static analysis to offer a holistic risk analysis. If there’s no internet connection or API key, it automatically reverts to using its local engine for analysis. Semantic Intelligence FileSentinel checks names of detections instead of merely considering the numbers. It breaks threats into:

Benign Tools: HackTools, Keygens, Patchers

- PUA: Potentially Unwanted Applications (

Malicious:Trojans,Worms,Ransomware (High Danger) This ensures that users understand when a file has been detected only because it’s a crack or if it actually contains malicious code. Local Heuristics (Offline Mode) Even if there’s no internet connection involved, FileSentinel analyzes how the PE (Portable Executable) structure of the given file looks like:

Import Analysis: Looks for malicious API calls (for example, memory injection or keylog hooks).

Entropy Check: It calculates entropy for sections to identify if code is packed or if it’s just been encrypted to conceal malware code.

Digital Signature Verification: It verifies if the files contain any digital signature of trusted vendors or not. Installer Detection Installers are statically difficult to analyze because the actual code is packed inside archives and compressed files. FileSentinel identifies the signs of installers and gives an important alert to test files inside Virtual Machine (VM) environments. User-Friendly Dashboard It has a modern Graphical User Interface (GUI) with features like drag-and-drop functionality, coloreplades with verdicts, and activity logs.

Download Download the newest FileSentinel.exe release from “Releases.” It’s a portable app; hence, there’s no need for setup or installing it on your computer. It can easily be run from any path or computer desktop or USB device. First Run & Antivirus Alert Since FileSentinel.exe acts as a security program built using “Python/PyInstaller,” Windows Defender or other virus protection software can misclassify this program (usually displaying “Trojan:Win32/Wacatac” or other generic messages) when executed on computers with Windows OS because it’s not signed using any company’s trust certification and using PyInstaller can cause this problem. Beginner Users Should Note:

OS: Windows 10 or Windows 11 (preferably 64-bit)

Internet Connection: Must for VirusTotal functionalities (optional for Local Mode)

For FileSentinel’s full potential to be reached, you will require a free VirusTotal API Key.

Visit the VirusTotal website and create a free account with them.

Go to your API Key settings and copy your own API key.

Open FileSentinel

Go to Settings -> API Configuration.

Now, copy your key and press “Save & Close”.

It can be checked if it’s functioning correctly using the “Test Connection” button. Your API key will be saved on your computer locally within a secure configuration file. It will not be transmitted to any third party other than VirusTotal itself. If not provided, FileSentinel will run “In Local Mode”, relying only on internal heuristic engines.

Scoring System The risk score assigned to an application is based on:

Valid Digital Signatures (Reduces Risk)

High Entropy/Packed Sections (Increases Risk)

Suspicious Imports - WriteProcessMemory or CreateRemoteThread (Increase Risk)

Global Vendor Consensus (Weighted heavily based on vendor reputation) The Verdicts

CLEAN: There were no threats found locally or on the Internet.

LIKELY SAFE (Tool/Keygen): High number of detections but semantic interpretation reveals this file is probably “HackTool” or “Keygen,” not malware.

SUSPICIOUS: Data conflicts or generic heuristic clues.

MALICIOUS: Known presence of specific types of malware (Trojan, Ransomware HIGH RISK (Installer): It’s an installer and therefore not amenable to analysis unless it’s run.
