# HollowOut 🪏

HollowOut is a Windows proof-of-concept demonstrating basic process hollowing.

It suspends a target **host** process, replaces its in-memory image with the executable image of a **hider** process, fixes relocations and imports, redirects the main thread to the new entry point, and resumes execution.

⚠️ Educational and research purposes only.

## Requirements
- Windows (64-bit)
- Visual Studio / MSVC
- Administrator privileges recommended

## Usage
1. Build and run.
2. Enter:
   - `Host` -> process to hollow
   - `Hider` -> process to inject

## Important Note
This implementation is simplified.  
Modern applications rely on complex dependencies and security mitigations (ASLR, CFG, integrity checks, etc.), so **most real-world applications will likely crash if hollowed using this tool.**

## Disclaimer
For learning Windows internals and PE loading mechanics only. Use responsibly.
