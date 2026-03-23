# Detector

Detector is a static analysis utility written in C++ designed to identify malware infections within Minecraft `.jar` modifications. While the current ruleset is exclusively focused on identifying the "Weedhack" Stage 1 dropper, the architecture is designed to be extensible for detecting additional Java-based malware strains in the future. It utilizes memory-safe archive extraction and YARA rule matching to detect heavily obfuscated malicious payloads without executing the underlying Java bytecode.

## Technical Overview

Currently, Detector targets the Weedhack malware, which operates as a multi-stage infostealer. Stage 1 is a dropper embedded within legitimate or fake Minecraft mods (typically Fabric). This dropper relies on a custom implementation of the JNIC (Java Native Interface Compiler) framework to reflectively load a heavily obfuscated native DLL (Stage 2) into memory, which then steals session tokens and exfiltrates them to a Command and Control (C2) server.

Because the Stage 2 payload never touches the disk and the Stage 1 strings are encrypted, standard static analysis engines often fail to detect the infection. 

### Detection Methodology
To bypass standard obfuscation, the tool targets architectural anomalies and immutable JVM bytecode patterns. For the Weedhack strain, the detection pipeline operates as follows:

1. **In-Memory Extraction:** The tool uses `libzip` to parse the `.jar` (ZIP) archive and extracts the internal `.class` and `.json` files directly into memory buffers. It does not write these files to disk, ensuring safe analysis.
2. **YARA Pattern Matching:** The memory buffers are passed to the `libyara` engine, which currently scans for two distinct indicators of compromise (IOCs) associated with Weedhack:
   * **Fake API Versioning:** Identifies the presence of a `fabric.api.json` configuration file containing a 36-character UUID disguised as an API version. This UUID is extracted and reported as the attacker's Campaign ID.
   * **Cryptographic Bytecode:** Detects the raw JVM bytecode hex sequences representing the mathematical operations of the malware's custom string decryption loops (S-Box generation and CBC state tracking), which cannot be easily obfuscated without breaking the decryption logic.

## Repository Structure

```text
.
├── linux/
│   ├── build/
│   ├── include/
│   ├── src/
│   └── CMakeLists.txt
└── windows/
    └── (Visual Studio Project Solution and Source Files)
```

## Linux Environment

### Requirements
The Linux build requires standard C++ build tools, CMake, and the development headers for `libzip` and `libyara`.

On Debian/Ubuntu-based distributions, install the requirements via `apt`:
```bash
sudo apt update
sudo apt install build-essential cmake libyara-dev libzip-dev pkg-config
```

### Compilation
Navigate to the Linux build directory and compile using CMake:
```bash
cd linux/build
cmake ..
make
```
This will output the `Detector` executable in the `build` directory.

## Windows Environment

### Requirements
The Windows build requires the Microsoft Visual C++ compiler and the `vcpkg` package manager to handle dependencies.
1. Install **Visual Studio** or **Visual Studio Build Tools** with the "Desktop development with C++" workload enabled.
2. Ensure **Git** and **CMake** are installed and added to your system PATH.
3. Install `vcpkg` by running the following in a command prompt:
   ```cmd
   git clone https://github.com/microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   ```

### Dependency Installation
Use `vcpkg` to install the required 64-bit libraries and integrate them into Visual Studio:
```cmd
.\vcpkg install libzip:x64-windows yara:x64-windows
.\vcpkg integrate install
```

### Compilation
1. Open the Visual Studio solution (`.sln`) located in the `windows/` directory.
2. Ensure the build target platform at the top of the IDE is set to **x64** (not x86).
3. Build the solution (`Ctrl + Shift + B` or `Build -> Build Solution`).
4. The compiled `Detector.exe` will be located in the project's `x64/Release` or `x64/Debug` folder.

## Usage

### Windows
The Windows application operates in a dual-mode configuration (GUI and CLI).

**GUI Mode:**
Drag and drop a `.jar` file directly onto the `Detector.exe` icon. A native Windows message box will appear displaying the scan results and any extracted Campaign IDs.

**CLI Mode:**
To run the tool via Command Prompt or PowerShell, pass the file path and the `-c` flag. This will suppress the message box and output the results directly to standard output.
```cmd
.\Detector.exe "C:\path\to\mod.jar" -c
```

### Linux
Run the compiled binary from the terminal, passing the path to the target `.jar` file as the first argument.
```bash
./Detector /path/to/mod.jar
```