#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

#include <iostream>
#include "../include/scanner.h"
#include "../include/unzipper.h"
#include <windows.h>
#include <string>
#include <vector>

void setupConsole() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        std::cout.clear();
        std::cerr.clear();
    }
}

int main(int argc, char* argv[]) {
    bool useConsole = false;
    std::string targetJar = "";

    // 1. Handle no arguments
    if (argc < 2) {
        MessageBoxA(NULL,
            "Please drag and drop a Minecraft .jar file onto this executable to scan it.\n",
            "Mod Detector",
            MB_ICONINFORMATION | MB_OK);
        return 1;
    }

    targetJar = argv[1];

    // 2. Check if the user passed the -c flag
    if (argc >= 3 && std::string(argv[2]) == "-c") {
        useConsole = true;
        setupConsole(); 
        std::cout << "[*] Scanning: " << targetJar << " ...\n";
    }

    // 3. Unzip into memory
    std::vector<ExtractedFile> filesToScan = extractJarContents(targetJar);

    if (filesToScan.empty()) {
        if (useConsole) {
            std::cout << "[+] No suspicious classes or config files found. File is clean.\n";
        }
        else {
            MessageBoxA(NULL,
                "No suspicious classes or config files found.\nThis file appears to be clean.",
                "Scan Result - CLEAN",
                MB_ICONINFORMATION | MB_OK);
        }
        return 0;
    }

    // 4. Scan the files
    ScanResult result = scanFilesForTraces(filesToScan);

    // 5. Output the results (Routing to Console OR MessageBox depending on the flag)
    if (result.isInfected) {
        if (useConsole) {
            std::cout << "\n[!] Infection Detected\n";
            std::cout << "==========================================\n";
            std::cout << result.reportText;
        }
        else {
            std::string alertMsg = "WARNING: INFECTION DETECTED!\n\n" + result.reportText;
            MessageBoxA(NULL, alertMsg.c_str(), "Scan Result - MALWARE FOUND", MB_ICONERROR | MB_OK);
        }
    }
    else {
        if (useConsole) {
            std::cout << "[+] No traces found. This file appears to be clean.\n";
        }
        else {
            MessageBoxA(NULL,
                "No traces found.\nThis file appears to be clean.",
                "Scan Result - NO_TRACES_FOUND",
                MB_ICONINFORMATION | MB_OK);
        }
    }

    // If we attached to a console, send a final newline
    if (useConsole) std::cout << std::endl;

    return 0;
}