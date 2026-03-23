#include <iostream>
#include "unzipper.h"
#include "scanner.h"

int main(int argc, char* argv[]) {
    std::cout << "==========================================\n";
    std::cout << "             FABRIC MOD SCANNER           \n";
    std::cout << "==========================================\n";

    if (argc < 2) {
        std::cerr << "[!] Usage: ./Detector <path_to_mod.jar>\n";
        return 1;
    }

    std::string targetJar = argv[1];
    std::cout << "[*] Target Archive: " << targetJar << "\n";

    // 1. Unzip the suspicious files into memory
    std::vector<ExtractedFile> filesToScan = extractJarContents(targetJar);

    if (filesToScan.empty()) {
        std::cout << "[+] No suspicious classes or configs found in JAR.\n";
        return 0;
    }

    // 2. Scan the memory buffers with YARA
    scanFilesForWeedhack(filesToScan);

    std::cout << "[*] Scan complete.\n";
    return 0;
}