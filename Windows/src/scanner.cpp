#include "../include/scanner.h"
#include <yara.h>
#include <iostream>
#include <regex>
#include <string>

const char* WEEDHACK_RULE = R"(
    rule Weedhack_Stage1_Bytecode {
        meta:
            description = "Detects Weedhack's custom String Decryptor and environment"
            author = "You"
    
        strings:
            // 1. The JVM Bytecode for the S-Box generation: (j * 53 + 97) % 256
            $sbox_math = { 10 35 68 10 61 60 11 01 00 70 }
    
            // 2. The JVM Bytecode for the CBC State tracking: (state * 37 + idx * 13) % 256
            $cbc_math = { 10 25 68 ?? 10 0D 68 60 11 01 00 70 }
    
        condition:
            $sbox_math or $cbc_math
    }

    rule Weedhack_Fake_Config {
        meta:
            description = "Detects Weedhack's malicious UUID Campaign ID masquerading as an API version"
            author = "You"
        strings:
            $uuid_regex = /"api_version"\s*:\s*"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"/
        condition:
            $uuid_regex
    }
)";

// The Callback: YARA triggers this whenever it analyzes a file
int yaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;

        // Cast user_data back to our ExtractedFile struct pointer
        const ExtractedFile* file = (const ExtractedFile*)user_data;

        std::cout << "\n[!] Trace Detected\n";
        std::cout << "Matched Rule: " << rule->identifier << " (in " << file->filename << ")\n";

        // If we hit the config file, let's extract the Campaign ID!
        if (std::string(rule->identifier) == "Weedhack_Fake_Config") {

            // Convert our memory buffer into a standard C++ string
            std::string fileData(file->data.begin(), file->data.end());

            // Use a C++ regex capture group to grab ONLY the 36-character UUID
            std::regex extract_uuid(R"REGEX("api_version"\s*:\s*"([a-fA-F0-9\-]{36})")REGEX"); std::smatch match;

            if (std::regex_search(fileData, match, extract_uuid) && match.size() > 1) {
                std::cout << "Campaign ID : " << match[1].str() << "\n";
            }
        }
    }
    return CALLBACK_CONTINUE;
}

void scanFilesForWeedhack(const std::vector<ExtractedFile>& files) {
    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "[!] Failed to initialize YARA engine.\n";
        return;
    }

    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "[!] Failed to create YARA compiler.\n";
        yr_finalize();
        return;
    }

    if (yr_compiler_add_string(compiler, WEEDHACK_RULE, nullptr) != 0) {
        std::cerr << "[!] Failed to compile YARA rules.\n";
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    yr_compiler_get_rules(compiler, &rules);

    std::cout << "[*] YARA Engine loaded. Scanning " << files.size() << " extracted files...\n";

    for (const auto& file : files) {
        // Notice we are passing the memory address of the WHOLE file struct (&file) as user_data
        int result = yr_rules_scan_mem(
            rules,
            (const uint8_t*)file.data.data(),
            file.data.size(),
            0,
            yaraCallback,
            (void*)&file,
            0
        );

        if (result != ERROR_SUCCESS) {
            std::cerr << "[-] Error scanning file: " << file.filename << "\n";
        }
    }

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
}