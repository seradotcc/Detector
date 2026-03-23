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

// Custom struct to pass multiple things into the callback
struct ScanUserData {
    const ExtractedFile* file;
    ScanResult* result;
};

int yaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        ScanUserData* data = (ScanUserData*)user_data;

        // Mark it as infected
        data->result->isInfected = true;

        // Build the report string
        data->result->reportText += "Matched Rule: " + std::string(rule->identifier) + "\n";
        data->result->reportText += "Tainted File: " + data->file->filename + "\n";

        if (std::string(rule->identifier) == "Weedhack_Fake_Config") {
            std::string fileData(data->file->data.begin(), data->file->data.end());
            std::regex extract_uuid(R"REGEX("api_version"\s*:\s*"([a-fA-F0-9\-]{36})")REGEX");
            std::smatch match;

            if (std::regex_search(fileData, match, extract_uuid) && match.size() > 1) {
                data->result->reportText += "Campaign ID : " + match[1].str() + "\n";
            }
        }
        data->result->reportText += "\n"; // Add a blank line between multiple detections
    }
    return CALLBACK_CONTINUE;
}

ScanResult scanFilesForTraces(const std::vector<ExtractedFile>& files) {
    ScanResult finalResult = { false, "" };

    if (yr_initialize() != ERROR_SUCCESS) {
        finalResult.reportText = "Failed to initialize YARA engine.";
        return finalResult;
    }

    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    yr_compiler_create(&compiler);
    yr_compiler_add_string(compiler, WEEDHACK_RULE, nullptr);
    yr_compiler_get_rules(compiler, &rules);

    for (const auto& file : files) {
        // Pack our file pointer and our result pointer into the custom struct
        ScanUserData userData = { &file, &finalResult };

        yr_rules_scan_mem(
            rules,
            (const uint8_t*)file.data.data(),
            file.data.size(),
            0,
            yaraCallback,
            (void*)&userData, // Pass the struct!
            0
        );
    }

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return finalResult;
}