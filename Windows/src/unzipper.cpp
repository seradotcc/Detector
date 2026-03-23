#include "../include/unzipper.h"
#include <zip.h>
#include <iostream>

std::vector<ExtractedFile> extractJarContents(const std::string& jarPath) {
    std::vector<ExtractedFile> extractedFiles;
    int err = 0;

    // 1. Open the JAR (ZIP) file
    zip_t* archive = zip_open(jarPath.c_str(), 0, &err);
    if (!archive) {
        std::cerr << "[!] Failed to open JAR: " << jarPath << " (libzip error code: " << err << ")\n";
        return extractedFiles;
    }

    // 2. Find out how many files are inside
    zip_int64_t num_entries = zip_get_num_entries(archive, 0);

    for (zip_int64_t i = 0; i < num_entries; i++) {
        // Get the name of the file
        const char* name = zip_get_name(archive, i, 0);
        if (!name) continue;

        std::string filename(name);

        // 3. Filter: We only care about .class files and fabric.api.json
        if (filename.find(".class") != std::string::npos || filename == "fabric.api.json") {

            // Get file stats (specifically so we know how big of a buffer to make)
            zip_stat_t stat;
            zip_stat_init(&stat);
            zip_stat_index(archive, i, 0, &stat);

            // Skip directories or empty files
            if (stat.size == 0) continue;

            // 4. Open the file inside the zip for reading
            zip_file_t* zf = zip_fopen_index(archive, i, 0);
            if (!zf) {
                std::cerr << "[-] Failed to open file inside zip: " << filename << "\n";
                continue;
            }

            // 5. Allocate a memory buffer and read the bytes into it!
            std::vector<char> buffer(stat.size);
            zip_int64_t bytes_read = zip_fread(zf, buffer.data(), stat.size);

            zip_fclose(zf);

            // If we successfully read the whole file, save it to our list
            if (bytes_read == stat.size) {
                extractedFiles.push_back({ filename, buffer });
            }
        }
    }

    // Clean up
    zip_close(archive);
    return extractedFiles;
}