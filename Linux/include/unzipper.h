#ifndef UNZIPPER_H
#define UNZIPPER_H

#include <string>
#include <vector>

// This struct holds the file's name and its raw bytes in memory
struct ExtractedFile {
    std::string filename;
    std::vector<char> data;
};

// Our main function to rip the files out of the JAR
std::vector<ExtractedFile> extractJarContents(const std::string& jarPath);

#endif