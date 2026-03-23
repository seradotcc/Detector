#ifndef SCANNER_H
#define SCANNER_H

#include <vector>
#include <string>
#include "../include/unzipper.h"

// A struct to hold the final verdict and the text to display
struct ScanResult {
    bool isInfected;
    std::string reportText;
};

// Update our function to return the result
ScanResult scanFilesForTraces(const std::vector<ExtractedFile>& files);

#endif