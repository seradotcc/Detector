#ifndef SCANNER_H
#define SCANNER_H

#include <vector>
#include "unzipper.h"

// Initialize YARA, compile the rules, and scan the extracted files
void scanFilesForWeedhack(const std::vector<ExtractedFile>& files);

#endif