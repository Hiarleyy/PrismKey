#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace prismkey::crypto {
struct FilePair { std::filesystem::path file; std::filesystem::path signature; };
struct BatchItemResult { std::filesystem::path file; bool ok; std::string message; };
struct FolderPairs { std::vector<FilePair> pairs; std::vector<std::filesystem::path> ignored; };

class BatchService {
public:
    static std::vector<std::filesystem::path> regularFiles(const std::vector<std::filesystem::path>& paths);
    static std::filesystem::path signaturePath(const std::filesystem::path& file);
    static FolderPairs discoverPairs(const std::filesystem::path& directory);
    static std::vector<BatchItemResult> signFiles(const std::vector<std::filesystem::path>& files, const std::filesystem::path& privateKey, const std::string& password);
    static std::vector<BatchItemResult> verifyPairs(const std::vector<FilePair>& pairs, const std::filesystem::path& publicKey);
};
}
