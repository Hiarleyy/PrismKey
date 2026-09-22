#include "crypto/BatchService.hpp"
#include "crypto/SignatureService.hpp"
#include <algorithm>

namespace prismkey::crypto {
std::vector<std::filesystem::path> BatchService::regularFiles(const std::vector<std::filesystem::path>& paths) {
    std::vector<std::filesystem::path> result;
    for (const auto& path : paths) if (std::filesystem::is_regular_file(path)) result.push_back(path);
    return result;
}
std::filesystem::path BatchService::signaturePath(const std::filesystem::path& file) { return file.string() + ".sig"; }
FolderPairs BatchService::discoverPairs(const std::filesystem::path& directory) {
    FolderPairs result;
    if (!std::filesystem::is_directory(directory)) return result;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (!entry.is_regular_file()) continue;
        const auto path = entry.path();
        if (path.extension() == ".sig") { if (!std::filesystem::is_regular_file(path.parent_path() / path.stem())) result.ignored.push_back(path); continue; }
        const auto signature = signaturePath(path);
        if (std::filesystem::is_regular_file(signature)) result.pairs.push_back({path, signature}); else result.ignored.push_back(path);
    }
    return result;
}
std::vector<BatchItemResult> BatchService::signFiles(const std::vector<std::filesystem::path>& files, const std::filesystem::path& privateKey, const std::string& password) {
    std::vector<BatchItemResult> results;
    for (const auto& file : files) { const auto r = SignatureService::signFile(file, privateKey, signaturePath(file), password); results.push_back({file, r.ok(), r.ok() ? "Assinado" : r.message()}); }
    return results;
}
std::vector<BatchItemResult> BatchService::verifyPairs(const std::vector<FilePair>& pairs, const std::filesystem::path& publicKey) {
    std::vector<BatchItemResult> results;
    for (const auto& pair : pairs) { const auto r = SignatureService::verifyFile(pair.file, pair.signature, publicKey); results.push_back({pair.file, r.ok(), r.ok() ? "Valida" : r.message()}); }
    return results;
}
}
