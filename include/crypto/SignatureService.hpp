#pragma once

#include <filesystem>
#include <string>

#include "core/Result.hpp"

namespace prismkey::crypto {
struct SignatureDetails {
    std::string algorithm;
    std::string timestampUtc;
    bool legacy = false;
};

class SignatureService {
   public:
    static core::Result<void> signFile(const std::filesystem::path& file, const std::filesystem::path& privateKey,
                                       const std::filesystem::path& outputSignature, const std::string& password);
    static core::Result<void> verifyFile(const std::filesystem::path& file, const std::filesystem::path& signature,
                                         const std::filesystem::path& publicKey);
    static core::Result<SignatureDetails> verifyFileDetails(const std::filesystem::path& file,
                                                            const std::filesystem::path& signature,
                                                            const std::filesystem::path& publicKey);
};

}  // namespace prismkey::crypto
