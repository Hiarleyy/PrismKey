#pragma once

#include "core/Result.hpp"

#include <filesystem>
#include <string>

namespace prismkey::crypto {

class SignatureService {
public:
    static core::Result<void> signFile(const std::filesystem::path& file,
                                       const std::filesystem::path& privateKey,
                                       const std::filesystem::path& outputSignature,
                                       const std::string& password);
    static core::Result<void> verifyFile(const std::filesystem::path& file,
                                         const std::filesystem::path& signature,
                                         const std::filesystem::path& publicKey);
};

}  // namespace prismkey::crypto
