#pragma once

#include "core/Result.hpp"

#include <filesystem>
#include <string>

namespace prismkey::crypto {

class KeyService {
public:
    static core::Result<void> generateRsaKeyPair(const std::filesystem::path& publicKey,
                                                  const std::filesystem::path& privateKey,
                                                  const std::string& password);
};

}  // namespace prismkey::crypto
