#pragma once

#include "core/Result.hpp"

#include <filesystem>
#include <string>

namespace prismkey::crypto {
struct PublicKeyDetails { std::string algorithm; int bits; std::string fingerprint; };

class KeyService {
public:
    static core::Result<void> generateRsaKeyPair(const std::filesystem::path& publicKey,
                                                  const std::filesystem::path& privateKey,
                                                  const std::string& password);
    static core::Result<PublicKeyDetails> inspectPublicKey(const std::filesystem::path& publicKey);
};

}  // namespace prismkey::crypto
