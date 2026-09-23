#pragma once

#include <filesystem>
#include <string>

#include "core/Result.hpp"

namespace prismkey::crypto {
enum class KeyAlgorithm { Rsa, Ed25519 };
struct PublicKeyDetails {
    std::string algorithm;
    int bits;
    std::string fingerprint;
};

class KeyService {
   public:
    static core::Result<void> generateRsaKeyPair(const std::filesystem::path& publicKey,
                                                 const std::filesystem::path& privateKey, const std::string& password);
    static core::Result<void> generateKeyPair(const std::filesystem::path& publicKey,
                                              const std::filesystem::path& privateKey, const std::string& password,
                                              KeyAlgorithm algorithm);
    static core::Result<PublicKeyDetails> inspectPublicKey(const std::filesystem::path& publicKey);
};

}  // namespace prismkey::crypto
