#include "crypto/HashService.hpp"

#include <openssl/evp.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>

namespace prismkey::crypto {
namespace {
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
}

core::Result<std::string> HashService::file(const std::filesystem::path& file, const std::string& algorithm) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        return core::Result<std::string>::failure(
            std::filesystem::exists(file) ? core::ErrorCode::FileNotReadable : core::ErrorCode::FileNotFound,
            "Não foi possível ler o arquivo informado.");
    }

    DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    const EVP_MD* algorithmDigest = EVP_get_digestbyname(algorithm.c_str());
    if (!algorithmDigest)
        return core::Result<std::string>::failure(core::ErrorCode::InvalidArgument, "Algoritmo de hash nao suportado.");
    if (!context || EVP_DigestInit_ex(context.get(), algorithmDigest, nullptr) != 1) {
        return core::Result<std::string>::failure(core::ErrorCode::CryptoError, "Falha ao inicializar o SHA-256.");
    }

    std::array<char, 64 * 1024> buffer{};
    while (input.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || input.gcount() > 0) {
        if (EVP_DigestUpdate(context.get(), buffer.data(), static_cast<size_t>(input.gcount())) != 1) {
            return core::Result<std::string>::failure(core::ErrorCode::CryptoError,
                                                      "Falha ao calcular o hash do arquivo.");
        }
    }
    if (!input.eof()) {
        return core::Result<std::string>::failure(core::ErrorCode::FileNotReadable,
                                                  "Não foi possível ler o arquivo informado.");
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestLength) != 1) {
        return core::Result<std::string>::failure(core::ErrorCode::CryptoError,
                                                  "Falha ao finalizar o cálculo do hash.");
    }

    std::ostringstream hexadecimal;
    hexadecimal << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < digestLength; ++index) {
        hexadecimal << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return core::Result<std::string>::success(hexadecimal.str());
}

core::Result<std::string> HashService::sha256File(const std::filesystem::path& file) {
    return HashService::file(file, "SHA256");
}

}  // namespace prismkey::crypto
