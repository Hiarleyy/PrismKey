#include "crypto/SignatureService.hpp"

#include <array>
#include <fstream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <vector>

namespace prismkey::crypto {
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

core::Result<void> updateFromFile(EVP_MD_CTX* context, const std::filesystem::path& file, bool signing) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        return core::Result<void>::failure(std::filesystem::exists(file) ? core::ErrorCode::FileNotReadable : core::ErrorCode::FileNotFound,
                                           "Não foi possível ler o arquivo informado.");
    }
    std::array<char, 64 * 1024> buffer{};
    while (input.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || input.gcount() > 0) {
        const int result = signing ? EVP_DigestSignUpdate(context, buffer.data(), static_cast<size_t>(input.gcount()))
                                   : EVP_DigestVerifyUpdate(context, buffer.data(), static_cast<size_t>(input.gcount()));
        if (result != 1) {
            return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao processar o arquivo.");
        }
    }
    if (!input.eof()) {
        return core::Result<void>::failure(core::ErrorCode::FileNotReadable, "Não foi possível ler o arquivo informado.");
    }
    return core::Result<void>::success();
}

bool configurePss(EVP_PKEY_CTX* context, bool signing) {
    return context != nullptr && EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) == 1 &&
           EVP_PKEY_CTX_set_rsa_pss_saltlen(context, signing ? RSA_PSS_SALTLEN_DIGEST : RSA_PSS_SALTLEN_AUTO) == 1;
}

bool isRsa(const EVP_PKEY* key) { return key != nullptr && EVP_PKEY_base_id(key) == EVP_PKEY_RSA; }
}

core::Result<void> SignatureService::signFile(const std::filesystem::path& file,
                                              const std::filesystem::path& privateKey,
                                              const std::filesystem::path& outputSignature,
                                              const std::string& password) {
    Bio keyBio(BIO_new_file(privateKey.string().c_str(), "rb"), BIO_free_all);
    if (!keyBio) {
        return core::Result<void>::failure(std::filesystem::exists(privateKey) ? core::ErrorCode::FileNotReadable : core::ErrorCode::FileNotFound,
                                           "Não foi possível abrir a chave privada.");
    }
    Key key(PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())), EVP_PKEY_free);
    if (!key || !isRsa(key.get())) {
        return core::Result<void>::failure(core::ErrorCode::IncorrectPassword, "Senha incorreta ou chave privada inválida.");
    }

    DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* keyContext = nullptr;
    if (!context || EVP_DigestSignInit(context.get(), &keyContext, EVP_sha256(), nullptr, key.get()) != 1 || !configurePss(keyContext, true)) {
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao inicializar a assinatura digital.");
    }
    const auto update = updateFromFile(context.get(), file, true);
    if (!update.ok()) return update;
    const int maximumSignatureSize = EVP_PKEY_get_size(key.get());
    if (maximumSignatureSize <= 0) {
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao preparar a assinatura digital.");
    }
    size_t signatureSize = static_cast<size_t>(maximumSignatureSize);
    std::vector<unsigned char> signature(signatureSize);
    if (EVP_DigestSignFinal(context.get(), signature.data(), &signatureSize) != 1) {
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao finalizar a assinatura digital.");
    }
    std::ofstream output(outputSignature, std::ios::binary | std::ios::trunc);
    if (!output) return core::Result<void>::failure(core::ErrorCode::FileNotWritable, "Não foi possível gravar a assinatura.");
    output.write(reinterpret_cast<const char*>(signature.data()), static_cast<std::streamsize>(signatureSize));
    if (!output) return core::Result<void>::failure(core::ErrorCode::FileNotWritable, "Não foi possível gravar a assinatura.");
    return core::Result<void>::success();
}

core::Result<void> SignatureService::verifyFile(const std::filesystem::path& file,
                                                const std::filesystem::path& signatureFile,
                                                const std::filesystem::path& publicKey) {
    Bio keyBio(BIO_new_file(publicKey.string().c_str(), "rb"), BIO_free_all);
    if (!keyBio) return core::Result<void>::failure(std::filesystem::exists(publicKey) ? core::ErrorCode::FileNotReadable : core::ErrorCode::FileNotFound,
                                                    "Não foi possível abrir a chave pública.");
    Key key(PEM_read_bio_PUBKEY(keyBio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!key || !isRsa(key.get())) return core::Result<void>::failure(core::ErrorCode::InvalidKey, "A chave pública é inválida.");

    std::ifstream signatureInput(signatureFile, std::ios::binary);
    if (!signatureInput) return core::Result<void>::failure(std::filesystem::exists(signatureFile) ? core::ErrorCode::FileNotReadable : core::ErrorCode::FileNotFound,
                                                            "Não foi possível ler o arquivo de assinatura.");
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(signatureInput)), {});
    if (signatureInput.bad() || signature.empty()) return core::Result<void>::failure(core::ErrorCode::InvalidSignature, "A assinatura é inválida.");

    DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* keyContext = nullptr;
    if (!context || EVP_DigestVerifyInit(context.get(), &keyContext, EVP_sha256(), nullptr, key.get()) != 1 || !configurePss(keyContext, false)) {
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao inicializar a verificação da assinatura.");
    }
    const auto update = updateFromFile(context.get(), file, false);
    if (!update.ok()) return update;
    if (EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size()) != 1) {
        return core::Result<void>::failure(core::ErrorCode::InvalidSignature, "A assinatura é inválida.");
    }
    return core::Result<void>::success();
}

}  // namespace prismkey::crypto
