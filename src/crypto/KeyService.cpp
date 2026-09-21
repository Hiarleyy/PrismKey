#include "crypto/KeyService.hpp"

#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace prismkey::crypto {
namespace {
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;

bool isRsa(const EVP_PKEY* key) { return key != nullptr && EVP_PKEY_base_id(key) == EVP_PKEY_RSA; }
}

core::Result<void> KeyService::generateRsaKeyPair(const std::filesystem::path& publicKey,
                                                   const std::filesystem::path& privateKey,
                                                   const std::string& password) {
    if (password.empty()) {
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument, "A senha da chave privada não pode ser vazia.");
    }
    if (publicKey == privateKey) {
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument, "Os arquivos de chave pública e privada devem ser diferentes.");
    }

    KeyContext context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* rawKey = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 3072) != 1 ||
        EVP_PKEY_keygen(context.get(), &rawKey) != 1) {
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao gerar o par de chaves RSA.");
    }
    Key key(rawKey, EVP_PKEY_free);
    if (!isRsa(key.get())) {
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "A chave gerada não é uma chave RSA válida.");
    }

    Bio publicBio(BIO_new_file(publicKey.string().c_str(), "wb"), BIO_free_all);
    if (!publicBio || PEM_write_bio_PUBKEY(publicBio.get(), key.get()) != 1) {
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable, "Não foi possível gravar a chave pública.");
    }
    Bio privateBio(BIO_new_file(privateKey.string().c_str(), "wb"), BIO_free_all);
    if (!privateBio || PEM_write_bio_PrivateKey(privateBio.get(), key.get(), EVP_aes_256_cbc(),
                                                reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
                                                static_cast<int>(password.size()), nullptr, nullptr) != 1) {
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable, "Não foi possível gravar a chave privada.");
    }
    return core::Result<void>::success();
}

}  // namespace prismkey::crypto
