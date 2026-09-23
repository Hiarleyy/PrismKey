#include "crypto/KeyService.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>

#include "core/ProjectStorage.hpp"

namespace prismkey::crypto {
namespace {
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
bool isRsa(const EVP_PKEY* key) { return key && EVP_PKEY_base_id(key) == EVP_PKEY_RSA; }
bool isEd25519(const EVP_PKEY* key) { return key && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519; }
}  // namespace

core::Result<PublicKeyDetails> KeyService::inspectPublicKey(const std::filesystem::path& publicKey) {
    Bio bio(BIO_new_file(publicKey.string().c_str(), "rb"), BIO_free_all);
    Key key(bio ? PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr) : nullptr, EVP_PKEY_free);
    if (!key || (!isRsa(key.get()) && !isEd25519(key.get())))
        return core::Result<PublicKeyDetails>::failure(core::ErrorCode::InvalidKey,
                                                       "Chave publica invalida ou nao suportada.");
    std::ifstream input(publicKey, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(input)), {});
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest);
    std::ostringstream fingerprint;
    fingerprint << std::hex << std::setfill('0');
    for (auto byte : digest) fingerprint << std::setw(2) << static_cast<unsigned>(byte);
    return core::Result<PublicKeyDetails>::success(
        {isRsa(key.get()) ? "RSA" : "Ed25519", EVP_PKEY_bits(key.get()), fingerprint.str()});
}

core::Result<void> KeyService::generateRsaKeyPair(const std::filesystem::path& publicKey,
                                                  const std::filesystem::path& privateKey,
                                                  const std::string& password) {
    return generateKeyPair(publicKey, privateKey, password, KeyAlgorithm::Rsa);
}

core::Result<void> KeyService::generateKeyPair(const std::filesystem::path& publicKey,
                                               const std::filesystem::path& privateKey, const std::string& password,
                                               KeyAlgorithm algorithm) {
    if (password.empty())
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument,
                                           "A senha da chave privada nao pode ser vazia.");
    if (publicKey == privateKey)
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument,
                                           "Os arquivos de chave publica e privada devem ser diferentes.");
    const auto storedPublicKey = core::ProjectStorage::destination(core::StorageKind::PublicKey, publicKey);
    const auto storedPrivateKey = core::ProjectStorage::destination(core::StorageKind::PrivateKey, privateKey);
    std::error_code storageError;
    std::filesystem::create_directories(storedPublicKey.parent_path(), storageError);
    std::filesystem::create_directories(storedPrivateKey.parent_path(), storageError);
    if (storageError)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "Nao foi possivel criar as pastas de chaves.");
    KeyContext context(EVP_PKEY_CTX_new_id(algorithm == KeyAlgorithm::Rsa ? EVP_PKEY_RSA : EVP_PKEY_ED25519, nullptr),
                       EVP_PKEY_CTX_free);
    EVP_PKEY* rawKey = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        (algorithm == KeyAlgorithm::Rsa && EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 3072) != 1) ||
        EVP_PKEY_keygen(context.get(), &rawKey) != 1)
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao gerar o par de chaves.");
    Key key(rawKey, EVP_PKEY_free);
    if ((algorithm == KeyAlgorithm::Rsa && !isRsa(key.get())) ||
        (algorithm == KeyAlgorithm::Ed25519 && !isEd25519(key.get())))
        return core::Result<void>::failure(core::ErrorCode::CryptoError,
                                           "A chave gerada nao corresponde ao algoritmo solicitado.");
    Bio publicBio(BIO_new_file(storedPublicKey.string().c_str(), "wb"), BIO_free_all);
    if (!publicBio || PEM_write_bio_PUBKEY(publicBio.get(), key.get()) != 1)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "Nao foi possivel gravar a chave publica.");
    Bio privateBio(BIO_new_file(storedPrivateKey.string().c_str(), "wb"), BIO_free_all);
    if (!privateBio || PEM_write_bio_PrivateKey(privateBio.get(), key.get(), EVP_aes_256_cbc(),
                                                reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
                                                static_cast<int>(password.size()), nullptr, nullptr) != 1)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "Nao foi possivel gravar a chave privada.");
    return core::Result<void>::success();
}
}  // namespace prismkey::crypto
