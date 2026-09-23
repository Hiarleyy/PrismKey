#include <gtest/gtest.h>
#include <openssl/pem.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>

#include "core/ProjectStorage.hpp"
#include "crypto/HashService.hpp"
#include "crypto/KeyService.hpp"
#include "crypto/SignatureService.hpp"

namespace {
class CryptoServicesTest : public ::testing::Test {
   protected:
    void SetUp() override {
        originalDirectory = std::filesystem::current_path();
        directory = std::filesystem::temp_directory_path() /
                    ("prismkey-tests-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(directory);
        std::filesystem::current_path(directory);
        publicKey = directory / "public.pem";
        privateKey = directory / "private.pem";
        const auto result = prismkey::crypto::KeyService::generateRsaKeyPair(publicKey, privateKey, password);
        ASSERT_TRUE(result.ok()) << result.message();
        publicKey = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PublicKey, publicKey);
        privateKey = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PrivateKey, privateKey);
    }

    void TearDown() override {
        std::filesystem::current_path(originalDirectory);
        std::filesystem::remove_all(directory);
    }

    void writeFile(const std::filesystem::path& path, const std::string& content) {
        std::ofstream output(path, std::ios::binary);
        output << content;
    }

    std::filesystem::path directory;
    std::filesystem::path originalDirectory;
    std::filesystem::path publicKey;
    std::filesystem::path privateKey;
    const std::string password = "senha-de-teste";
};

TEST(HashServiceStandaloneTest, CalculatesKnownSha256) {
    const auto file = std::filesystem::temp_directory_path() / "prismkey-known-hash.txt";
    {
        std::ofstream output(file, std::ios::binary);
        output << "abc";
    }
    const auto result = prismkey::crypto::HashService::sha256File(file);
    EXPECT_TRUE(result.ok()) << result.message();
    EXPECT_EQ(result.value(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::filesystem::remove(file);
}

TEST_F(CryptoServicesTest, GeneratesLoadableEncryptedPemKeys) {
    using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    Bio privateBio(BIO_new_file(privateKey.string().c_str(), "rb"), BIO_free_all);
    Key privateLoaded(PEM_read_bio_PrivateKey(privateBio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())),
                      EVP_PKEY_free);
    Bio publicBio(BIO_new_file(publicKey.string().c_str(), "rb"), BIO_free_all);
    Key publicLoaded(PEM_read_bio_PUBKEY(publicBio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    ASSERT_NE(privateLoaded, nullptr);
    ASSERT_NE(publicLoaded, nullptr);
    EXPECT_EQ(EVP_PKEY_bits(privateLoaded.get()), 3072);
}

TEST_F(CryptoServicesTest, SignsAndVerifiesFile) {
    const auto file = directory / "documento.txt";
    const auto signature = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::Signature,
                                                                       directory / "documento.sig");
    writeFile(file, "conteúdo original");
    const auto signedResult = prismkey::crypto::SignatureService::signFile(file, privateKey, signature, password);
    ASSERT_TRUE(signedResult.ok()) << signedResult.message();
    const auto verifiedResult = prismkey::crypto::SignatureService::verifyFile(file, signature, publicKey);
    EXPECT_TRUE(verifiedResult.ok()) << verifiedResult.message();
}

TEST_F(CryptoServicesTest, RejectsModifiedFile) {
    const auto file = directory / "documento.txt";
    const auto signature = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::Signature,
                                                                       directory / "documento.sig");
    writeFile(file, "conteúdo original");
    ASSERT_TRUE(prismkey::crypto::SignatureService::signFile(file, privateKey, signature, password).ok());
    writeFile(file, "conteúdo adulterado");
    const auto result = prismkey::crypto::SignatureService::verifyFile(file, signature, publicKey);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.errorCode(), prismkey::core::ErrorCode::InvalidSignature);
}

TEST_F(CryptoServicesTest, RejectsDifferentPublicKey) {
    const auto file = directory / "documento.txt";
    const auto signature = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::Signature,
                                                                       directory / "documento.sig");
    const auto otherPublic = directory / "other-public.pem";
    const auto otherPrivate = directory / "other-private.pem";
    writeFile(file, "conteúdo original");
    ASSERT_TRUE(prismkey::crypto::SignatureService::signFile(file, privateKey, signature, password).ok());
    ASSERT_TRUE(prismkey::crypto::KeyService::generateRsaKeyPair(otherPublic, otherPrivate, password).ok());
    const auto result = prismkey::crypto::SignatureService::verifyFile(
        file, signature,
        prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PublicKey, otherPublic));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.errorCode(), prismkey::core::ErrorCode::InvalidSignature);
}

TEST_F(CryptoServicesTest, SignsAndVerifiesEd25519WithTimestamp) {
    const auto edPublic = directory / "ed-public.pem";
    const auto edPrivate = directory / "ed-private.pem";
    const auto file = directory / "ed-documento.txt";
    const auto signature = directory / "ed-documento.sig";
    ASSERT_TRUE(prismkey::crypto::KeyService::generateKeyPair(edPublic, edPrivate, password,
                                                              prismkey::crypto::KeyAlgorithm::Ed25519)
                    .ok());
    writeFile(file, "conteudo Ed25519");
    const auto storedPrivate =
        prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PrivateKey, edPrivate);
    const auto storedPublic =
        prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PublicKey, edPublic);
    const auto storedSignature =
        prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::Signature, signature);
    ASSERT_TRUE(prismkey::crypto::SignatureService::signFile(file, storedPrivate, signature, password).ok());
    const auto verified = prismkey::crypto::SignatureService::verifyFileDetails(file, storedSignature, storedPublic);
    ASSERT_TRUE(verified.ok()) << verified.message();
    EXPECT_EQ(verified.value().algorithm, "Ed25519");
    EXPECT_FALSE(verified.value().legacy);
    EXPECT_TRUE(verified.value().timestampUtc.ends_with("Z"));
}

TEST_F(CryptoServicesTest, RejectsModifiedTimestampEnvelope) {
    const auto file = directory / "documento.txt";
    const auto signature = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::Signature,
                                                                       directory / "documento.sig");
    writeFile(file, "conteudo original");
    ASSERT_TRUE(prismkey::crypto::SignatureService::signFile(file, privateKey, signature, password).ok());
    std::fstream stream(signature, std::ios::binary | std::ios::in | std::ios::out);
    stream.seekp(11);
    stream.put('X');
    stream.close();
    const auto result = prismkey::crypto::SignatureService::verifyFileDetails(file, signature, publicKey);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.errorCode(), prismkey::core::ErrorCode::InvalidSignature);
}
}  // namespace
