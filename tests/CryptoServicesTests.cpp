#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <vector>

#include "core/ProjectStorage.hpp"
#include "crypto/HashService.hpp"
#include "crypto/DownloadService.hpp"
#include "crypto/KeyService.hpp"
#include "crypto/SignatureService.hpp"

namespace {
#ifdef _WIN32
class LocalHttpsServer {
   public:
    LocalHttpsServer() {
        const auto nonce = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        directory_ = std::filesystem::temp_directory_path() / ("prismkey-https-" + nonce);
        certificatePath_ = directory_ / "ca.pem";
        std::filesystem::create_directories(directory_);
        ready_ = createContext() && createListener();
        if (ready_) worker_ = std::thread([this] { serve(); });
    }

    ~LocalHttpsServer() {
        if (listener_ != INVALID_SOCKET) closesocket(listener_);
        if (worker_.joinable()) worker_.join();
        if (context_) SSL_CTX_free(context_);
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    [[nodiscard]] bool ready() const { return ready_; }
    [[nodiscard]] std::filesystem::path certificatePath() const { return certificatePath_; }
    [[nodiscard]] std::string url() const { return "https://localhost:" + std::to_string(port_) + "/arquivo"; }

   private:
    static bool addExtension(X509* certificate, int id, const char* value) {
        X509V3_CTX extensionContext{};
        X509V3_set_ctx_nodb(&extensionContext);
        X509V3_set_ctx(&extensionContext, certificate, certificate, nullptr, nullptr, 0);
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &extensionContext, id, const_cast<char*>(value));
        if (!extension) return false;
        const bool added = X509_add_ext(certificate, extension, -1) == 1;
        X509_EXTENSION_free(extension);
        return added;
    }

    bool createContext() {
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> keyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                                                                                EVP_PKEY_CTX_free);
        EVP_PKEY* rawKey = nullptr;
        if (!keyContext || EVP_PKEY_keygen_init(keyContext.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 2048) != 1 ||
            EVP_PKEY_keygen(keyContext.get(), &rawKey) != 1)
            return false;
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(rawKey, EVP_PKEY_free);
        std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
        if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
            ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1 ||
            X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0) == nullptr ||
            X509_gmtime_adj(X509_get_notAfter(certificate.get()), 24 * 60 * 60) == nullptr ||
            X509_set_pubkey(certificate.get(), key.get()) != 1)
            return false;
        X509_NAME* subject = X509_get_subject_name(certificate.get());
        if (!subject || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                                    reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) != 1 ||
            X509_set_issuer_name(certificate.get(), subject) != 1 ||
            !addExtension(certificate.get(), NID_basic_constraints, "critical,CA:TRUE") ||
            !addExtension(certificate.get(), NID_subject_alt_name, "DNS:localhost") ||
            X509_sign(certificate.get(), key.get(), EVP_sha256()) == 0)
            return false;
        context_ = SSL_CTX_new(TLS_server_method());
        if (!context_ || SSL_CTX_use_certificate(context_, certificate.get()) != 1 ||
            SSL_CTX_use_PrivateKey(context_, key.get()) != 1)
            return false;
        std::unique_ptr<BIO, decltype(&BIO_free)> certificateBio(BIO_new(BIO_s_mem()), BIO_free);
        if (!certificateBio || PEM_write_bio_X509(certificateBio.get(), certificate.get()) != 1) return false;
        char* pem = nullptr;
        const long pemLength = BIO_get_mem_data(certificateBio.get(), &pem);
        std::ofstream certificateFile(certificatePath_, std::ios::binary | std::ios::trunc);
        certificateFile.write(pem, pemLength);
        return certificateFile.good();
    }

    bool createListener() {
        WSADATA winsock{};
        if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return false;
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener_ == INVALID_SOCKET) return false;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(listener_, 1) != 0)
            return false;
        int length = sizeof(address);
        if (getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) != 0) return false;
        port_ = ntohs(address.sin_port);
        return true;
    }

    void serve() {
        const SOCKET client = accept(listener_, nullptr, nullptr);
        if (client == INVALID_SOCKET) return;
        SSL* ssl = SSL_new(context_);
        if (ssl) {
            SSL_set_fd(ssl, static_cast<int>(client));
            if (SSL_accept(ssl) == 1) {
                std::array<char, 4096> request{};
                SSL_read(ssl, request.data(), static_cast<int>(request.size()));
                constexpr char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc";
                SSL_write(ssl, response, static_cast<int>(sizeof(response) - 1));
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
        }
        closesocket(client);
    }

    std::filesystem::path directory_;
    std::filesystem::path certificatePath_;
    SSL_CTX* context_ = nullptr;
    SOCKET listener_ = INVALID_SOCKET;
    std::thread worker_;
    unsigned short port_ = 0;
    bool ready_ = false;
};
#endif
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

TEST(DownloadServiceStandaloneTest, RejectsHttpUrlWithoutPublishingDestination) {
    const auto output = std::filesystem::temp_directory_path() / "prismkey-http-download.bin";
    std::filesystem::remove(output);
    const auto result = prismkey::crypto::DownloadService::download(
        "http://example.com/", output, "0000000000000000000000000000000000000000000000000000000000000000", "SHA-256");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.errorCode(), prismkey::core::ErrorCode::InvalidArgument);
    EXPECT_FALSE(std::filesystem::exists(output));
}

TEST(DownloadServiceStandaloneTest, RejectsInvalidHashWithoutPublishingDestination) {
    const auto output = std::filesystem::temp_directory_path() / "prismkey-invalid-hash-download.bin";
    std::filesystem::remove(output);
    const auto result = prismkey::crypto::DownloadService::download("https://example.com/", output, "not-a-hash", "SHA-256");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.errorCode(), prismkey::core::ErrorCode::InvalidArgument);
    EXPECT_FALSE(std::filesystem::exists(output));
}

#ifdef _WIN32
TEST(DownloadServiceStandaloneTest, DownloadsKnownVectorsWithTrustedLocalCertificate) {
    const std::array<std::pair<const char*, const char*>, 4> vectors = {{
        {"SHA-256", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"},
        {"SHA-512", "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"},
        {"SHA3-256", "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532"},
        {"BLAKE2b-512", "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"},
    }};
    for (const auto& [algorithm, expectedHash] : vectors) {
        LocalHttpsServer server;
        ASSERT_TRUE(server.ready());
        const auto output = server.certificatePath().parent_path() / "download.bin";
        const auto result = prismkey::crypto::DownloadService::download(server.url(), output, expectedHash, algorithm,
                                                                         server.certificatePath());
        ASSERT_TRUE(result.ok()) << result.message();
        std::ifstream downloaded(output, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(downloaded)), {});
        EXPECT_EQ(content, "abc");
    }
}

TEST(DownloadServiceStandaloneTest, RemovesOutputForHashMismatchAndUntrustedCertificate) {
    {
        LocalHttpsServer server;
        ASSERT_TRUE(server.ready());
        const auto output = server.certificatePath().parent_path() / "mismatch.bin";
        const auto result = prismkey::crypto::DownloadService::download(
            server.url(), output, "0000000000000000000000000000000000000000000000000000000000000000", "SHA-256",
            server.certificatePath());
        EXPECT_FALSE(result.ok());
        EXPECT_FALSE(std::filesystem::exists(output));
    }
    {
        LocalHttpsServer server;
        ASSERT_TRUE(server.ready());
        const auto output = server.certificatePath().parent_path() / "tls-error.bin";
        const auto result = prismkey::crypto::DownloadService::download(
            server.url(), output, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", "SHA-256");
        EXPECT_FALSE(result.ok());
        EXPECT_FALSE(std::filesystem::exists(output));
    }
}
#endif

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

TEST_F(CryptoServicesTest, RejectsEd25519SignatureWithDifferentPublicKey) {
    const auto file = directory / "ed-documento.txt";
    const auto signature = directory / "ed-documento.sig";
    const auto firstPublic = directory / "ed-first-public.pem";
    const auto firstPrivate = directory / "ed-first-private.pem";
    const auto otherPublic = directory / "ed-other-public.pem";
    const auto otherPrivate = directory / "ed-other-private.pem";
    ASSERT_TRUE(prismkey::crypto::KeyService::generateKeyPair(firstPublic, firstPrivate, password,
                                                              prismkey::crypto::KeyAlgorithm::Ed25519)
                    .ok());
    ASSERT_TRUE(prismkey::crypto::KeyService::generateKeyPair(otherPublic, otherPrivate, password,
                                                              prismkey::crypto::KeyAlgorithm::Ed25519)
                    .ok());
    writeFile(file, "conteudo Ed25519");
    const auto storedPrivate = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PrivateKey,
                                                                            firstPrivate);
    const auto storedPublic = prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::PublicKey,
                                                                           otherPublic);
    ASSERT_TRUE(prismkey::crypto::SignatureService::signFile(file, storedPrivate, signature, password).ok());
    const auto result = prismkey::crypto::SignatureService::verifyFile(
        file, prismkey::core::ProjectStorage::destination(prismkey::core::StorageKind::Signature, signature), storedPublic);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.errorCode(), prismkey::core::ErrorCode::InvalidSignature);
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

TEST_F(CryptoServicesTest, VerifiesLegacyRsaPssSignatureWithoutTimestamp) {
    const auto file = directory / "legado.txt";
    const auto signature = directory / "legado.sig";
    writeFile(file, "assinatura RSA-PSS legada");

    using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Bio privateBio(BIO_new_file(privateKey.string().c_str(), "rb"), BIO_free_all);
    Key privateKeyHandle(
        PEM_read_bio_PrivateKey(privateBio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())), EVP_PKEY_free);
    ASSERT_NE(privateKeyHandle, nullptr);
    const std::string content = "assinatura RSA-PSS legada";
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* keyContext = nullptr;
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(EVP_DigestSignInit(context.get(), &keyContext, EVP_sha256(), nullptr, privateKeyHandle.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(keyContext, RSA_PSS_SALTLEN_DIGEST), 1);
    size_t signatureSize = 0;
    ASSERT_EQ(EVP_DigestSign(context.get(), nullptr, &signatureSize,
                             reinterpret_cast<const unsigned char*>(content.data()), content.size()), 1);
    std::vector<unsigned char> legacy(signatureSize);
    ASSERT_EQ(EVP_DigestSign(context.get(), legacy.data(), &signatureSize,
                             reinterpret_cast<const unsigned char*>(content.data()), content.size()), 1);
    legacy.resize(signatureSize);
    std::ofstream output(signature, std::ios::binary);
    output.write(reinterpret_cast<const char*>(legacy.data()), static_cast<std::streamsize>(legacy.size()));
    output.close();

    const auto result = prismkey::crypto::SignatureService::verifyFileDetails(file, signature, publicKey);
    ASSERT_TRUE(result.ok()) << result.message();
    EXPECT_TRUE(result.value().legacy);
    EXPECT_EQ(result.value().algorithm, "RSA-PSS/SHA-256");
    EXPECT_TRUE(result.value().timestampUtc.empty());
}
}  // namespace
