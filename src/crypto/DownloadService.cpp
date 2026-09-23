#include "crypto/DownloadService.hpp"

#include <curl/curl.h>
#include <openssl/evp.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>

namespace prismkey::crypto {
namespace {
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using CurlUrl = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>;

struct Transfer {
    std::ofstream output;
    EVP_MD_CTX* digest = nullptr;
    bool writeFailed = false;
};

bool initializeCurl() {
    static std::once_flag once;
    static CURLcode result = CURLE_FAILED_INIT;
    std::call_once(once, [] { result = curl_global_init(CURL_GLOBAL_DEFAULT); });
    return result == CURLE_OK;
}

std::string uppercase(std::string value) {
    for (char& character : value) character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    return value;
}

const EVP_MD* digestFor(const std::string& algorithm) {
    const auto normalized = uppercase(algorithm);
    if (normalized == "SHA256" || normalized == "SHA-256") return EVP_sha256();
    if (normalized == "SHA512" || normalized == "SHA-512") return EVP_sha512();
    if (normalized == "SHA3-256") return EVP_sha3_256();
    if (normalized == "BLAKE2B512" || normalized == "BLAKE2B-512") return EVP_blake2b512();
    return nullptr;
}

bool isHexHash(const std::string& hash, std::size_t expectedLength) {
    return hash.size() == expectedLength &&
           std::all_of(hash.begin(), hash.end(), [](unsigned char character) { return std::isxdigit(character) != 0; });
}

std::string hexDigest(EVP_MD_CTX* context) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context, digest.data(), &length) != 1) return {};
    std::ostringstream value;
    value << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < length; ++index) value << std::setw(2) << static_cast<unsigned>(digest[index]);
    return value.str();
}

size_t writeData(char* data, size_t size, size_t count, void* userData) {
    auto* transfer = static_cast<Transfer*>(userData);
    const auto length = size * count;
    if (!transfer || !transfer->output.write(data, static_cast<std::streamsize>(length)) ||
        EVP_DigestUpdate(transfer->digest, data, length) != 1) {
        if (transfer) transfer->writeFailed = true;
        return 0;
    }
    return length;
}

bool isHttpsUrl(const std::string& value) {
    CurlUrl parsed(curl_url(), curl_url_cleanup);
    if (!parsed || curl_url_set(parsed.get(), CURLUPART_URL, value.c_str(), 0) != CURLUE_OK) return false;
    char* scheme = nullptr;
    char* host = nullptr;
    const bool valid = curl_url_get(parsed.get(), CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
                       curl_url_get(parsed.get(), CURLUPART_HOST, &host, 0) == CURLUE_OK && scheme && host &&
                       uppercase(scheme) == "HTTPS" && *host != '\0';
    curl_free(scheme);
    curl_free(host);
    return valid;
}
}  // namespace

core::Result<void> DownloadService::download(const std::string& url, const std::filesystem::path& output,
                                             const std::string& expectedHash, const std::string& algorithm,
                                             const std::filesystem::path& caBundle) {
    if (!initializeCurl())
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao inicializar o cliente HTTPS.");
    if (!isHttpsUrl(url))
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument, "A URL deve usar HTTPS.");
    const EVP_MD* digestAlgorithm = digestFor(algorithm);
    if (!digestAlgorithm)
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument, "Algoritmo de hash nao suportado.");
    const auto digestLength = static_cast<std::size_t>(EVP_MD_get_size(digestAlgorithm)) * 2;
    if (!isHexHash(expectedHash, digestLength))
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument, "O hash esperado e invalido para o algoritmo.");
    if (output.empty())
        return core::Result<void>::failure(core::ErrorCode::InvalidArgument, "Informe o arquivo de destino.");

    const auto directory = output.has_parent_path() ? output.parent_path() : std::filesystem::path{"."};
    std::error_code filesystemError;
    std::filesystem::create_directories(directory, filesystemError);
    if (filesystemError || std::filesystem::exists(output))
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "O arquivo de destino nao pode ser preparado.");
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto temporary = directory / (output.filename().string() + ".prismkey-" + suffix + ".tmp");
    struct TemporaryFile {
        std::filesystem::path path;
        bool keep = false;
        ~TemporaryFile() {
            if (!keep) {
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
            }
        }
    } temporaryFile{temporary};

    DigestContext digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    Transfer transfer{std::ofstream(temporary, std::ios::binary | std::ios::trunc), digest.get()};
    if (!digest || !transfer.output || EVP_DigestInit_ex(digest.get(), digestAlgorithm, nullptr) != 1)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "Nao foi possivel preparar o arquivo temporario.");
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl)
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao inicializar o download HTTPS.");
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeData);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &transfer);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    const auto caBundleName = caBundle.string();
    if (!caBundle.empty()) curl_easy_setopt(curl.get(), CURLOPT_CAINFO, caBundleName.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl.get(), CURLOPT_REDIR_PROTOCOLS_STR, "https");
    const auto curlResult = curl_easy_perform(curl.get());
    transfer.output.close();
    if (curlResult != CURLE_OK || transfer.writeFailed)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "O download HTTPS falhou e o arquivo temporario foi removido.");
    const auto calculatedHash = hexDigest(digest.get());
    if (calculatedHash.empty())
        return core::Result<void>::failure(core::ErrorCode::CryptoError, "Falha ao calcular o hash do download.");
    if (uppercase(calculatedHash) != uppercase(expectedHash))
        return core::Result<void>::failure(core::ErrorCode::InvalidSignature,
                                           "O hash do download nao corresponde ao valor esperado.");
    std::filesystem::rename(temporary, output, filesystemError);
    if (filesystemError)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "Nao foi possivel disponibilizar o arquivo validado.");
    temporaryFile.keep = true;
    return core::Result<void>::success();
}

}  // namespace prismkey::crypto
