#include "crypto/SignatureService.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <memory>
#include <vector>

#include "core/ProjectStorage.hpp"

namespace prismkey::crypto {
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
using Ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
constexpr unsigned char magic[] = {'P', 'K', 'S', 'I', 'G', '0', '0', '1'};
bool rsa(EVP_PKEY* k) { return k && EVP_PKEY_base_id(k) == EVP_PKEY_RSA; }
bool ed(EVP_PKEY* k) { return k && EVP_PKEY_base_id(k) == EVP_PKEY_ED25519; }
core::Result<std::vector<unsigned char>> bytes(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return core::Result<std::vector<unsigned char>>::failure(
            std::filesystem::exists(p) ? core::ErrorCode::FileNotReadable : core::ErrorCode::FileNotFound,
            "Nao foi possivel ler o arquivo informado.");
    std::vector<unsigned char> v((std::istreambuf_iterator<char>(f)), {});
    return f.bad() ? core::Result<std::vector<unsigned char>>::failure(core::ErrorCode::FileNotReadable,
                                                                       "Nao foi possivel ler o arquivo informado.")
                   : core::Result<std::vector<unsigned char>>::success(std::move(v));
}
bool pss(EVP_PKEY_CTX* c, bool s) {
    return c && EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_PSS_PADDING) == 1 &&
           EVP_PKEY_CTX_set_rsa_pss_saltlen(c, s ? RSA_PSS_SALTLEN_DIGEST : RSA_PSS_SALTLEN_AUTO) == 1;
}
std::string utc() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm x{};
    gmtime_s(&x, &t);
    char b[21]{};
    std::strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &x);
    return b;
}
void u16(std::vector<unsigned char>& v, size_t n) {
    v.push_back(n >> 8);
    v.push_back(n);
}
std::vector<unsigned char> data(unsigned char a, const std::string& t, const std::vector<unsigned char>& f) {
    std::vector<unsigned char> v = {'P', 'r', 'i', 's', 'm', 'K', 'e', 'y', '-', 'v', '1', 0, a};
    u16(v, t.size());
    v.insert(v.end(), t.begin(), t.end());
    v.insert(v.end(), f.begin(), f.end());
    return v;
}
core::Result<std::vector<unsigned char>> sign(const std::vector<unsigned char>& d, EVP_PKEY* k, unsigned char a) {
    Ctx c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* pc = nullptr;
    if (!c || EVP_DigestSignInit(c.get(), &pc, a == 1 ? EVP_sha256() : nullptr, nullptr, k) != 1 ||
        (a == 1 && !pss(pc, true)))
        return core::Result<std::vector<unsigned char>>::failure(core::ErrorCode::CryptoError,
                                                                 "Falha ao inicializar a assinatura digital.");
    size_t n = 0;
    if (EVP_DigestSign(c.get(), nullptr, &n, d.data(), d.size()) != 1)
        return core::Result<std::vector<unsigned char>>::failure(core::ErrorCode::CryptoError,
                                                                 "Falha ao preparar a assinatura digital.");
    std::vector<unsigned char> s(n);
    if (EVP_DigestSign(c.get(), s.data(), &n, d.data(), d.size()) != 1)
        return core::Result<std::vector<unsigned char>>::failure(core::ErrorCode::CryptoError,
                                                                 "Falha ao finalizar a assinatura digital.");
    s.resize(n);
    return core::Result<std::vector<unsigned char>>::success(std::move(s));
}
core::Result<void> check(const std::vector<unsigned char>& d, const std::vector<unsigned char>& s, EVP_PKEY* k,
                         unsigned char a) {
    Ctx c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* pc = nullptr;
    if (!c || EVP_DigestVerifyInit(c.get(), &pc, a == 1 ? EVP_sha256() : nullptr, nullptr, k) != 1 ||
        (a == 1 && !pss(pc, false)))
        return core::Result<void>::failure(core::ErrorCode::CryptoError,
                                           "Falha ao inicializar a verificacao da assinatura.");
    return EVP_DigestVerify(c.get(), s.data(), s.size(), d.data(), d.size()) == 1
               ? core::Result<void>::success()
               : core::Result<void>::failure(core::ErrorCode::InvalidSignature, "A assinatura e invalida.");
}
}  // namespace
core::Result<void> SignatureService::signFile(const std::filesystem::path& f, const std::filesystem::path& pk,
                                              const std::filesystem::path& o, const std::string& pass) {
    Bio b(BIO_new_file(pk.string().c_str(), "rb"), BIO_free_all);
    Key k(b ? PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, const_cast<char*>(pass.c_str())) : nullptr,
          EVP_PKEY_free);
    if (!k || (!rsa(k.get()) && !ed(k.get())))
        return core::Result<void>::failure(core::ErrorCode::IncorrectPassword,
                                           "Senha incorreta ou chave privada invalida.");
    auto file = bytes(f);
    if (!file.ok()) return core::Result<void>::failure(file.errorCode(), file.message());
    auto a = rsa(k.get()) ? 1 : 2;
    auto t = utc();
    auto s = sign(data(a, t, file.value()), k.get(), a);
    if (!s.ok()) return core::Result<void>::failure(s.errorCode(), s.message());
    std::vector<unsigned char> v(magic, magic + 8);
    v.push_back(a);
    u16(v, t.size());
    v.insert(v.end(), t.begin(), t.end());
    v.insert(v.end(), s.value().begin(), s.value().end());
    const auto stored = core::ProjectStorage::destination(core::StorageKind::Signature, o);
    std::error_code error;
    std::filesystem::create_directories(stored.parent_path(), error);
    if (error)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable,
                                           "Nao foi possivel criar a pasta de assinaturas.");
    std::ofstream out(stored, std::ios::binary | std::ios::trunc);
    if (!out)
        return core::Result<void>::failure(core::ErrorCode::FileNotWritable, "Nao foi possivel gravar a assinatura.");
    out.write(reinterpret_cast<char*>(v.data()), v.size());
    return out ? core::Result<void>::success()
               : core::Result<void>::failure(core::ErrorCode::FileNotWritable, "Nao foi possivel gravar a assinatura.");
}
core::Result<SignatureDetails> SignatureService::verifyFileDetails(const std::filesystem::path& f,
                                                                   const std::filesystem::path& s,
                                                                   const std::filesystem::path& pub) {
    Bio b(BIO_new_file(pub.string().c_str(), "rb"), BIO_free_all);
    Key k(b ? PEM_read_bio_PUBKEY(b.get(), nullptr, nullptr, nullptr) : nullptr, EVP_PKEY_free);
    if (!k || (!rsa(k.get()) && !ed(k.get())))
        return core::Result<SignatureDetails>::failure(core::ErrorCode::InvalidKey, "A chave publica e invalida.");
    auto file = bytes(f), sig = bytes(s);
    if (!file.ok()) return core::Result<SignatureDetails>::failure(file.errorCode(), file.message());
    if (!sig.ok())
        return core::Result<SignatureDetails>::failure(sig.errorCode(),
                                                       "Nao foi possivel ler o arquivo de assinatura.");
    auto& v = sig.value();
    if (v.size() < 11 || !std::equal(magic, magic + 8, v.begin())) {
        if (!rsa(k.get()))
            return core::Result<SignatureDetails>::failure(core::ErrorCode::InvalidSignature,
                                                           "Assinatura legada requer chave RSA.");
        auto r = check(file.value(), v, k.get(), 1);
        return r.ok() ? core::Result<SignatureDetails>::success({"RSA-PSS/SHA-256", {}, true})
                      : core::Result<SignatureDetails>::failure(r.errorCode(), r.message());
    }
    auto a = v[8];
    size_t n = (size_t(v[9]) << 8) | v[10];
    if ((a != 1 && a != 2) || v.size() < 11 + n || ((a == 1) != rsa(k.get())))
        return core::Result<SignatureDetails>::failure(core::ErrorCode::InvalidSignature, "A assinatura e invalida.");
    std::string t(v.begin() + 11, v.begin() + 11 + n);
    std::vector<unsigned char> x(v.begin() + 11 + n, v.end());
    auto r = check(data(a, t, file.value()), x, k.get(), a);
    return r.ok() ? core::Result<SignatureDetails>::success({a == 1 ? "RSA-PSS/SHA-256" : "Ed25519", t, false})
                  : core::Result<SignatureDetails>::failure(r.errorCode(), r.message());
}
core::Result<void> SignatureService::verifyFile(const std::filesystem::path& f, const std::filesystem::path& s,
                                                const std::filesystem::path& p) {
    auto r = verifyFileDetails(f, s, p);
    return r.ok() ? core::Result<void>::success() : core::Result<void>::failure(r.errorCode(), r.message());
}
}  // namespace prismkey::crypto
