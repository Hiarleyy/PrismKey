#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "crypto/HashService.hpp"
#include "crypto/DownloadService.hpp"
#include "crypto/KeyService.hpp"
#include "crypto/SignatureService.hpp"

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {
void printUsage() {
    std::cerr << "Uso:\n"
              << "  prismkey hash <arquivo> [--algorithm SHA256|SHA512|SHA3-256|BLAKE2b512]\n"
              << "  prismkey keygen [--algorithm RSA|ED25519] --public <arquivo.pem> --private <arquivo.pem>\n"
              << "  prismkey sign <arquivo> --key <privada.pem> --out <assinatura.sig>\n"
              << "  prismkey verify <arquivo> --signature <assinatura.sig> --key <publica.pem>\n"
              << "  prismkey download <url-https> --out <arquivo> --hash <hash-esperado> "
                 "--algorithm SHA-256|SHA-512|SHA3-256|BLAKE2b-512\n";
}

std::optional<std::string> optionValue(const std::vector<std::string>& arguments, const std::string& option) {
    for (size_t index = 0; index < arguments.size(); ++index) {
        if (arguments[index] == option) {
            if (index + 1 >= arguments.size() || arguments[index + 1].starts_with("--")) return std::nullopt;
            return arguments[index + 1];
        }
    }
    return std::nullopt;
}

std::optional<std::string> readPassword(const char* prompt) {
    std::cerr << prompt;
    std::string password;
#ifdef _WIN32
    for (int character = _getch(); character != '\r' && character != '\n'; character = _getch()) {
        if (character == 3) return std::nullopt;
        if (character == '\b') {
            if (!password.empty()) password.pop_back();
        } else if (character >= 32 && character <= 126) {
            password.push_back(static_cast<char>(character));
        }
    }
#else
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) return std::nullopt;
    termios hidden = original;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden) != 0) return std::nullopt;
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &original);
#endif
    std::cerr << '\n';
    return password;
}

int report(const prismkey::core::Result<void>& result, const char* successMessage) {
    if (!result.ok()) {
        std::cerr << "Erro: " << result.message() << '\n';
        return 1;
    }
    std::cout << successMessage << '\n';
    return 0;
}
}  // namespace

int main(int argc, char* argv[]) {
    const std::vector<std::string> arguments(argv + 1, argv + argc);
    if (arguments.empty()) {
        printUsage();
        return 1;
    }
    const std::string& command = arguments.front();
    if (command == "hash") {
        if (arguments.size() != 2 && arguments.size() != 4) {
            printUsage();
            return 1;
        }
        const auto algorithm = optionValue(arguments, "--algorithm").value_or("SHA256");
        const auto result = prismkey::crypto::HashService::file(arguments[1], algorithm);
        if (!result.ok()) {
            std::cerr << "Erro: " << result.message() << '\n';
            return 1;
        }
        std::cout << algorithm << ": " << result.value() << '\n';
        return 0;
    }
    if (command == "keygen") {
        const auto publicKey = optionValue(arguments, "--public");
        const auto privateKey = optionValue(arguments, "--private");
        if (!publicKey || !privateKey) {
            printUsage();
            return 1;
        }
        const auto algorithmValue = optionValue(arguments, "--algorithm").value_or("RSA");
        if (algorithmValue != "RSA" && algorithmValue != "ED25519") {
            std::cerr << "Erro: algoritmo invalido.\n";
            printUsage();
            return 1;
        }
        const auto algorithm =
            algorithmValue == "RSA" ? prismkey::crypto::KeyAlgorithm::Rsa : prismkey::crypto::KeyAlgorithm::Ed25519;
        const auto password = readPassword("Senha da chave privada: ");
        const auto confirmation = readPassword("Confirme a senha: ");
        if (!password || !confirmation || password->empty() || *password != *confirmation) {
            std::cerr << "Erro: as senhas não coincidem ou são inválidas.\n";
            return 1;
        }
        return report(prismkey::crypto::KeyService::generateKeyPair(*publicKey, *privateKey, *password, algorithm),
                      "Par de chaves gerado com sucesso.");
    }
    if (command == "download") {
        if (arguments.size() != 8) {
            printUsage();
            return 1;
        }
        const auto output = optionValue(arguments, "--out");
        const auto hash = optionValue(arguments, "--hash");
        const auto algorithm = optionValue(arguments, "--algorithm");
        if (!output || !hash || !algorithm) {
            printUsage();
            return 1;
        }
        return report(prismkey::crypto::DownloadService::download(arguments[1], *output, *hash, *algorithm),
                      "Download e validacao concluidos com sucesso.");
    }
    if (command == "sign") {
        if (arguments.size() < 2) {
            printUsage();
            return 1;
        }
        const auto key = optionValue(arguments, "--key");
        const auto output = optionValue(arguments, "--out");
        if (!key || !output) {
            printUsage();
            return 1;
        }
        const auto password = readPassword("Senha da chave privada: ");
        if (!password) {
            std::cerr << "Erro: não foi possível ler a senha.\n";
            return 1;
        }
        return report(prismkey::crypto::SignatureService::signFile(arguments[1], *key, *output, *password),
                      "Arquivo assinado com sucesso.");
    }
    if (command == "verify") {
        if (arguments.size() < 2) {
            printUsage();
            return 1;
        }
        const auto signature = optionValue(arguments, "--signature");
        const auto key = optionValue(arguments, "--key");
        if (!signature || !key) {
            printUsage();
            return 1;
        }
        const auto details = prismkey::crypto::SignatureService::verifyFileDetails(arguments[1], *signature, *key);
        if (!details.ok()) {
            std::cerr << "Erro: " << details.message() << '\n';
            return 1;
        }
        std::cout << "Assinatura valida. Algoritmo: " << details.value().algorithm;
        if (details.value().legacy)
            std::cout << " | Assinatura legada sem timestamp";
        else
            std::cout << " | Timestamp UTC: " << details.value().timestampUtc;
        std::cout << '\n';
        return 0;
    }
    std::cerr << "Erro: comando desconhecido.\n";
    printUsage();
    return 1;
}
