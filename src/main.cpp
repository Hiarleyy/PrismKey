#include "crypto/HashService.hpp"
#include "crypto/KeyService.hpp"
#include "crypto/SignatureService.hpp"

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {
void printUsage() {
    std::cerr << "Uso:\n"
              << "  prismkey hash <arquivo>\n"
              << "  prismkey keygen --public <arquivo.pem> --private <arquivo.pem>\n"
              << "  prismkey sign <arquivo> --key <privada.pem> --out <assinatura.sig>\n"
              << "  prismkey verify <arquivo> --signature <assinatura.sig> --key <publica.pem>\n";
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
    if (!result.ok()) { std::cerr << "Erro: " << result.message() << '\n'; return 1; }
    std::cout << successMessage << '\n';
    return 0;
}
}  // namespace

int main(int argc, char* argv[]) {
    const std::vector<std::string> arguments(argv + 1, argv + argc);
    if (arguments.empty()) { printUsage(); return 1; }
    const std::string& command = arguments.front();
    if (command == "hash") {
        if (arguments.size() != 2) { printUsage(); return 1; }
        const auto result = prismkey::crypto::HashService::sha256File(arguments[1]);
        if (!result.ok()) { std::cerr << "Erro: " << result.message() << '\n'; return 1; }
        std::cout << "SHA-256: " << result.value() << '\n';
        return 0;
    }
    if (command == "keygen") {
        const auto publicKey = optionValue(arguments, "--public");
        const auto privateKey = optionValue(arguments, "--private");
        if (!publicKey || !privateKey) { printUsage(); return 1; }
        const auto password = readPassword("Senha da chave privada: ");
        const auto confirmation = readPassword("Confirme a senha: ");
        if (!password || !confirmation || password->empty() || *password != *confirmation) {
            std::cerr << "Erro: as senhas não coincidem ou são inválidas.\n"; return 1;
        }
        return report(prismkey::crypto::KeyService::generateRsaKeyPair(*publicKey, *privateKey, *password), "Par de chaves RSA gerado com sucesso.");
    }
    if (command == "sign") {
        if (arguments.size() < 2) { printUsage(); return 1; }
        const auto key = optionValue(arguments, "--key");
        const auto output = optionValue(arguments, "--out");
        if (!key || !output) { printUsage(); return 1; }
        const auto password = readPassword("Senha da chave privada: ");
        if (!password) { std::cerr << "Erro: não foi possível ler a senha.\n"; return 1; }
        return report(prismkey::crypto::SignatureService::signFile(arguments[1], *key, *output, *password), "Arquivo assinado com sucesso.");
    }
    if (command == "verify") {
        if (arguments.size() < 2) { printUsage(); return 1; }
        const auto signature = optionValue(arguments, "--signature");
        const auto key = optionValue(arguments, "--key");
        if (!signature || !key) { printUsage(); return 1; }
        return report(prismkey::crypto::SignatureService::verifyFile(arguments[1], *signature, *key), "Assinatura válida.");
    }
    std::cerr << "Erro: comando desconhecido.\n";
    printUsage();
    return 1;
}
