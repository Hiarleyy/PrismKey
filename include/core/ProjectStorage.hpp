#pragma once

#include <filesystem>

namespace prismkey::core {

enum class StorageKind {
    PublicKey,
    PrivateKey,
    Signature,
};

class ProjectStorage {
   public:
    static std::filesystem::path destination(StorageKind kind, const std::filesystem::path& source);
    static bool copy(StorageKind kind, const std::filesystem::path& source, bool overwrite = false);
};

}  // namespace prismkey::core
