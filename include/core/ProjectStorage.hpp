#pragma once
#include <filesystem>
namespace prismkey::core { enum class StorageKind { PublicKey, PrivateKey, Signature }; class ProjectStorage { public: static std::filesystem::path destination(StorageKind, const std::filesystem::path&); static bool copy(StorageKind, const std::filesystem::path&, bool overwrite = false); }; }
