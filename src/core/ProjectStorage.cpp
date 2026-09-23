#include "core/ProjectStorage.hpp"

namespace prismkey::core {
namespace {

const char* folderFor(StorageKind kind) {
    switch (kind) {
        case StorageKind::PublicKey:
            return "keys/public";
        case StorageKind::PrivateKey:
            return "keys/private";
        case StorageKind::Signature:
            return "signatures";
    }
    return "signatures";
}

}  // namespace

std::filesystem::path ProjectStorage::destination(StorageKind kind, const std::filesystem::path& source) {
    return std::filesystem::current_path() / folderFor(kind) / source.filename();
}

bool ProjectStorage::copy(StorageKind kind, const std::filesystem::path& source, bool overwrite) {
    std::error_code error;
    const auto target = destination(kind, source);
    std::filesystem::create_directories(target.parent_path(), error);
    if (error || (!overwrite && std::filesystem::exists(target))) return false;

    const auto options =
        overwrite ? std::filesystem::copy_options::overwrite_existing : std::filesystem::copy_options::none;
    std::filesystem::copy_file(source, target, options, error);
    return !error;
}

}  // namespace prismkey::core
