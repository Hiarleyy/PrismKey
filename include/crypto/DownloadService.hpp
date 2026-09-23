#pragma once

#include <filesystem>
#include <string>

#include "core/Result.hpp"

namespace prismkey::crypto {

class DownloadService {
   public:
    static core::Result<void> download(const std::string& url, const std::filesystem::path& output,
                                       const std::string& expectedHash, const std::string& algorithm,
                                       const std::filesystem::path& caBundle = {});
};

}  // namespace prismkey::crypto
