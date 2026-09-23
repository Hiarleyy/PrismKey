#pragma once

#include <filesystem>
#include <string>

#include "core/Result.hpp"

namespace prismkey::crypto {

class HashService {
   public:
    static core::Result<std::string> file(const std::filesystem::path& file, const std::string& algorithm);
    static core::Result<std::string> sha256File(const std::filesystem::path& file);
};

}  // namespace prismkey::crypto
