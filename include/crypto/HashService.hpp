#pragma once

#include "core/Result.hpp"

#include <filesystem>
#include <string>

namespace prismkey::crypto {

class HashService {
public:
    static core::Result<std::string> sha256File(const std::filesystem::path& file);
};

}  // namespace prismkey::crypto
