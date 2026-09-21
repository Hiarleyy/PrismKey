#pragma once

#include <string>
#include <utility>

namespace prismkey::core {

enum class ErrorCode {
    FileNotFound,
    FileNotReadable,
    FileNotWritable,
    InvalidKey,
    IncorrectPassword,
    InvalidSignature,
    CryptoError,
    InvalidArgument
};

template <typename T>
class Result {
public:
    static Result success(T value) { return Result(std::move(value)); }
    static Result failure(ErrorCode code, std::string message) {
        return Result(code, std::move(message));
    }

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] const T& value() const { return value_; }
    [[nodiscard]] T& value() { return value_; }
    [[nodiscard]] ErrorCode errorCode() const noexcept { return errorCode_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

private:
    explicit Result(T value) : ok_(true), value_(std::move(value)) {}
    Result(ErrorCode code, std::string message) : ok_(false), errorCode_(code), message_(std::move(message)) {}

    bool ok_ = false;
    T value_{};
    ErrorCode errorCode_ = ErrorCode::CryptoError;
    std::string message_;
};

template <>
class Result<void> {
public:
    static Result success() { return Result(true, ErrorCode::CryptoError, {}); }
    static Result failure(ErrorCode code, std::string message) { return Result(false, code, std::move(message)); }

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] ErrorCode errorCode() const noexcept { return errorCode_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

private:
    Result(bool ok, ErrorCode code, std::string message) : ok_(ok), errorCode_(code), message_(std::move(message)) {}

    bool ok_;
    ErrorCode errorCode_;
    std::string message_;
};

}  // namespace prismkey::core
