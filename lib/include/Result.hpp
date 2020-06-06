#pragma once
#include <functional>
#include <sstream>
#include <variant>

namespace MyOpenSslExample {

// TODO: Error should save file and line where it happened
// TODO: it should be stacked

enum class ErrorCode {
    NoError = 0,
    FileAccessError,
    MemoryAllocationError,
    InvalidState,
    InvalidArguments,
    InvalidInput,
    SSLBackendError,
    EncryptionError
};

struct ErrDesc {
    ErrorCode err{ErrorCode::NoError};
    std::string description{"Empty description"};
    std::string file{"File Unassigned"};
    int line{-1};
};

class Error {
  public:
    Error(const ErrDesc& desc) { m_stack.emplace_back(desc); }
    Error(Error&& stack, const ErrDesc& desc) {
        m_stack.reserve(stack.m_stack.size() + 1);

        for (auto e = std::rbegin(stack.m_stack); e != std::rend(stack.m_stack);
             ++e) {
            m_stack.emplace_back(std::move(*e));
        }

        m_stack.push_back(desc);
    }

    std::string asText() {
        std::stringstream ss;
        for (auto i = std::rbegin(m_stack); i != std::rend(m_stack); ++i) {
            ss << i->file << ":" << i->line << ": " << i->description << "\n";
        }
        return ss.str();
    }

  private:
    std::vector<ErrDesc> m_stack;
};

template <typename T> class Result {
    // safe-bool idiom - avoid integer conversions
    // https://www.artima.com/cppsource/safebool.html
    static void this_type_does_not_support_comparisons() {}
    using bool_type =
        decltype(&Result<T>::this_type_does_not_support_comparisons);

  public:
    explicit Result(T value);

    // cppcheck-suppress  noExplicitConstructor
    Result(ErrorCode error);

    inline T& value();
    inline const ErrorCode& error() const;

    inline operator bool_type() const;
    inline T& operator->() const;
    inline T& operator*() const;

  private:
    inline bool hasError() const;

    std::variant<T, ErrorCode> m_result;
};

template <typename T, typename Other>
bool operator!=(const Result<T> lhs, const Other& rhs) {
    lhs.this_type_does_not_support_comparisons();
    return false;
}

template <typename T, typename Other>
bool operator==(const Result<T> lhs, const Other& rhs) {
    lhs.this_type_does_not_support_comparisons();
    return false;
}

template <typename T> Result<T>::Result(T value) : m_result(value) {}

template <typename T> Result<T>::Result(ErrorCode error) : m_result(error) {}

template <typename T> T& Result<T>::value() { return std::get<T>(m_result); }

template <typename T> const ErrorCode& Result<T>::error() const {
    static const auto ret{ErrorCode::NoError};
    return std::holds_alternative<ErrorCode>(m_result)
               ? std::get<ErrorCode>(m_result)
               : ret;
}

template <typename T> T& Result<T>::operator->() const { return value(); }

template <typename T> T& Result<T>::operator*() const { return value(); }

template <typename T> bool Result<T>::hasError() const {
    return std::holds_alternative<ErrorCode>(m_result) &&
           error() != ErrorCode::NoError;
}

template <typename T> Result<T>::operator bool_type() const {
    return (!hasError() ? &Result<T>::this_type_does_not_support_comparisons
                        : nullptr);
}

} // namespace MyOpenSslExample
