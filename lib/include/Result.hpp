#pragma once
#include <functional>
#include <sstream>
#include <variant>

namespace MyOpenSslExample {

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

static inline std::string to_string(const ErrorCode& code) {
#define F(x)                                                                   \
    case ErrorCode::x:                                                         \
        return std::string(#x);

    switch (code) {
        F(NoError)
        F(FileAccessError)
        F(MemoryAllocationError)
        F(InvalidState)
        F(InvalidArguments)
        F(InvalidInput)
        F(SSLBackendError)
        F(EncryptionError)
    default:
        return {};
    }
#undef F
}

struct ErrDesc {
    ErrorCode err{ErrorCode::NoError};
    std::string description{"Empty description"};
    std::string file{"File Unassigned"};
    int line{-1};
};

class StackedError {
  public:
    StackedError(ErrDesc desc) { m_stack.emplace_back(std::move(desc)); }
    StackedError(StackedError&& stack, const ErrDesc& desc) {
        m_stack.reserve(stack.m_stack.size() + 1);

        for (auto e = std::rbegin(stack.m_stack); e != std::rend(stack.m_stack);
             ++e) {
            m_stack.emplace_back(std::move(*e));
        }

        m_stack.push_back(desc);
    }
    StackedError(const StackedError& other) { m_stack = other.m_stack; }

    std::string asText() const {
        std::stringstream ss;
        for (auto i = std::rbegin(m_stack); i != std::rend(m_stack); ++i) {
            ss << i->file << ":" << i->line << ": " << to_string(i->err) << ": "
               << i->description << "\n";
        }
        return ss.str();
    }

    ErrorCode lastErrorCode() const { return m_stack.front().err; }

  private:
    std::vector<ErrDesc> m_stack;
};

#define MAKE_ERROR(code, desc)                                                 \
    StackedError(ErrDesc{code, desc, __FILE__, __LINE__})
#define ADD_ERROR(error, code, desc)                                           \
    StackedError(std::move(error), ErrDesc{code, desc, __FILE__, __LINE__})

template <typename T> class Result {
    // safe-bool idiom - avoid integer conversions
    // https://www.artima.com/cppsource/safebool.html
    static void this_type_does_not_support_comparisons() {}
    using bool_type =
        decltype(&Result<T>::this_type_does_not_support_comparisons);

  public:
    explicit Result(T value);

    // cppcheck-suppress  noExplicitConstructor
    Result(StackedError errorCode);

    inline T& value();
    inline ErrorCode errorCode() const;
    inline StackedError error() const;

    inline operator bool_type() const;
    inline T* operator->();
    inline const T& operator*() const;

  private:
    inline bool hasError() const;

    std::variant<T, StackedError> m_result;
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

template <typename T> Result<T>::Result(StackedError error) : m_result(error) {}

template <typename T> T& Result<T>::value() { return std::get<T>(m_result); }

template <typename T> ErrorCode Result<T>::errorCode() const {
    auto ret{ErrorCode::NoError};
    if (std::holds_alternative<StackedError>(m_result))
        ret = std::get<StackedError>(m_result).lastErrorCode();
    return ret;
}

template <typename T> StackedError Result<T>::error() const {
    auto ret{MAKE_ERROR(ErrorCode::NoError, "no error")};
    if (std::holds_alternative<StackedError>(m_result))
        ret = std::get<StackedError>(m_result);
    return ret;
}

template <typename T> T* Result<T>::operator->() { return &value(); }

template <typename T> const T& Result<T>::operator*() const { return value(); }

template <typename T> bool Result<T>::hasError() const {
    return std::holds_alternative<StackedError>(m_result);
}

template <typename T> Result<T>::operator bool_type() const {
    return (!hasError() ? &Result<T>::this_type_does_not_support_comparisons
                        : nullptr);
}

} // namespace MyOpenSslExample
