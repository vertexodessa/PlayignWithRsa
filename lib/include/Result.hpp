#pragma once
#include <variant>

namespace MyOpenSslExample {

enum class Error {
    NoError = 0,
    FileAccessError,
    MemoryAllocationError,
    InvalidState,
    InvalidArguments,
    SSLBackendError
};

template <typename T> class Result {
    // safe-bool idiom - avoid integer conversions
    // https://www.artima.com/cppsource/safebool.html
    using bool_type = void (Result<T>::*)() const;
    void this_type_does_not_support_comparisons() const {}

  public:
    explicit Result(T value);
    Result(Error value);

    inline T& value();
    inline const Error& error() const;

    inline operator bool_type() const;

  private:
    inline bool hasError() const;

    std::variant<T, Error> m_result;
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

template <typename T> Result<T>::Result(T value) { m_result = value; }

template <typename T> Result<T>::Result(Error error) { m_result = error; }

template <typename T> T& Result<T>::value() { return std::get<T>(m_result); }

template <typename T> const Error& Result<T>::error() const {
    return std::get<Error>(m_result);
}

template <typename T> bool Result<T>::hasError() const {
    return std::holds_alternative<Error>(m_result) && error() != Error::NoError;
}

template <typename T> Result<T>::operator bool_type() const {
    return !hasError() ? &Result<T>::this_type_does_not_support_comparisons
                       : nullptr;
}

} // namespace MyOpenSslExample
