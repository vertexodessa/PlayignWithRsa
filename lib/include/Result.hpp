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
  public:
    explicit Result(T value);
    Result(Error value);

    inline T& value();
    inline const Error& error() const;

    inline operator bool() const;

  private:
    inline bool hasError() const;

    std::variant<T, Error> m_result;
};

template <typename T> Result<T>::Result(T value) { m_result = value; }

template <typename T> Result<T>::Result(Error error) { m_result = error; }

template <typename T> T& Result<T>::value() { return std::get<T>(m_result); }

template <typename T> const Error& Result<T>::error() const {
    return std::get<Error>(m_result);
}

template <typename T> bool Result<T>::hasError() const {
    return std::holds_alternative<Error>(m_result) && error() != Error::NoError;
}

template <typename T> Result<T>::operator bool() const { return !hasError(); }

} // namespace MyOpenSslExample
