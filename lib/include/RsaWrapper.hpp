#pragma once

#include <cstddef>
#include <functional>
#include <memory>

// TODO: forward-declare everything and move to .cpp
#include <openssl/rsa.h>
#include <openssl/ssl.h>

namespace MyOpenSslExample {
template <class T>
using Deleter = std::function<void(T*)>;

class RsaKey {
  public:
    enum class Exponent {
        Rsa3 = RSA_3,
        RsaF4 = RSA_F4
    };

    RsaKey(std::uint16_t keyLength = 1024, Exponent exponent = Exponent::Rsa3);
    ~RsaKey() = default;

    int initialize();

  protected:
    RSA* getKey();

  private:
    const std::uint16_t m_bits;
    const Exponent m_exponent;
    bool m_initialized;
    std::unique_ptr<RSA, Deleter<RSA>> m_rsa;
};

class RsaWrapper {
  public:
    RsaWrapper();
    ~RsaWrapper();

  private:
    void initialize();
};

} // namespace MyOpenSslExample
