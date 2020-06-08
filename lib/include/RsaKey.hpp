#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <variant>

#include <OpenSslWrapper.hpp>
#include <Result.hpp>
#include <utils/Deleter.hpp>

// TODO: forward-declare everything and move to .cpp
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <experimental/filesystem>

using namespace std::experimental;

namespace MyOpenSslExample {

using RsaKeyPtr = std::unique_ptr<RSA, Deleter<RSA>>;

class BigNumber;

class RsaKey {
  public:
    enum class Exponent { Rsa3 = RSA_3, RsaF4 = RSA_F4 };

    RsaKey(const OpenSslWrapper& ssl, uint16_t keyLength = 1024,
           Exponent exponent = Exponent::Rsa3);

    RsaKey(RsaKey&& other);

    RsaKey(const RsaKey& other) = delete;
    virtual ~RsaKey() = default;

    uint16_t keySize() const;

    bool operator==(const RsaKey& other) const;
    bool operator!=(const RsaKey& other) const { return !(*this == other); };

    virtual std::optional<StackedError> saveToFiles(const filesystem::path& privPath,
                              const filesystem::path& pubPath);
    virtual ErrorCode readFromFile(const filesystem::path& priv);

    Result<RSA*> getKey() const;

    Result<std::pair<std::string, std::string>> asStrings() const;

    virtual ErrorCode fromPrivateKey(const std::string& privKey);
    virtual ErrorCode fromPublicKey(const std::string& privKey);

  protected:
  private:
    std::optional<StackedError> initialize() const;
    static filesystem::path getAbsolutePath(const filesystem::path& relative);

    const uint16_t m_bits;
    const Exponent m_exponent;
    const OpenSslWrapper& m_ssl;

    // FIXME: this cannot be used with move ctor
    mutable std::shared_mutex m_rsaMutex;

    mutable RsaKeyPtr m_rsa;
};

} // namespace MyOpenSslExample
