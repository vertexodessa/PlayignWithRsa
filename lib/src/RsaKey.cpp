#include "RsaKey.hpp"

#include <BigNumber.hpp>
#include <utils/SslError.hpp>

#include <fstream>
#include <openssl/err.h>
#include <openssl/rsa.h>

constexpr bool DEBUG = false;

using namespace std;

namespace MyOpenSslExample {

RsaKey::RsaKey(const OpenSslWrapper& ssl, std::uint16_t bits, Exponent exponent)
    : m_bits(bits), m_exponent(exponent), m_ssl(ssl) {}

RsaKey::RsaKey(RsaKey&& other)
    : m_bits(other.m_bits), m_exponent(other.m_exponent),
      m_ssl(std::move(other.m_ssl)), m_rsa(move(other.m_rsa)) /*,
               m_initOnce(std::move(other.m_initOnce))*/
{}

uint16_t RsaKey::keySize() const { return m_bits; }

bool RsaKey::operator==(const RsaKey& other) const {
    const BIGNUM *n1, *e1, *d1;
    const BIGNUM *n2, *e2, *d2;

    shared_lock lock(m_rsaMutex);
    if (!m_rsa || !other.m_rsa)
        return false;

    m_ssl.RSA_get0_key(m_rsa.get(), &n1, &e1, &d1);
    m_ssl.RSA_get0_key(other.m_rsa.get(), &n2, &e2, &d2);

    const auto all = [](auto... args) { return (args && ...); };

    if (!all(n1, n2, e1, e2, d1, d2))
        return false;

    return !m_ssl.BN_cmp(n1, n2) && !m_ssl.BN_cmp(e1, e2) &&
           !m_ssl.BN_cmp(d1, d2);
}

std::optional<StackedError>
RsaKey::saveToFiles(const filesystem::path& privPath,
                    const filesystem::path& pubPath) {
    auto keys = asStrings();

    if (!keys) {
        return ADD_ERROR(keys.error(), ErrorCode::InvalidState,
                         "Could not convert key to strings");
    }

    if constexpr (DEBUG)
        cout << keys.value().first << "\n" << keys.value().second << "\n";

    ofstream privFile(getAbsolutePath(privPath));
    ofstream pubFile(getAbsolutePath(pubPath));

    if (!pubFile.is_open() || !privFile.is_open())
        return MAKE_ERROR(ErrorCode::FileAccessError, "could not open file");

    const auto& [privStr, pubStr] = keys.value();
    pubFile.write(pubStr.c_str(), pubStr.size());
    pubFile.close();

    privFile.write(privStr.c_str(), privStr.size());
    privFile.close();
    return {};
}

std::optional<StackedError> RsaKey::readFromFile(const filesystem::path& priv) {
    ifstream privFile(getAbsolutePath(priv));

    if (!privFile.is_open()) {
        return MAKE_ERROR(ErrorCode::FileAccessError,
                          "Unable to open file " + priv.string());
    }

    std::string privStr((std::istreambuf_iterator<char>(privFile)),
                        std::istreambuf_iterator<char>());

    if (privStr.empty()) {
        return MAKE_ERROR(ErrorCode::InvalidInput, "file content is empty");
    }

    auto ret = fromPrivateKey(privStr);
    if (ret)
        return ADD_ERROR(*ret, ErrorCode::InvalidState, "");

    shared_lock lock(m_rsaMutex);
    return m_rsa.get()
               ? std::optional<StackedError>{}
               : MAKE_ERROR(ErrorCode::InvalidState, "m_rsa is not valid");
}

optional<StackedError> RsaKey::initialize() const {
    optional<StackedError> ret{};

    if (m_bits > 4096L) {
        return MAKE_ERROR(ErrorCode::InvalidState,
                          "Bit value should be < 4096");
    }

    BigNumber bne(m_ssl);
    if (!bne.init())
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          "unable to init bignumber");
    if (!bne.get()) {
        if (!bne.init()) {
            return MAKE_ERROR(ErrorCode::InvalidArguments,
                              "Unable to init bignumber");
        }
    }

    auto exponent = static_cast<int>(m_exponent);

    if (!bne.setWord(exponent)) {
        return MAKE_ERROR(ErrorCode::InvalidArguments,
                          "Unable to set big number");
    }

    {
        unique_lock lock(m_rsaMutex);
        // while we were creating bigNumber, another thread could've already
        // initialized the rsa, so we need to double-check it under lock
        if (!m_rsa)
            m_rsa = RsaKeyPtr(m_ssl.RSA_new(),
                              [this](RSA* r) { m_ssl.RSA_free(r); });
    }
    shared_lock lock(m_rsaMutex);

    if (!m_rsa) {
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          "Unable to allocate rsa");
    }

    ret = (m_ssl.RSA_generate_key_ex(m_rsa.get(), m_bits, bne.get(), NULL)
               ? optional<StackedError>{}
               : MAKE_ERROR(ErrorCode::SSLBackendError,
                            "Unable to generate key"));
    return ret;
}

filesystem::path RsaKey::getAbsolutePath(const filesystem::path& relative) {
    const auto currPath = filesystem::current_path();
    return (relative.is_relative()) ? (currPath / relative) : relative;
}

Result<std::pair<string, string>> RsaKey::asStrings() const {
    Result<RSA*> keypair = getKey();
    if (!keypair)
        return ADD_ERROR(keypair.error(), ErrorCode::InvalidState,
                         "unable to get valid key");

    auto pri =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });
    auto pub =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!pri || !pub)
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          "unable to allocate memory for keys");

    if (m_ssl.PEM_write_bio_RSAPrivateKey(pri.get(), keypair.value(), NULL,
                                          NULL, 0, NULL, NULL) < 1) {
        char buf[1024];
        ERR_error_string_n(ERR_get_error(), buf, 1024);
        return MAKE_ERROR(ErrorCode::SSLBackendError, buf);
    }

    if (m_ssl.PEM_write_bio_RSAPublicKey(pub.get(), keypair.value()) < 1) {
        char buf[1024];
        ERR_error_string_n(ERR_get_error(), buf, 1024);
        return MAKE_ERROR(ErrorCode::SSLBackendError, buf);
    }

    int pri_len = BIO_pending(pri.get());
    int pub_len = BIO_pending(pub.get());

    if (pri_len < 1 || pub_len < 1)
        return MAKE_ERROR(ErrorCode::SSLBackendError,
                          "unable to read from bio");

    string pri_key; // Private key
    string pub_key; // Public key
    pri_key.resize(pri_len);
    pub_key.resize(pub_len);

    if (m_ssl.BIO_read(pri.get(), pri_key.data(), pri_len) < 1)
        return MAKE_ERROR(ErrorCode::SSLBackendError,
                          "unable to read from bio");

    if (m_ssl.BIO_read(pub.get(), pub_key.data(), pub_len) < 1)
        return MAKE_ERROR(ErrorCode::SSLBackendError,
                          "unable to read from bio");

    return Result(pair{pri_key, pub_key});
}

std::optional<StackedError> RsaKey::fromPrivateKey(const std::string& privKey) {
    auto bo =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!m_ssl.BIO_write(bo.get(), privKey.data(), privKey.size()))
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          getLastSslError(m_ssl));

    RSA* rsa = m_ssl.RSA_new();

    if (!rsa)
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          "unable to allocate memory for RSA");

    if (!m_ssl.PEM_read_bio_RSAPrivateKey(bo.get(), &rsa, 0, 0)) {
        m_ssl.RSA_free(rsa);
        return MAKE_ERROR(ErrorCode::InvalidArguments,
                          getLastSslError(m_ssl) +
                              " - unable to parse rsa key");
    }

    {
        unique_lock lock(m_rsaMutex);
        m_rsa = Ptr<RSA>(rsa, [this](auto* r) { m_ssl.RSA_free(r); });
    }
    shared_lock lock(m_rsaMutex);

    if (!m_rsa)
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          getLastSslError(m_ssl) +
                              " unable to allocate memory for RSA");

    return optional<StackedError>{};
}

std::optional<StackedError> RsaKey::fromPublicKey(const string& pubKey) {
    auto bo =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!m_ssl.BIO_write(bo.get(), pubKey.data(), pubKey.size()))
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          getLastSslError(m_ssl));

    RSA* rsa = m_ssl.RSA_new();

    if (!rsa)
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          "unable to allocate memory for RSA");

    if (!m_ssl.PEM_read_bio_RSAPublicKey(bo.get(), &rsa, 0, 0)) {
        m_ssl.RSA_free(rsa);
        return MAKE_ERROR(ErrorCode::InvalidArguments,
                          getLastSslError(m_ssl) +
                              " - unable to parse rsa key");
    }

    {
        unique_lock lock(m_rsaMutex);
        m_rsa = Ptr<RSA>(rsa, [this](auto* r) { m_ssl.RSA_free(r); });
    }

    shared_lock lock(m_rsaMutex);
    if (!m_rsa)
        return MAKE_ERROR(ErrorCode::MemoryAllocationError,
                          getLastSslError(m_ssl) +
                              " unable to allocate memory for RSA");

    return optional<StackedError>{};
}

Result<RSA*> RsaKey::getKey() const {
    shared_lock lock(m_rsaMutex);
    if (!m_rsa) {
        lock.unlock();
        if (auto ret = initialize(); ret) {
            return ADD_ERROR(*ret, ErrorCode::InvalidState,
                             "unable to initialize key");
        }
    }

    return Result{m_rsa.get()};
}
} // namespace MyOpenSslExample
