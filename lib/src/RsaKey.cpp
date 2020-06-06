#include "RsaKey.hpp"

#include <BigNumber.hpp>

#include <fstream>
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

ErrorCode RsaKey::saveToFiles(const filesystem::path& privPath,
                          const filesystem::path& pubPath) {
    auto keys = asStrings();

    if (!keys)
        return keys.error();

    if constexpr (DEBUG)
        cout << keys.value().first << "\n" << keys.value().second << "\n";

    ofstream privFile(getAbsolutePath(privPath));
    ofstream pubFile(getAbsolutePath(pubPath));

    if (!pubFile.is_open() || !privFile.is_open())
        return ErrorCode::FileAccessError;

    const auto& [privStr, pubStr] = keys.value();
    pubFile.write(pubStr.c_str(), pubStr.size());
    pubFile.close();

    privFile.write(privStr.c_str(), privStr.size());
    privFile.close();
    return ErrorCode::NoError;
}

ErrorCode RsaKey::readFromFile(const filesystem::path& priv) {
    ifstream privFile(getAbsolutePath(priv));

    if (!privFile.is_open()) {
        return ErrorCode::FileAccessError;
    }

    std::string privStr((std::istreambuf_iterator<char>(privFile)),
                        std::istreambuf_iterator<char>());

    if (privStr.empty()) {
        return ErrorCode::InvalidInput;
    }

    auto ret = fromPrivateKey(privStr);
    if (ret != ErrorCode::NoError)
        return ret;

    return m_rsa.get() ? ErrorCode::NoError : ErrorCode::InvalidState;
}

ErrorCode RsaKey::initialize() const {
    BigNumber bne(m_ssl);
    if (!bne.init())
        return ErrorCode::MemoryAllocationError;

    return initialize(bne);
}

ErrorCode RsaKey::initialize(BigNumber& bne) const {
    ErrorCode ret = ErrorCode::NoError;

    std::call_once(m_initOnce, [&ret, &bne, this]() {
        if (m_bits > 4096L) {
            ret = ErrorCode::InvalidState;
            return;
        }

        if (!bne.get()) {
            if (!bne.init()) {
                ret = ErrorCode::InvalidArguments;
                return;
            }
        }

        auto exponent = static_cast<int>(m_exponent);

        if (!bne.setWord(exponent)) {
            ret = ErrorCode::InvalidArguments;
            return;
        }

        m_rsa =
            RsaKeyPtr(m_ssl.RSA_new(), [this](RSA* r) { m_ssl.RSA_free(r); });

        if (!m_rsa) {
            ret = ErrorCode::MemoryAllocationError;
            return;
        }

        ret = (m_ssl.RSA_generate_key_ex(m_rsa.get(), m_bits, bne.get(), NULL)
                   ? ErrorCode::NoError
                   : ErrorCode::SSLBackendError);
    });
    return ret;
}

filesystem::path RsaKey::getAbsolutePath(const filesystem::path& relative) {
    const auto currPath = filesystem::current_path();
    return (relative.is_relative()) ? (currPath / relative) : relative;
}

Result<std::pair<string, string>> RsaKey::asStrings() const {
    Result<RSA*> keypair = getKey();
    if (!keypair)
        return keypair.error();

    auto pri =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });
    auto pub =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!pri || !pub)
        return ErrorCode::MemoryAllocationError;

    if (m_ssl.PEM_write_bio_RSAPrivateKey(pri.get(), keypair.value(), NULL,
                                          NULL, 0, NULL, NULL) < 1)
        return ErrorCode::SSLBackendError;

    if (m_ssl.PEM_write_bio_RSAPublicKey(pub.get(), keypair.value()) < 1)
        return ErrorCode::SSLBackendError;

    int pri_len = BIO_pending(pri.get());
    int pub_len = BIO_pending(pub.get());

    if (pri_len < 1 || pub_len < 1)
        return ErrorCode::SSLBackendError;

    string pri_key; // Private key
    string pub_key; // Public key
    pri_key.resize(pri_len);
    pub_key.resize(pub_len);

    if (m_ssl.BIO_read(pri.get(), pri_key.data(), pri_len) < 1)
        return ErrorCode::SSLBackendError;

    if (m_ssl.BIO_read(pub.get(), pub_key.data(), pub_len) < 1)
        return ErrorCode::SSLBackendError;

    return Result(pair{pri_key, pub_key});
}

ErrorCode RsaKey::fromPrivateKey(const std::string& privKey) {
    auto bo =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!m_ssl.BIO_write(bo.get(), privKey.data(), privKey.size()))
        return ErrorCode::MemoryAllocationError;

    RSA* rsa = RSA_new();
    if (!rsa)
        return ErrorCode::MemoryAllocationError;

    if (!m_ssl.PEM_read_bio_RSAPrivateKey(bo.get(), &rsa, 0, 0))
        return ErrorCode::InvalidArguments;

    m_rsa = Ptr<RSA>(rsa, [this](auto* r) { m_ssl.RSA_free(r); });

    if (!m_rsa)
        return ErrorCode::MemoryAllocationError;

    return m_rsa ? ErrorCode::NoError : ErrorCode::InvalidState;
}

ErrorCode RsaKey::fromPublicKey(const string& pubKey) {
    auto bo =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!m_ssl.BIO_write(bo.get(), pubKey.data(), pubKey.size()))
        return ErrorCode::MemoryAllocationError;

    RSA* rsa = RSA_new();
    ;
    if (!rsa)
        return ErrorCode::MemoryAllocationError;

    if (!m_ssl.PEM_read_bio_RSAPublicKey(bo.get(), &rsa, 0, 0))
        return ErrorCode::InvalidArguments;

    m_rsa = Ptr<RSA>(rsa, [this](auto* r) { m_ssl.RSA_free(r); });
    return m_rsa ? ErrorCode::NoError : ErrorCode::InvalidState;
}

Result<RSA*> RsaKey::getKey() const {
    auto ret = ErrorCode::NoError;

    if (!m_rsa)
        ret = initialize();

    if (ret != ErrorCode::NoError)
        return ret;

    return Result{m_rsa.get()};
}
} // namespace MyOpenSslExample
