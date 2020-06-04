#include "RsaKey.hpp"

#include <openssl/rsa.h>

#include <BigNumber.hpp>

#include <mylog.h>

constexpr bool DEBUG = false;

using namespace std;

namespace MyOpenSslExample {

RsaKey::RsaKey(const OpenSsl& ssl, std::uint16_t bits, Exponent exponent)
    : m_bits(bits), m_exponent(exponent), m_ssl(ssl), m_initialized(false) {}

bool RsaKey::saveToFiles(const filesystem::path& privPath,
                         const filesystem::path& pubPath) {
    auto keys = asStrings();

    if (!keys)
        return false;

    if constexpr (DEBUG)
        cout << keys->first << "\n" << keys->second << "\n";

    auto privFullPath = getAbsolutePath(privPath);
    ofstream privFile(privFullPath);
    auto pubFullPath = getAbsolutePath(pubPath);
    ofstream pubFile(pubFullPath);

    if (!pubFile.is_open() || !privFile.is_open())
        return false;

    const auto& privStr = keys->first;
    const auto& pubStr = keys->second;
    pubFile.write(pubStr.c_str(), pubStr.size());
    pubFile.close();

    privFile.write(privStr.c_str(), privStr.size());
    privFile.close();
    return true;
}

bool RsaKey::initialize() {
    BigNumber bne(m_ssl);
    bne.init();
    return initialize(bne);
}

bool RsaKey::initialize(BigNumber& bne) {
    if (m_bits > 4096L)
        return false;

    if (!bne.get())
        bne.init();

    if (!bne.get())
        return false;

    auto exponent = static_cast<int>(m_exponent);

    auto ret = bne.setWord(exponent);
    if (!ret)
        return false;

    m_rsa = unique_ptr<RSA, Deleter<RSA>>(
        m_ssl.RSA_new(), [this](RSA* r) { m_ssl.RSA_free(r); });

    if (!m_rsa)
        return false;

    return generateKey(bne);
}

bool RsaKey::generateKey(const BigNumber& bne) {
    return m_ssl.RSA_generate_key_ex(m_rsa.get(), m_bits, bne.get(), NULL);
}

filesystem::path
RsaKey::getAbsolutePath(const filesystem::__cxx11::path& relative) {
    const auto currPath = filesystem::current_path();
    return (relative.is_relative()) ? (currPath / relative) : relative;
}

std::optional<std::pair<string, string>> RsaKey::asStrings() {
    RSA* keypair = get();
    if (!keypair)
        return {};

    auto pri =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });
    auto pub =
        unique_ptr<BIO, Deleter<BIO>>(m_ssl.BIO_new(m_ssl.BIO_s_mem()),
                                      [this](auto* p) { m_ssl.BIO_vfree(p); });

    if (!pri || !pub)
        return {};

    if (m_ssl.PEM_write_bio_RSAPrivateKey(pri.get(), keypair, NULL, NULL, 0,
                                          NULL, NULL) < 1)
        return {};

    if (m_ssl.PEM_write_bio_RSAPublicKey(pub.get(), keypair) < 1)
        return {};

    int pri_len = BIO_pending(pri.get());
    int pub_len = BIO_pending(pub.get());

    if (pri_len < 1 || pub_len < 1)
        return {};

    string pri_key; // Private key
    string pub_key; // Public key
    pri_key.resize(pri_len);
    pub_key.resize(pub_len);

    if (m_ssl.BIO_read(pri.get(), pri_key.data(), pri_len) < 1)
        return {};

    if (m_ssl.BIO_read(pub.get(), pub_key.data(), pub_len) < 1)
        return {};

    return make_optional(pair{pri_key, pub_key});
}

RSA* RsaKey::get() const { return m_rsa.get(); }

std::optional<RsaKey> make_rsa_key(uint16_t keyLength,
                                   RsaKey::Exponent exponent) {
    OpenSsl ssl;
    RsaKey key{ssl, keyLength, exponent};
    if (key.initialize())
        return std::optional(std::move(key));
    return std::optional<RsaKey>();
}

} // namespace MyOpenSslExample
