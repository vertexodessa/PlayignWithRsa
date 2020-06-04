#include "RsaKey.hpp"

#include <openssl/rsa.h>

#include <BigNumber.hpp>

using namespace std;

namespace MyOpenSslExample {

RsaKey::RsaKey(const OpenSsl& ssl, std::uint16_t bits, Exponent exponent)
    : m_bits(bits), m_exponent(exponent), m_ssl(ssl), m_initialized(false) {}

bool RsaKey::initialize() {
    BigNumber bne(m_ssl);
    bne.init();
    return initialize(bne);
}

bool RsaKey::initialize(BigNumber& bne) {
    if (m_bits > 4096)
        return false;

    if(!bne.get())
        bne.init();

    if(!bne.get())
        return false;

    auto exponent = static_cast<int>(m_exponent);

    auto ret = bne.setWord(exponent);
    if (!ret)
        return false;

    m_rsa = unique_ptr<RSA, Deleter<RSA>>(RSA_new(),
                                          [](RSA* r) { RSA_free(r); });

    if (!m_rsa)
        return false;

    return generateKey(bne);
}

bool RsaKey::generateKey(const BigNumber& bne) {
    return RSA_generate_key_ex(m_rsa.get(), m_bits, bne.get(), NULL);
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
