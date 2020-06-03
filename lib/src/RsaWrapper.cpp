#include "RsaWrapper.hpp"

#include <openssl/rsa.h>

using namespace std;

namespace MyOpenSslExample {

RsaWrapper::RsaWrapper() {}

RsaWrapper::~RsaWrapper() {}

RsaKey::RsaKey(std::uint16_t bits, Exponent exponent)
    : m_bits(bits), m_exponent(exponent), m_initialized(false) {}

int RsaKey::initialize() {
    auto bne = unique_ptr<BIGNUM, Deleter<BIGNUM>>(
        BN_new(), [](BIGNUM* b) { BN_clear_free(b); });
    auto exponent = static_cast<int>(m_exponent);
    auto ret = BN_set_word(bne.get(), exponent);

    m_rsa =
        unique_ptr<RSA, Deleter<RSA>>(RSA_new(), [](RSA* r) { RSA_free(r); });
    ret = RSA_generate_key_ex(m_rsa.get(), m_bits, bne.get(), NULL);

    // error checking
}

} // namespace MyOpenSslExample
