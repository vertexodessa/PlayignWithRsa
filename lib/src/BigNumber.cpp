#include <BigNumber.hpp>

#include <OpenSslWrapper.hpp>

namespace MyOpenSslExample {

BigNumber::BigNumber(const OpenSslWrapper& ssl) : m_ssl(ssl) {}

bool BigNumber::init() {
    m_num = BigNumberPtr(m_ssl.BN_new(),
                         [this](BIGNUM* b) { m_ssl.BN_clear_free(b); });
    return !!m_num;
}

BIGNUM* BigNumber::get() const { return m_num.get(); }

int BigNumber::setWord(unsigned long w) {
    return m_ssl.BN_set_word(m_num.get(), w);
}

} // namespace MyOpenSslExample
