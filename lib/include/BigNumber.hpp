#pragma once

//#include <cstddef>
#include <functional>
#include <memory>
//#include <optional>

#include <OpenSsl.hpp>
#include <utils/Deleter.hpp>

#include <iostream>

namespace MyOpenSslExample {

using BigNumberPtr = std::unique_ptr<BIGNUM, Deleter<BIGNUM>>;

class BigNumber {
    friend class MockBigNumber;

  public:
    explicit inline BigNumber(const OpenSsl& ssl);
    virtual ~BigNumber() = default;

    inline virtual bool init();
    inline virtual BIGNUM* get() const;
    inline virtual int setWord(BN_ULONG w);

  protected:
    inline virtual BigNumberPtr newNum() const;

  private:
    const OpenSsl& m_ssl;
    BigNumberPtr m_num{nullptr};
};

BigNumber::BigNumber(const OpenSsl& ssl) : m_ssl(ssl) {}

bool BigNumber::init() {
    m_num = newNum();
    return !!m_num;
}

BIGNUM* BigNumber::get() const { return m_num.get(); }

int BigNumber::setWord(unsigned long w) {
    return m_ssl.BN_set_word(m_num.get(), w);
}

BigNumberPtr BigNumber::newNum() const {
    return BigNumberPtr(m_ssl.BN_new(),
                        [this](BIGNUM* b) { m_ssl.BN_clear_free(b); });
}

} // namespace MyOpenSslExample
