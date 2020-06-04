#pragma once

//#include <cstddef>
#include <functional>
#include <memory>
//#include <optional>

// TODO: forward-declare everything and move to .cpp
#include <openssl/rsa.h>
//#include <openssl/ssl.h>

#include <utils/Deleter.hpp>

#include <iostream>

namespace MyOpenSslExample {

using BigNumberPtr = std::unique_ptr<BIGNUM, Deleter<BIGNUM>>;

class BigNumber {
    friend class MockBigNumber;
  public:
    inline BigNumber() = default;
    virtual ~BigNumber() = default;

    inline virtual bool init();
    inline virtual BIGNUM* get() const;
    inline virtual int setWord(BN_ULONG w);

  protected:
    inline virtual BigNumberPtr newNum() const;

  private:
    BigNumberPtr m_num{nullptr};
};

bool BigNumber::init() {
    m_num = newNum();
    return !!m_num;
}

BIGNUM* BigNumber::get() const { return m_num.get(); }

int BigNumber::setWord(unsigned long w) { return BN_set_word(m_num.get(), w); }

BigNumberPtr BigNumber::newNum() const {
    return BigNumberPtr(BN_new(), [](BIGNUM* b) { BN_clear_free(b); });
}

} // namespace MyOpenSslExample
