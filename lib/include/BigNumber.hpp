#pragma once

#include <functional>
#include <memory>

#include <utils/Deleter.hpp>

#include <iostream>

namespace MyOpenSslExample {
class OpenSsl;

using BigNumberPtr = std::unique_ptr<BIGNUM, Deleter<BIGNUM>>;

class BigNumber {
    friend class MockBigNumber;

  public:
    explicit BigNumber(const OpenSsl& ssl);
    virtual ~BigNumber() = default;

    virtual bool init();
    virtual BIGNUM* get() const;
    virtual int setWord(BN_ULONG w);

  private:
    const OpenSsl& m_ssl;
    BigNumberPtr m_num{nullptr};
};

} // namespace MyOpenSslExample
