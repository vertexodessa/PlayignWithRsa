#pragma once

#include <functional>
#include <memory>

#include <utils/Deleter.hpp>

#include <iostream>

namespace MyOpenSslExample {
class OpenSslWrapper;

using BigNumberPtr = std::unique_ptr<BIGNUM, Deleter<BIGNUM>>;

class BigNumber {
    friend class MockBigNumber;

  public:
    explicit BigNumber(const OpenSslWrapper& ssl);
    virtual ~BigNumber() = default;

    virtual bool init();
    virtual BIGNUM* get() const;
    virtual int setWord(BN_ULONG w);

  private:
    const OpenSslWrapper& m_ssl;
    BigNumberPtr m_num{nullptr};
};

} // namespace MyOpenSslExample
