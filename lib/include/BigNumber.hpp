#pragma once

#include <functional>
#include <memory>
#include <shared_mutex>

#include <utils/Deleter.hpp>

namespace MyOpenSslExample {
class OpenSslWrapper;

using BigNumberPtr = std::unique_ptr<BIGNUM, Deleter<BIGNUM>>;

class BigNumber {
    friend class MockBigNumber;

  public:
    explicit BigNumber(const OpenSslWrapper& ssl);
    virtual ~BigNumber() = default;

    BIGNUM* get() const;
    int setWord(BN_ULONG w);

  private:
    bool init() const;
    const OpenSslWrapper& m_ssl;
    mutable std::shared_mutex m_ptrMutex;
    mutable BigNumberPtr m_num{nullptr};
};

} // namespace MyOpenSslExample
