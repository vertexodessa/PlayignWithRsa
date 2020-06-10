#include <BigNumber.hpp>

#include <OpenSslWrapper.hpp>

#include <mutex>

using namespace  std;

namespace MyOpenSslExample {

BigNumber::BigNumber(const OpenSslWrapper& ssl) : m_ssl(ssl) {}

bool BigNumber::init() const {
    unique_lock lock(m_ptrMutex);
    m_num = BigNumberPtr(m_ssl.BN_new(),
                         [this](BIGNUM* b) { m_ssl.BN_clear_free(b); });
    return !!m_num;
}

BIGNUM* BigNumber::get() const {
    shared_lock lock(m_ptrMutex);
    if(!m_num)
    {
        lock.unlock();
        init();
    }
    return m_num.get(); }

int BigNumber::setWord(unsigned long w) {
    shared_lock lock(m_ptrMutex);
    return m_ssl.BN_set_word(m_num.get(), w);
}

} // namespace MyOpenSslExample
