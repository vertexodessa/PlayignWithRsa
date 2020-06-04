#pragma once

#include <openssl/ssl.h>

namespace MyOpenSslExample {
class OpenSsl {
  public:
    virtual RSA* RSA_new() const;
    virtual void RSA_free(RSA*) const;

    virtual BIGNUM* BN_new() const;
    virtual void BN_clear_free(BIGNUM*) const;
    virtual int BN_set_word(BIGNUM* a, BN_ULONG w) const;
};
} // namespace MyOpenSslExample
