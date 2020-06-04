#pragma once

#include <openssl/ssl.h>

namespace MyOpenSslExample {
class OpenSsl {
  public:
    virtual RSA* RSA_new() const;
    virtual void RSA_free(RSA*) const;

    virtual int RSA_generate_key_ex(RSA* rsa, int bits, BIGNUM* e,
                                    BN_GENCB* cb) const;

    virtual BIGNUM* BN_new() const;
    virtual void BN_clear_free(BIGNUM*) const;
    virtual int BN_set_word(BIGNUM* a, BN_ULONG w) const;

    virtual const BIO_METHOD* BIO_s_mem(void) const;
    virtual BIO* BIO_new(const BIO_METHOD* type) const;
    virtual void BIO_vfree(BIO* p) const;
    virtual int BIO_read(BIO* b, void* buf, int len) const;

    virtual int PEM_write_bio_RSAPublicKey(BIO* bp, RSA* x) const;
    virtual int PEM_write_bio_RSAPrivateKey(BIO* bp, RSA* x,
                                            const EVP_CIPHER* enc,
                                            unsigned char* kstr, int klen,
                                            pem_password_cb* cb, void* u) const;
};
} // namespace MyOpenSslExample
