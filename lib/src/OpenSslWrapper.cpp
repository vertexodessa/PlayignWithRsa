#include <OpenSslWrapper.hpp>

#include <openssl/err.h>

namespace MyOpenSslExample {
RSA* OpenSslWrapper::RSA_new() const { return ::RSA_new(); }

void OpenSslWrapper::RSA_free(RSA* p) const { ::RSA_free(p); }

int OpenSslWrapper::RSA_generate_key_ex(RSA* rsa, int bits, BIGNUM* e,
                                        BN_GENCB* cb) const {
    return ::RSA_generate_key_ex(rsa, bits, e, cb);
}

BIGNUM* OpenSslWrapper::BN_new() const { return ::BN_new(); }

void OpenSslWrapper::BN_clear_free(BIGNUM* p) const { ::BN_clear_free(p); }

int OpenSslWrapper::BN_set_word(BIGNUM* a, unsigned long w) const {
    return ::BN_set_word(a, w);
}

const BIO_METHOD* OpenSslWrapper::BIO_s_mem() const { return ::BIO_s_mem(); }

BIO* OpenSslWrapper::BIO_new(const BIO_METHOD* type) const {
    return ::BIO_new(type);
}

void OpenSslWrapper::BIO_vfree(BIO* p) const { return ::BIO_vfree(p); }

int OpenSslWrapper::BIO_read(BIO* b, void* buf, int len) const {
    return ::BIO_read(b, buf, len);
}

int OpenSslWrapper::BIO_write(BIO* b, const void* buf, int len) const {
    return ::BIO_write(b, buf, len);
}

int OpenSslWrapper::PEM_write_bio_RSAPublicKey(BIO* bp, RSA* x) const {
    return ::PEM_write_bio_RSAPublicKey(bp, x);
}

int OpenSslWrapper::PEM_write_bio_RSAPrivateKey(BIO* bp, RSA* x,
                                                const EVP_CIPHER* enc,
                                                unsigned char* kstr, int klen,
                                                pem_password_cb* cb,
                                                void* u) const {
    return ::PEM_write_bio_RSAPrivateKey(bp, x, enc, kstr, klen, cb, u);
}

RSA* OpenSslWrapper::PEM_read_bio_RSAPrivateKey(BIO* bp, RSA** x,
                                                pem_password_cb* cb,
                                                void* u) const {
    return ::PEM_read_bio_RSAPrivateKey(bp, x, cb, u);
}

RSA* OpenSslWrapper::EVP_PKEY_get1_RSA(EVP_PKEY* pkey) const {
    return ::EVP_PKEY_get1_RSA(pkey);
}

void OpenSslWrapper::RSA_get0_key(const RSA* r, const BIGNUM** n,
                                  const BIGNUM** e, const BIGNUM** d) const {
    return ::RSA_get0_key(r, n, e, d);
}

int OpenSslWrapper::BN_cmp(const BIGNUM* a, const BIGNUM* b) const {
    return ::BN_cmp(a, b);
}

int OpenSslWrapper::RSA_public_encrypt(int flen, const unsigned char* from,
                                       unsigned char* to, RSA* rsa,
                                       int padding) const {
    return ::RSA_public_encrypt(flen, from, to, rsa, padding);
}

int OpenSslWrapper::RSA_private_decrypt(int flen, const unsigned char* from,
                                        unsigned char* to, RSA* rsa,
                                        int padding) const {
    return ::RSA_private_decrypt(flen, from, to, rsa, padding);
}

RSA* OpenSslWrapper::PEM_read_bio_RSAPublicKey(BIO* bp, RSA** x,
                                               pem_password_cb* cb,
                                               void* u) const {
    return ::PEM_read_bio_RSAPublicKey(bp, x, cb, u);
}

void OpenSslWrapper::ERR_error_string_n(unsigned long e, char* buf,
                                        size_t len) const {
    return ::ERR_error_string_n(e, buf, len);
}

unsigned long OpenSslWrapper::ERR_get_error() const {
    return ::ERR_get_error();
}

long OpenSslWrapper::BIO_ctrl(BIO* bp, int cmd, long larg, void* parg) const {
    return ::BIO_ctrl(bp, cmd, larg, parg);
}

} // namespace MyOpenSslExample
