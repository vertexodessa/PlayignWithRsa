#include <OpenSsl.hpp>

namespace MyOpenSslExample {
RSA* OpenSsl::RSA_new() const { return ::RSA_new(); }

void OpenSsl::RSA_free(RSA* p) const { ::RSA_free(p); }

int OpenSsl::RSA_generate_key_ex(RSA* rsa, int bits, BIGNUM* e,
                                 BN_GENCB* cb) const {
    return ::RSA_generate_key_ex(rsa, bits, e, cb);
}

BIGNUM* OpenSsl::BN_new() const { return ::BN_new(); }

void OpenSsl::BN_clear_free(BIGNUM* p) const { ::BN_clear_free(p); }

int OpenSsl::BN_set_word(BIGNUM* a, unsigned long w) const {
    return ::BN_set_word(a, w);
}

const BIO_METHOD* OpenSsl::BIO_s_mem() const { return ::BIO_s_mem(); }

BIO* OpenSsl::BIO_new(const BIO_METHOD* type) const { return ::BIO_new(type); }

void OpenSsl::BIO_vfree(BIO* p) const { return ::BIO_vfree(p); }

int OpenSsl::BIO_read(BIO* b, void* buf, int len) const {
    return ::BIO_read(b, buf, len);
}

int OpenSsl::PEM_write_bio_RSAPublicKey(BIO* bp, RSA* x) const {
    return ::PEM_write_bio_RSAPublicKey(bp, x);
}

int OpenSsl::PEM_write_bio_RSAPrivateKey(BIO* bp, RSA* x, const EVP_CIPHER* enc,
                                         unsigned char* kstr, int klen,
                                         pem_password_cb* cb, void* u) const {
    return ::PEM_write_bio_RSAPrivateKey(bp, x, enc, kstr, klen, cb, u);
}
} // namespace MyOpenSslExample
