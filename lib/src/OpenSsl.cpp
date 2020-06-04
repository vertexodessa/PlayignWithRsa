#include <OpenSsl.hpp>

namespace MyOpenSslExample {
RSA* OpenSsl::RSA_new() const { return ::RSA_new(); }

void OpenSsl::RSA_free(RSA* p) const { ::RSA_free(p); }

BIGNUM* OpenSsl::BN_new() const { return ::BN_new(); }

void OpenSsl::BN_clear_free(BIGNUM* p) const { ::BN_clear_free(p); }

int OpenSsl::BN_set_word(BIGNUM* a, unsigned long w) const {
    return ::BN_set_word(a, w);
}
} // namespace MyOpenSslExample
