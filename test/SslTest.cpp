#include <BigNumber.hpp>
#include <RsaEngine.hpp>
#include <RsaKey.hpp>

#include <utils/Deleter.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <iostream>
#include <memory>

using namespace std;
using namespace testing;
using namespace MyOpenSslExample;

constexpr char privName[]{"./priv.key"};
constexpr char pubName[]{"./pub.key"};

constexpr auto privKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQDXAW7AXMYXltS7VoF2QPomOPzr4S5gXVwQILwyEwo2BJkxBDHz\n\
KYiYLUo9NLTPCSAP/5oGZk/vWz1+DxIoo0uHePEv7Zt7ffpeJD9F3rDHtrIbbMVh\n\
Z70k5HSxDqEqNBYvvXGP0IK5yFtHcNxXnehyheu1QqkVL773Ma35w0wKTQIBAwKB\n\
gQCPVknVky66ZI3SOaukK1Fu0KidQMmVk5K1ayghYgbOrbt2Asv3cQW6yNwozc3f\n\
W2q1VRFZmYqfkij+tLbFwjJZFvTHgLje3baqlhIDyTrbkZ7R+PQ4yXVJB44OKKdR\n\
pWG4JdHBTkfaVeH99ew0FezrZA2CXYRJspSIQhCQ4wc0KwJBAPypD45gy5iFTK8h\n\
9otkZ0/+fasetVIDsslFx5rVfIth0vY3xd8aAcoCpii9heOdGw6LwQsVfUW0YGPo\n\
k4JH0B0CQQDZ2PUeJWGY4xGUAkmldBcMRWLMOFbniYSP2dQ20LMwociOfyf7/PB9\n\
haRXPIOZZ/ZhS7CrTSleK8pqrIzseWvxAkEAqHC1CZXdEFjdyhakXO2aNVRTx2nO\n\
Nq0h24PaZzj9skE3Ts/ZP2ar3AHEGykD7RNnXwfWB2Oo2SLq7UW3rC/gEwJBAJE7\n\
ThQY67tCC7gBhm5NZLLY7Iglj0UGWF/mjXngd3XBMF7/b/1TSv5ZGDooV7uapEDd\n\
IHIzcOlyhvHIXfL7nUsCQDgpPEMZ4y7VkLR3wl8E081XvGtmA+ETsM0ipwPDLOhe\n\
xm2HOptY8p6yh9V4jGk5MU3BpJp0Jw47rqVTWgBLDtc=\n\
-----END RSA PRIVATE KEY-----\n";

constexpr auto invalidPrivKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQDXAW7AXMYXltS7VoF2QPomOPzr4S5gXVwQILwyEwo2BJkxBDHz\n\
KYiYLUo9NLTPCSAP/5oGZk/vWz1+DxIoo0uHePEv7Zt7ffpeJD9F3rDHtrIbbMVh\n\
Z70k5HSxDqEqNBYvvXGP0IK5yFtHcNxXnehyheu1QqkVL773Ma35w0wKTQIBAwKB\n\
gQCPVknVky66ZI3SOaukK1Fu0KidQMmVk5K1ayghYgbOrbt2Asv3cQW6yNwozc3f\n\
W2q1VRFZmYqfkij+tLbFwjJZFvTHgLje3baqlhIDyTrbkZ7R+PQ4yXVJB44OKKdR\n\
pWG4JdHBTkfaVeH99ew0FezrZA2CXYRJspSIQhCQ4wc0KwJBAPypD45gy5iFTK8h\n\
9otkZ0/+fasetVIDsslFx5rVfIth0vY3xd8aAcoCpii9heOdGw6LwQsVfUW0YGPo\n\
0000000000000000000000000000000000000000000000000000000000000000\n\
haRXPIOZZ/ZhS7CrTSleK8pqrIzseWvxAkEAqHC1CZXdEFjdyhakXO2aNVRTx2nO\n\
Nq0h24PaZzj9skE3Ts/ZP2ar3AHEGykD7RNnXwfWB2Oo2SLq7UW3rC/gEwJBAJE7\n\
ThQY67tCC7gBhm5NZLLY7Iglj0UGWF/mjXngd3XBMF7/b/1TSv5ZGDooV7uapEDd\n\
IHIzcOlyhvHIXfL7nUsCQDgpPEMZ4y7VkLR3wl8E081XvGtmA+ETsM0ipwPDLOhe\n\
xm2HOptY8p6yh9V4jGk5MU3BpJp0Jw47rqVTWgBLDtc=\n\
-----END RSA PRIVATE KEY-----\n";

const string pubKey = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIGHAoGBANcBbsBcxheW1LtWgXZA+iY4/OvhLmBdXBAgvDITCjYEmTEEMfMpiJgt\n\
Sj00tM8JIA//mgZmT+9bPX4PEiijS4d48S/tm3t9+l4kP0XesMe2shtsxWFnvSTk\n\
dLEOoSo0Fi+9cY/QgrnIW0dw3Fed6HKF67VCqRUvvvcxrfnDTApNAgED\n\
-----END RSA PUBLIC KEY-----\n";

constexpr char smallText[]{"test"};

constexpr char largeText[]{
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest"
    "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttestte"
    "sttest"};

#define FORWARD_TO_BASE(x)                                                     \
    ON_CALL(*this, x).WillByDefault(                                           \
        [this](auto... args) { return base_type::x(args...); });

class MockOpenSslWrapper : public OpenSslWrapper {
  public:
    using base_type = OpenSslWrapper;

    MOCK_METHOD(RSA*, RSA_new, (), (const, override));
    MOCK_METHOD(void, RSA_free, (RSA*), (const, override));

    MOCK_METHOD(int, RSA_generate_key_ex,
                (RSA * rsa, int bits, BIGNUM* e, BN_GENCB* cb),
                (const, override));

    MOCK_METHOD(BIGNUM*, BN_new, (), (const, override));
    MOCK_METHOD(void, BN_clear_free, (BIGNUM*), (const, override));
    MOCK_METHOD(int, BN_set_word, (BIGNUM * a, BN_ULONG w), (const, override));

    MOCK_METHOD(const BIO_METHOD*, BIO_s_mem, (), (const, override));
    MOCK_METHOD(BIO*, BIO_new, (const BIO_METHOD* type), (const, override));
    MOCK_METHOD(void, BIO_vfree, (BIO * p), (const, override));
    MOCK_METHOD(int, BIO_read, (BIO * b, void* buf, int len),
                (const, override));
    MOCK_METHOD(int, BIO_write, (BIO * b, const void* buf, int len),
                (const, override));

    MOCK_METHOD(int, PEM_write_bio_RSAPublicKey, (BIO * bp, RSA* x),
                (const, override));
    MOCK_METHOD(int, PEM_write_bio_RSAPrivateKey,
                (BIO * bp, RSA* x, const EVP_CIPHER* enc, unsigned char* kstr,
                 int klen, pem_password_cb* cb, void* u),
                (const, override));
    MOCK_METHOD(RSA*, PEM_read_bio_RSAPrivateKey,
                (BIO * bp, RSA** x, pem_password_cb* cb, void* u),
                (const, override));
    MOCK_METHOD(RSA*, EVP_PKEY_get1_RSA, (EVP_PKEY * pkey), (const, override));

    MOCK_METHOD(void, RSA_get0_key,
                (const RSA* r, const BIGNUM** n, const BIGNUM** e,
                 const BIGNUM** d),
                (const, override));
    MOCK_METHOD(int, BN_cmp, (const BIGNUM* a, const BIGNUM* b),
                (const, override));
    MOCK_METHOD(int, RSA_public_encrypt,
                (int flen, const unsigned char* from, unsigned char* to,
                 RSA* rsa, int padding),
                (const, override));
    MOCK_METHOD(int, RSA_private_decrypt,
                (int flen, const unsigned char* from, unsigned char* to,
                 RSA* rsa, int padding),
                (const, override));
    MOCK_METHOD(RSA*, PEM_read_bio_RSAPublicKey,
                (BIO * bp, RSA** x, pem_password_cb* cb, void* u),
                (const, override));
    MOCK_METHOD(void, ERR_error_string_n,
                (unsigned long e, char* buf, size_t len), (const, override));
    MOCK_METHOD(unsigned long, ERR_get_error, (), (const, override));
    MOCK_METHOD(long, BIO_ctrl, (BIO * bp, int cmd, long larg, void* parg),
                (const, override));

    MockOpenSslWrapper() {
        FORWARD_TO_BASE(RSA_new);
        FORWARD_TO_BASE(RSA_free);
        FORWARD_TO_BASE(RSA_generate_key_ex);

        FORWARD_TO_BASE(BN_new);
        FORWARD_TO_BASE(BN_clear_free);
        FORWARD_TO_BASE(BN_set_word);

        FORWARD_TO_BASE(BIO_s_mem);
        FORWARD_TO_BASE(BIO_new);
        FORWARD_TO_BASE(BIO_vfree);
        FORWARD_TO_BASE(BIO_read);
        FORWARD_TO_BASE(BIO_write);

        FORWARD_TO_BASE(PEM_write_bio_RSAPublicKey);
        FORWARD_TO_BASE(PEM_write_bio_RSAPrivateKey);
        FORWARD_TO_BASE(PEM_read_bio_RSAPrivateKey);
        FORWARD_TO_BASE(EVP_PKEY_get1_RSA);

        FORWARD_TO_BASE(RSA_get0_key);

        FORWARD_TO_BASE(BN_cmp);
        FORWARD_TO_BASE(RSA_public_encrypt);
        FORWARD_TO_BASE(RSA_private_decrypt);
        FORWARD_TO_BASE(PEM_read_bio_RSAPublicKey);
        FORWARD_TO_BASE(ERR_error_string_n);
        FORWARD_TO_BASE(ERR_get_error);
        FORWARD_TO_BASE(BIO_ctrl);
    }
};

TEST(BigNumber, InitSequence) {
    MockOpenSslWrapper ssl;
    BigNumber bn(ssl);
    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);

    ASSERT_TRUE(!!bn.get());
}

TEST(RsaKey, CorrectRsaKeyInitialization) {
    MockOpenSslWrapper ssl;

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), RSA_3)).Times(1);
    EXPECT_CALL(ssl, RSA_new()).Times(1);
    EXPECT_CALL(ssl, RSA_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);

    RsaKey key(ssl);

    auto res = key.getKey();
    ASSERT_TRUE(res);
    ASSERT_TRUE(!!res.value());
}

TEST(RsaKey, DifferentKeyIsGeneratedEachTime) {
    MockOpenSslWrapper ssl;
    RsaKey key1(ssl);
    RsaKey key2(ssl);

    EXPECT_CALL(ssl, RSA_new()).Times(2);
    EXPECT_CALL(ssl, RSA_free(NotNull())).Times(2);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), RSA_3)).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);
    auto keyPtr1 = key1.getKey();
    ASSERT_TRUE(keyPtr1);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), RSA_3)).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);

    auto keyPtr2 = key2.getKey();
    ASSERT_TRUE(keyPtr2);
    ASSERT_NE(keyPtr1.value(), keyPtr2.value());
}

TEST(RsaKey, CorrectKeySaveToFile) {
    MockOpenSslWrapper ssl;
    RsaKey key(ssl);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), RSA_3)).Times(1);

    EXPECT_CALL(ssl, RSA_new()).Times(1);
    EXPECT_CALL(ssl, RSA_free(_)).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);

    auto res = key.getKey();
    ASSERT_TRUE(res);
    ASSERT_TRUE(!!res.value());

    EXPECT_CALL(ssl, BIO_s_mem()).Times(2);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(2);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(2);

    EXPECT_CALL(ssl, BIO_read(_, _, 247)).Times(1);
    EXPECT_CALL(ssl, BIO_read(_, _, 887)).Times(1);

    EXPECT_CALL(
        ssl, PEM_write_bio_RSAPrivateKey(NotNull(), NotNull(), _, _, 0, _, _))
        .Times(1);
    EXPECT_CALL(ssl, PEM_write_bio_RSAPublicKey(NotNull(), NotNull())).Times(1);

    EXPECT_CALL(ssl, BIO_ctrl(NotNull(), 10, 0, NULL)).Times(2);
    ASSERT_FALSE(key.saveToFiles(privName, pubName));
    // check file sizes
    ASSERT_EQ(filesystem::file_size(privName), 887);
    ASSERT_EQ(filesystem::file_size(pubName), 247);
}

TEST(RsaKey, CorrectKeySaveAndReadFromFile) {
    MockOpenSslWrapper ssl;
    RsaKey key(ssl);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), 3)).Times(1);
    EXPECT_CALL(ssl, RSA_new()).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);

    auto res = key.getKey();
    ASSERT_TRUE(res);
    ASSERT_TRUE(!!res.value());

    EXPECT_CALL(ssl, BIO_s_mem()).Times(3);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(3);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(3);

    EXPECT_CALL(
        ssl, PEM_write_bio_RSAPrivateKey(NotNull(), NotNull(), 0, 0, 0, 0, 0))
        .Times(1);
    EXPECT_CALL(ssl, PEM_write_bio_RSAPublicKey(NotNull(), NotNull())).Times(1);
    EXPECT_CALL(ssl, BIO_read(NotNull(), NotNull(), 887)).Times(1);
    EXPECT_CALL(ssl, BIO_read(NotNull(), NotNull(), 247)).Times(1);

    EXPECT_CALL(ssl, BIO_ctrl(NotNull(), 10, 0, NULL)).Times(2);
    ASSERT_FALSE(key.saveToFiles(privName, pubName));

    // check file sizes
    ASSERT_EQ(filesystem::file_size(privName), 887);
    ASSERT_EQ(filesystem::file_size(pubName), 247);

    EXPECT_CALL(ssl, PEM_read_bio_RSAPrivateKey(NotNull(), 0, 0, 0)).Times(1);
    EXPECT_CALL(ssl, RSA_free(NotNull())).Times(2);
    EXPECT_CALL(ssl, BIO_write(NotNull(), NotNull(), 887)).Times(1);
    RsaKey otherKey(ssl);

    EXPECT_CALL(ssl, RSA_get0_key(_, _, _, _)).Times(2);
    EXPECT_CALL(ssl, BN_cmp(_, _)).Times(3);

    ASSERT_FALSE(otherKey.readPrivateKeyFromFile(privName));
    ASSERT_EQ(key, otherKey);
}

TEST(RsaEngine, Encrypt) {
    MockOpenSslWrapper ssl;
    RsaEngine engine(ssl);

    vector<unsigned char> in(begin(smallText), end(smallText));

    RsaKey key(ssl);
    EXPECT_CALL(ssl, BIO_s_mem()).Times(1);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(1);
    EXPECT_CALL(ssl, BIO_write(NotNull(), NotNull(), 247)).Times(1);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(1);

    EXPECT_CALL(ssl, PEM_read_bio_RSAPublicKey(NotNull(), 0, 0, 0)).Times(1);
    ASSERT_FALSE(key.fromPublicKey(pubKey));

    RsaKey key2(ssl);
    EXPECT_CALL(ssl, BIO_s_mem()).Times(1);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(1);
    EXPECT_CALL(ssl, BIO_write(NotNull(), NotNull(), 887)).Times(1);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(1);
    EXPECT_CALL(ssl, PEM_read_bio_RSAPrivateKey(NotNull(), 0, 0, 0)).Times(1);
    EXPECT_CALL(ssl, RSA_get0_key(_, _, _, _)).Times(2);
    EXPECT_CALL(ssl, RSA_public_encrypt(5, _, _, _, 1)).Times(1);

    ASSERT_FALSE(key2.fromPrivateKey(privKey));

    auto val = engine.publicEncrypt(key, in);
    ASSERT_TRUE(val);
    ASSERT_NE(key, key2);

    EXPECT_CALL(ssl, RSA_private_decrypt(128, _, _, _, 1)).Times(1);
    auto decrypted = engine.privateDecrypt(key2, val.value());
    ASSERT_TRUE(decrypted);
    ASSERT_EQ(string(begin(decrypted.value()), end(decrypted.value())),
              string(begin(smallText), end(smallText)));

    EXPECT_CALL(ssl, RSA_free(NotNull())).Times(2);
}

TEST(RsaEngine, InvalidPrivKey) {
    MockOpenSslWrapper ssl;

    RsaKey key2(ssl);
    EXPECT_CALL(ssl, BIO_s_mem()).Times(1);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(1);
    EXPECT_CALL(ssl, BIO_write(NotNull(), NotNull(), 887)).Times(1);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(1);
    EXPECT_CALL(ssl, PEM_read_bio_RSAPrivateKey(NotNull(), 0, 0, 0)).Times(1);

    EXPECT_CALL(ssl, ERR_get_error()).Times(1);
    EXPECT_CALL(ssl, ERR_error_string_n(_, _, 1024)).Times(1);

    auto err = key2.fromPrivateKey(invalidPrivKey);
    ASSERT_TRUE(err);

    const char errStr[] =
        "error:0D07207B:asn1 encoding routines:ASN1_get_object:header too long "
        "- unable to parse rsa key";
    ASSERT_NE(err->asText().find(errStr), string::npos);
}

TEST(RsaEngine, EncryptLargeFile) {
    MockOpenSslWrapper ssl;
    RsaEngine engine(ssl);

    vector<unsigned char> in(begin(largeText), end(largeText));

    RsaKey key(ssl);

    EXPECT_CALL(ssl, BIO_s_mem()).Times(1);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(1);
    EXPECT_CALL(ssl, BIO_write(NotNull(), NotNull(), 247)).Times(1);
    EXPECT_CALL(ssl, PEM_read_bio_RSAPublicKey(NotNull(), 0, 0, 0)).Times(1);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(1);

    ASSERT_FALSE(key.fromPublicKey(pubKey));

    RsaKey key2(ssl);

    EXPECT_CALL(ssl, BIO_s_mem()).Times(1);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(1);
    EXPECT_CALL(ssl, BIO_write(NotNull(), NotNull(), 887)).Times(1);
    EXPECT_CALL(ssl, PEM_read_bio_RSAPrivateKey(NotNull(), 0, 0, 0)).Times(1);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(1);

    ASSERT_FALSE(key2.fromPrivateKey(privKey));

    EXPECT_CALL(ssl, RSA_get0_key(_, _, _, _)).Times(2);
    ASSERT_NE(key, key2);

    EXPECT_CALL(ssl, RSA_public_encrypt(117, _, _, _, 1)).Times(34);
    EXPECT_CALL(ssl, RSA_public_encrypt(19, _, _, _, 1)).Times(1);
    EXPECT_CALL(ssl, RSA_free(NotNull())).Times(2);

    auto val = engine.publicEncrypt(key, in);
    ASSERT_TRUE(val);

    EXPECT_CALL(ssl, RSA_private_decrypt(128, _, _, _, 1)).Times(35);
    auto decrypted = engine.privateDecrypt(key2, val.value());
    ASSERT_TRUE(decrypted);
    ASSERT_EQ(string(begin(decrypted.value()), end(decrypted.value())),
              string(begin(largeText), end(largeText)));
}
