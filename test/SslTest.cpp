#include <iostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <utils/Deleter.hpp>

#include <BigNumber.hpp>
#include <RsaKey.hpp>

using namespace std;
using namespace testing;
using namespace MyOpenSslExample;

#define FORWARD_TO_BASE(x)                                                     \
    ON_CALL(*this, x).WillByDefault(                                           \
        [this](auto... args) { return base_type::x(args...); });

class MockOpenSsl : public OpenSsl {
  public:
    using base_type = OpenSsl;

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

    MOCK_METHOD(int, PEM_write_bio_RSAPublicKey, (BIO * bp, RSA* x),
                (const, override));
    MOCK_METHOD(int, PEM_write_bio_RSAPrivateKey,
                (BIO * bp, RSA* x, const EVP_CIPHER* enc, unsigned char* kstr,
                 int klen, pem_password_cb* cb, void* u),
                (const, override));

    MockOpenSsl() {
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

        FORWARD_TO_BASE(PEM_write_bio_RSAPublicKey);
        FORWARD_TO_BASE(PEM_write_bio_RSAPrivateKey);
    }
};

class MockBigNumber : public BigNumber {
  public:
    using base_type = BigNumber;

    MOCK_METHOD(bool, init, (), (override));
    MOCK_METHOD(BIGNUM*, get, (), (const, override));
    MOCK_METHOD(int, setWord, (BN_ULONG), (override));

    MockBigNumber(const OpenSsl& ssl) : BigNumber(ssl) {
        FORWARD_TO_BASE(init);
        FORWARD_TO_BASE(get);
        FORWARD_TO_BASE(setWord);
    }
};

TEST(BigNumber, InitSequence) {
    MockOpenSsl ssl;
    MockBigNumber bn(ssl);
    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, get()).Times(1);

    ASSERT_TRUE(bn.init());
    ASSERT_TRUE(!!bn.get());
}

TEST(RsaKey, CorrectRsaKeyInitialization) {
    MockOpenSsl ssl;
    MockBigNumber bn(ssl);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), RSA_3)).Times(1);

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, get()).Times(3);
    EXPECT_CALL(bn, setWord(RSA_3)).Times(1);

    ASSERT_TRUE(bn.init());

    EXPECT_CALL(ssl, RSA_new()).Times(1);
    EXPECT_CALL(ssl, RSA_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);

    RsaKey key(ssl);
    ASSERT_TRUE(key.initialize(bn));
    ASSERT_TRUE(!!key.get());
}

static int fileSize(const filesystem::path& p){
    return filesystem::file_size(p);
}

TEST(RsaKey, CorrectKeySaveToFile) {
    MockOpenSsl ssl;
    MockBigNumber bn(ssl);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(NotNull())).Times(1);
    EXPECT_CALL(ssl, BN_set_word(NotNull(), RSA_3)).Times(1);

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, get()).Times(3);
    EXPECT_CALL(bn, setWord(RSA_3)).Times(1);

    ASSERT_TRUE(bn.init());

    EXPECT_CALL(ssl, RSA_new()).Times(1);
    EXPECT_CALL(ssl, RSA_free(_)).Times(1);
    EXPECT_CALL(ssl, RSA_generate_key_ex(NotNull(), 1024, NotNull(), NULL))
        .Times(1);

    RsaKey key(ssl);
    ASSERT_TRUE(key.initialize(bn));
    ASSERT_TRUE(!!key.get());

    EXPECT_CALL(ssl, BIO_s_mem()).Times(2);
    EXPECT_CALL(ssl, BIO_new(NotNull())).Times(2);
    EXPECT_CALL(ssl, BIO_vfree(NotNull())).Times(2);

    EXPECT_CALL(ssl, BIO_read(_, _, 247)).Times(1);
    EXPECT_CALL(ssl, BIO_read(_, _, 887)).Times(1);

    EXPECT_CALL(ssl, PEM_write_bio_RSAPrivateKey(NotNull(), NotNull(), _, _, 0, _, _)).Times(1);
    EXPECT_CALL(ssl, PEM_write_bio_RSAPublicKey(NotNull(), NotNull())).Times(1);

    ASSERT_TRUE(key.saveToFiles("./priv.key", "./pub.key"));
    // check file sizes
    ASSERT_EQ(fileSize("./priv.key"), 887);
    ASSERT_EQ(fileSize("./pub.key"), 247);
}
TEST(DISABLED_RsaKey, DifferentKeyIsGeneratedEachTime) {
    cerr << "Hello world!\n";
}
