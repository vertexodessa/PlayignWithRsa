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

    MockOpenSsl() {
        FORWARD_TO_BASE(RSA_new);
        FORWARD_TO_BASE(RSA_free);
        FORWARD_TO_BASE(RSA_generate_key_ex);

        FORWARD_TO_BASE(BN_new);
        FORWARD_TO_BASE(BN_clear_free);
        FORWARD_TO_BASE(BN_set_word);
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
    EXPECT_CALL(ssl, BN_clear_free(_)).Times(1);

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, get()).Times(1);

    ASSERT_TRUE(bn.init());
    ASSERT_TRUE(!!bn.get());
}

TEST(RsaKey, CorrectBigNumberInitialization) {
    MockOpenSsl ssl;
    MockBigNumber bn(ssl);

    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(_)).Times(1);
    EXPECT_CALL(ssl, BN_set_word(_, RSA_3)).Times(1);

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, get()).Times(3);
    EXPECT_CALL(bn, setWord(RSA_3)).Times(1);

    ASSERT_TRUE(bn.init());

    OpenSsl ssl1;
    RsaKey key(ssl1);
    ASSERT_TRUE(key.initialize(bn));
    ASSERT_TRUE(!!key.get());
}

TEST(DISABLED_RsaKey, DifferentKeyIsGeneratedEachTime) {
    cerr << "Hello world!\n";
}
