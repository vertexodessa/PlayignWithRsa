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

class MockOpenSsl : public OpenSsl {
  public:
    MOCK_METHOD(RSA*, RSA_new, (), (const, override));
    MOCK_METHOD(void, RSA_free, (RSA*), (const, override));

    MOCK_METHOD(BIGNUM*, BN_new, (), (const, override));
    MOCK_METHOD(void, BN_clear_free, (BIGNUM*), (const, override));
    MOCK_METHOD(int, BN_set_word, (BIGNUM * a, BN_ULONG w), (const, override));

    MockOpenSsl() {
        ON_CALL(*this, RSA_new).WillByDefault([this]() {
            return OpenSsl::RSA_new();
        });
        ON_CALL(*this, RSA_free).WillByDefault([this](auto* p) {
            return OpenSsl::RSA_free(p);
        });

        ON_CALL(*this, BN_new).WillByDefault([this]() {
            return OpenSsl::BN_new();
        });
        ON_CALL(*this, BN_clear_free).WillByDefault([this](auto* p) {
            return OpenSsl::BN_clear_free(p);
        });
        ON_CALL(*this, BN_set_word).WillByDefault([this](auto* a, auto w) {
            return OpenSsl::BN_set_word(a, w);
        });
    }
};

class MockBigNumber : public BigNumber {
  public:
    MOCK_METHOD(bool, init, (), (override));
    MOCK_METHOD(BIGNUM*, get, (), (const, override));
    MOCK_METHOD(int, setWord, (BN_ULONG), (override));
    MOCK_METHOD(BigNumberPtr, newNum, (), (const, override));

    MockBigNumber(const OpenSsl& ssl) : BigNumber(ssl) {
        ON_CALL(*this, init).WillByDefault([this]() {
            return BigNumber::init();
        });
        ON_CALL(*this, get).WillByDefault([this]() {
            return BigNumber::get();
        });
        ON_CALL(*this, setWord).WillByDefault([this](auto w) {
            return BigNumber::setWord(w);
        });
        ON_CALL(*this, newNum).WillByDefault([this]() {
            return BigNumber::newNum();
        });
    }
};

TEST(BigNumber, InitSequence) {
    MockOpenSsl ssl;
    MockBigNumber bn(ssl);
    EXPECT_CALL(ssl, BN_new()).Times(1);
    EXPECT_CALL(ssl, BN_clear_free(_)).Times(1);

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, newNum()).Times(1);
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
    EXPECT_CALL(bn, newNum()).Times(1);
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
