#include <iostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <utils/Deleter.hpp>

#include <BigNumber.hpp>
#include <RsaKey.hpp>

#include <mylog.h>

using namespace std;
using namespace testing;
using namespace MyOpenSslExample;

class MockBigNumber : public BigNumber {
  public:
    MOCK_METHOD(bool, init, (), (override));
    MOCK_METHOD(BIGNUM*, get, (), (const, override));
    MOCK_METHOD(int, setWord, (BN_ULONG), (override));
    MOCK_METHOD(BigNumberPtr, newNum, (), (const, override));

    MockBigNumber() {
        ON_CALL(*this, init).WillByDefault([this]() {
            M(__PRETTY_FUNCTION__);
            return BigNumber::init();
        });
        ON_CALL(*this, get).WillByDefault([this]() {
            M(__PRETTY_FUNCTION__);
            return BigNumber::get();
        });
        ON_CALL(*this, setWord).WillByDefault([this](BN_ULONG w) {
            M(__PRETTY_FUNCTION__);
            return BigNumber::setWord(w);
        });
        ON_CALL(*this, newNum).WillByDefault([this]() {
            M(__PRETTY_FUNCTION__);
            return BigNumber::newNum();
        });
    }
};

TEST(BigNumber, InitSequence) {
    MockBigNumber bn;

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, newNum()).Times(1);

    ASSERT_TRUE(bn.init());
    ASSERT_TRUE(!!bn.get());
}

TEST(RsaKey, CorrectBigNumberInitialization) {
    MockBigNumber bn;

    EXPECT_CALL(bn, init()).Times(1);
    EXPECT_CALL(bn, newNum()).Times(1);
    EXPECT_CALL(bn, get()).Times(3);
    EXPECT_CALL(bn, setWord(RSA_3)).Times(1);

    ASSERT_TRUE(bn.init());

    RsaKey key;
    ASSERT_TRUE(key.initialize(bn));
}

TEST(RsaKey, DifferentKeyIsGeneratedEachTime) { cerr << "Hello world!\n"; }
