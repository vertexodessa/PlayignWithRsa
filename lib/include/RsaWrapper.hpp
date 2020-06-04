#pragma once

#include <cstddef>
#include <functional>
#include <memory>

// TODO: forward-declare everything and move to .cpp
#include <openssl/rsa.h>
#include <openssl/ssl.h>

namespace MyOpenSslExample {

class RsaWrapper {
  public:
    RsaWrapper();
    ~RsaWrapper();

  private:
    void initialize();
};

} // namespace MyOpenSslExample
