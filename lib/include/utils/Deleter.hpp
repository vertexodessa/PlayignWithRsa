#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>

// TODO: forward-declare everything and move to .cpp
#include <openssl/rsa.h>
#include <openssl/ssl.h>

namespace MyOpenSslExample {

template <class T> using Deleter = std::function<void(T*)>;

}
