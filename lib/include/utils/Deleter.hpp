#pragma once

#include <functional>
#include <memory>

namespace MyOpenSslExample {

template <class T> using Deleter = std::function<void(T*)>;

template  <typename T>
using Ptr = std::unique_ptr<T, Deleter<T>>;

}
