#pragma once

#include <OpenSslWrapper.hpp>
#include <string>

namespace MyOpenSslExample {

inline std::string getLastSslError(const OpenSslWrapper& ssl) {
    char buf[1024];
    ssl.ERR_error_string_n(ssl.ERR_get_error(), buf, 1024);
    return std::string{buf};
}

} // namespace MyOpenSslExample
