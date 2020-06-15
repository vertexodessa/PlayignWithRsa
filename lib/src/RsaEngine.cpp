#include <RsaEngine.hpp>

#include <utils/SslError.hpp>

#include <openssl/err.h>

#include <algorithm>
#include <iostream>

#include <functional>
#include <future>

#define PARALLEL_WAY 1

using namespace std;

namespace MyOpenSslExample {

RsaEngine::RsaEngine(const MyOpenSslExample::OpenSslWrapper& ssl)
    : m_ssl(ssl) {}

const auto processData = [](const OpenSslWrapper& ssl, const RsaKey& key,
                            const vector<unsigned char>& data, auto* func,
                            bool encrypt) -> Result<vector<unsigned char>> {
    if (data.empty())
        return MAKE_ERROR(ErrorCode::InvalidArguments,
                          "data should not be empty");

    auto keyPtr = key.getKey();
    if (!keyPtr)
        return MAKE_ERROR(keyPtr.errorCode(), "unable to get key");

    const int padding = RSA_PKCS1_PADDING;
    const auto rsaSize = RSA_size(keyPtr.value());

    // 11 for RSA_PKCS1_PADDING encryption (see man RSA_public_encrypt)
    const auto flen = encrypt ? 11 : 0;
    const auto iterSize = rsaSize - flen;

    const int dataSize = data.size();
    const auto bufSize = ((dataSize / rsaSize) + 1) * rsaSize;

    vector<unsigned char> ret;
    vector<unsigned char> buffer;

    buffer.resize(bufSize, '\0');
    ret.reserve(bufSize * rsaSize);

#if !defined(PARALLEL_WAY)

    for (int i = 0; i < dataSize; i += iterSize) {
        auto len_ = min(iterSize, dataSize - i);

        int returned_length = (*func)(len_, data.data() + i, buffer.data(),
                                      keyPtr.value(), padding);

        if (returned_length == -1) {
            return MAKE_ERROR(ErrorCode::EncryptionError, getLastSslError(ssl));
        }

        ret.insert(end(ret), buffer.data(), buffer.data() + returned_length);
    }

    return Result(ret);

#else
    using Bunch = vector<unsigned char>;
    using Data = vector<Bunch>;
    using ProcessedData = vector<future<Bunch>>;
    Data out;
    for (int i = 0; i < dataSize; i += iterSize) {
        auto len_ = min(iterSize, dataSize - i);
        out.push_back(Bunch{begin(data) + i, begin(data) + i + len_});
    }

    ProcessedData dest;
    dest.resize(out.size());

    for (int i=0; i < out.size(); ++i){
        dest[i] = std::async(launch::async, [&keyPtr, padding, rsaSize, &func](const auto& bunch) {
            Bunch ret;
            auto len_ = bunch.size();
            vector<unsigned char> buffer;
            buffer.resize(rsaSize, '\0');

            int returned_length = (*func)(len_, bunch.data(), buffer.data(),
                                          keyPtr.value(), padding);

            if (returned_length == -1) {
                char buf[1024];
                ERR_error_string_n(ERR_get_error(), buf, 1024);
                return Bunch{};
            }
            ret.insert(begin(ret), buffer.data(),
                       buffer.data() + returned_length);
            return ret;
        }, out[i]);
    }

    for (auto& c : dest) {
        auto val = c.get();
        if (val.empty())
            return MAKE_ERROR(ErrorCode::EncryptionError,
                              "unable to encrypt data");
        ret.insert(end(ret), begin(val), end(val));
    }

    return Result(ret);
#endif
};

Result<vector<unsigned char>>
RsaEngine::publicEncrypt(const RsaKey& key, const vector<unsigned char>& data) {
    using namespace std::placeholders;
    auto func =
        bind(&OpenSslWrapper::RSA_public_encrypt, &m_ssl, _1, _2, _3, _4, _5);
    return processData(m_ssl, key, data, &func, true);
}

Result<vector<unsigned char>>
RsaEngine::privateDecrypt(const RsaKey& key,
                          const vector<unsigned char>& data) {
    using namespace std::placeholders;
    auto func =
        bind(&OpenSslWrapper::RSA_private_decrypt, &m_ssl, _1, _2, _3, _4, _5);
    return processData(m_ssl, key, data, &func, false);
}

} // namespace MyOpenSslExample
