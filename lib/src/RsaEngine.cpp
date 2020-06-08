#include <RsaEngine.hpp>

#include <openssl/err.h>

#include <algorithm>
#include <iostream>

#if (__has_include(<execution>))
#include <execution>
#define PARALLEL_WAY 1
#endif

using namespace std;

namespace MyOpenSslExample {

RsaEngine::RsaEngine(const MyOpenSslExample::OpenSslWrapper& ssl)
    : m_ssl(ssl) {}

const auto processData = [](const RsaKey& key,
                            const vector<unsigned char>& data, auto* func,
                            bool encrypt) -> Result<vector<unsigned char>> {
    if (data.empty())
        return ErrorCode::InvalidArguments;

    auto keyPtr = key.getKey();
    if (!keyPtr)
        return keyPtr.error();

    const int padding = RSA_PKCS1_PADDING;
    auto rsaSize = RSA_size(keyPtr.value());

    // 11 for RSA_PKCS1_PADDING encryption (see man RSA_public_encrypt)
    const auto flen = encrypt ? 11 : 0;
    const auto iterSize = rsaSize - flen;

    int dataSize = data.size();

    auto bufSize = ((dataSize / rsaSize) + 1) * rsaSize;

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
            char buf[1024];
            ERR_error_string_n(ERR_get_error(), buf, 1024);
            return ErrorCode::EncryptionError;
        }

        ret.insert(end(ret), buffer.data(), buffer.data() + returned_length);
    }

    return Result(ret);

#else
    using Bunch = vector<unsigned char>;
    using Data = vector<Bunch>;
    Data out;
    for (int i = 0; i < dataSize; i += iterSize) {
        auto len_ = min(iterSize, dataSize - i);
        out.push_back(Bunch{begin(data) + i, begin(data) + i + len_});
    }

    Data dest;
    dest.resize(out.size());

    transform(
        execution_policy::par, out.begin(), out.end(), back_inserter(dest),
        [&keyPtr, padding, rsaSize, &func](const auto& bunch) {
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
        });

    for (auto& c : dest) {
        if (c.empty())
            return ErrorCode::EncryptionError;
        ret.insert(end(ret), begin(c), end(c));
    }

    return Result(ret);
#endif
};

Result<vector<unsigned char>>
RsaEngine::publicEncrypt(const RsaKey& key, const vector<unsigned char>& data) {
    return processData(key, data, &RSA_public_encrypt, true);
}

Result<vector<unsigned char>>
RsaEngine::privateDecrypt(const RsaKey& key,
                          const vector<unsigned char>& data) {
    return processData(key, data, &RSA_private_decrypt, false);
}

} // namespace MyOpenSslExample
