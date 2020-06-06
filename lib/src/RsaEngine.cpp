#include <RsaEngine.hpp>

#include <openssl/err.h>

#include <iostream>


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
};

Result<vector<unsigned char>>
RsaEngine::encrypt(const RsaKey& key, const vector<unsigned char>& data) {
    return processData(key, data, &RSA_public_encrypt, true);
}

Result<vector<unsigned char>>
RsaEngine::decrypt(const RsaKey& key, const vector<unsigned char>& data) {
    return processData(key, data, &RSA_private_decrypt, false);
}

} // namespace MyOpenSslExample
