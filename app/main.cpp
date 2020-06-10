#include <RsaEngine.hpp>
#include <RsaKey.hpp>

#include <ProgramOptions.hxx>
#include <fstream>
#include <iostream>

using namespace std;
using namespace MyOpenSslExample;

int encrypt_file(const string& publicKeyPath, const string& filename,
                 const string& out_filename) {
    OpenSslWrapper ssl;
    RsaKey pubKey(ssl);
    if (auto err = pubKey.readPublicKeyFromFile(publicKeyPath); !err) {
        cout << "ERROR: " << err->asText();
    }

    RsaEngine eng(ssl);

    ifstream input(filename);

    if (!input.is_open()) {
        cout << "Could not open " << filename << endl;
        return -1;
    }

    std::vector<unsigned char> data((std::istreambuf_iterator<char>(input)),
                                    std::istreambuf_iterator<char>());

    if (data.empty()) {
        cout << "File " << filename << " is empty" << endl;
        return -1;
    }

    auto encrypted = eng.publicEncrypt(pubKey, data);

    if (!encrypted) {
        cout << " ERROR encrypting file: " << encrypted.error().asText()
             << endl;
        return -1;
    }

    ofstream out(out_filename);
    out << string(encrypted.value().begin(), encrypted.value().end());
    return 0;
}

int decrypt_file(const string& privateKeyPath, const string& filename,
                 const string& out_filename) {
    OpenSslWrapper ssl;
    RsaKey privKey(ssl);
    if (auto err = privKey.readPrivateKeyFromFile(privateKeyPath); !err) {
        cout << "ERROR: " << err->asText();
    }

    RsaEngine eng(ssl);

    ifstream input(filename);

    if (!input.is_open()) {
        cout << "Could not open " << filename << endl;
        return -1;
    }

    std::vector<unsigned char> data((std::istreambuf_iterator<char>(input)),
                                    std::istreambuf_iterator<char>());

    if (data.empty()) {
        cout << "File " << filename << " is empty" << endl;
        return -1;
    }

    auto decrypted = eng.privateDecrypt(privKey, data);

    if (!decrypted) {
        cout << "ERROR decrypting file: " << decrypted.error().asText() << endl;
        return -1;
    }

    ofstream out(out_filename);
    out << string(decrypted.value().begin(), decrypted.value().end());
    return 0;
}

int main(int argc, char** argv) {
    po::parser parser;
    string privKey;
    string pubKey;
    string filename;
    string outFilename;

    parser["private-key"].description("Path to private key").bind(privKey);
    parser["public-key"].description("Path to public key").bind(pubKey);
    parser["filename"].description("Input file name").bind(filename);
    parser["out-filename"].description("Output file name").bind(outFilename);

    auto& help = parser["help"]
                     .abbreviation('?')
                     .description("print this help screen")
                     .callback([&] { std::cout << parser << '\n'; });

    if (!parser(argc, argv)) {
        cout << parser;
        return -1;
    }

    if (help.was_set())
        return 0;

    if (!privKey.empty() && !pubKey.empty()) {
        cout << "Only public or private key should be defined, both are not "
                "allowed!\n\n"
             << parser;
        return -1;
    }

    if (pubKey.empty() && privKey.empty()) {
        cout << "Either public or private key should be defined.\n\n" << parser;
        return -1;
    }

    if (outFilename.empty() || filename.empty()) {
        cout << "Input and output filenames should be defined.\n\n" << parser;
        return -1;
    }

    if (!pubKey.empty())
        return encrypt_file(pubKey, filename, outFilename);
    else
        return decrypt_file(privKey, filename, outFilename);
}
