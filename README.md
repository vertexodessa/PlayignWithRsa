# PlayingWithRsa

Console program

	- Generate RSA key pair and dump it to the disk
	- Encrypt a file with a public key
	- Decrypt a file with a private key
	- 100% statement coverage by unit and integration tests using GTest/GMock, mocking of external dependencies
	- Use C++14/17 features
	- Use SOLID and modern C++ idioms (RAII, strong typing)
	- Use defensive programming and other security programming approaches
	- Use OpenSSL library, create C++ wrappers over all used crypto functions
	- Disable exceptions, use monadic error handling, e.g., https://github.com/TartanLlama/expected (or just error codes if not enough time)
	- Use CMake build configuration
	- Use Github
	- Use clang-format & google style
