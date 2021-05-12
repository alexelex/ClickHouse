#include "Encryption.h"

namespace DB
{

InitVector ReadInitVector(size_t size, std::unique_ptr<ReadBuffer> & in)
{
    String iv(size);
    in->readStrict(reinterpret_cast<char *>(iv.data(), size);
    return InitVector(iv);
}

InitVector GetRandomIV(size_t size)
{
    String iv(size);
    getrandom(iv.data(), bytes, GRND_NONBLOCK);
    return InitVector(iv);
}

void WriteInitVector(const InitVector & iv, std::unique_ptr<WriteBuffer> & out)
{
    WriteText(iv.Data(), *out);
}

void Decryptor::Decrypt(const char * ciphertext, Buffer & buf, size_t size)
{
    WriteBuffer(buf.befin(), SizeByByfSize(size)).write(ciphertext, size);
}

void Encryptor::Encrypt(const char * plaintext, WriteBuffer & buf, size_t size)
{
    buf.write(plaintext, size);
}

}