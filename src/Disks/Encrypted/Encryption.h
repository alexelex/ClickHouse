#pragma once

#include <IO/ReadBuffer.h>
#include <IO/WriteBuffer.h>

namespace DB
{

class InitVector
{
public:
    InitVector(String iv_) : iv(iv_) { }

    size_t Size() const { return iv.size(); }
    String Data() const { return iv; }

private:
    String iv;
};

class EncryptionKey
{
public:
    EncryptionKey(String key_) : key(key_) { }
    String Get() const { return key; }

private:
    String key;
};

InitVector ReadInitVector(size_t size, std::unique_ptr<ReadBuffer> in);
InitVector GetRandomIV(size_t size);
void WriteInitVector(const InitVector & iv, std::unique_ptr<WriteBuffer> out);


class Encryption
{
public:
    Encryption(const InitVector & iv_, const EncryptionKey & key_, const EVP_CIPHER * evp_cipher_, size_t offset_ = 0)
        : iv(iv_), key(key_), evp_cipher(evp_cipher_)
        , block_size(static_cast<size_t>(EVP_CIPHER_block_size(evp_cipher_)))
    {
        blocks = Blocks(offset_);
        offset = BlockOffset(offset_);
    }

    size_t SizeByByfSize(size_t input_size) const { return input_size; }

private:

    size_t Blocks(size_t pos) { return pos / block_size; }

    size_t BlockOffset(size_t pos) const { return pos % block_size; }

//    size_t BlocksAlign(size_t pos) const { return pos - BlockOffset(pos); }

//    size_t BlockStartPos(size_t pos) const { return iv.Size() + pos - BlockOffset(pos); }

    const EVP_CIPHER * evp_cipher;
    InitVector iv;
    EncryptionKey key;
    size_t blocks = 0;
    size_t block_size;
    size_t offset = 0;
};

class Encryptor : public Encryption
{
public:
    Encryptor(const InitVector & iv_, const EncryptionKey & key_, const EVP_CIPHER * evp_cipher_, size_t offset_)
        : Encryption(iv_, key_, evp_cipher_, offset_) { }

    void Encrypt(const char * plaintext, Buffer & buf, size_t size);
};

class Decryptor : public Encryption
{
public:
    Decryptor(const InitVector & iv_, const EncryptionKey & key_, const EVP_CIPHER * evp_cipher_)
        : Encryption(iv_, key_, evp_cipher_) { }

    void Decrypt(const char * ciphertext, WriteBuffer & buf, size_t size);
};



}