#pragma once

#include <IO/WriteBufferFromFileBase.h>
#include "Encryption.h"

namespace DB
{
class WriteEncryptedBuffer : public WriteBufferFromFileBase
{
public:
    WriteIndirectBufferFromS3(
        size_t buf_size_,
        std::unique_ptr<WriteBufferFromFile> out_,
        const EVP_CIPHER * evp_cipher_,
        const InitVector & init_vector_,
        const EncryptionKey & key_,
        const size_t & file_size)
        : WriteBufferFromFileBase(buf_size_, nullptr, 0)
        , buf_size(buf_size_)
        , encryptor(Encryptor(init_vector_, key_, evp_cipher_, file_size))
        , out(std::move(out_))
        , flush_iv(file_size == 0)
        , init_vector(init_vector_)
    {
    }

    ~WriteBufferFromFileBase() override;

    void sync() override {
        // ALEXELEX TODO
        out->sync();
    }

    std::string getFileName() const override { return out->getFileName(); }

private:
    void nextImpl overload
    {
        if (!offset())
            return;
        if (flush_iv)
        {
            WriteInitVector(iv, out);
            flush_iv = false;
        }

        encryptor.Encrypt(working_buffer.begin(), *out, working_buffer.size());
    }

    size_t buf_size;
    std::unique_ptr<WriteBufferFromFile> out;

    bool flush_iv;
    InitVector init_vector;
    Encryptor encryptor;
};

}
