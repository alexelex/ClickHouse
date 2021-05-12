#pragma once

#include "IO/ReadBufferFromFileBase.h"
#include "Encryption.h"

namespace DB
{

class ReadEncryptedBuffer : public ReadBufferFromFileBase
{
public:
    ReadEncryptedBuffer(
        size_t buf_size_,
        std::unique_ptr<ReadBufferFromFile> in_,
        const EVP_CIPHER * evp_cipher_,
        const InitVector & init_vector_,
        const EncryptionKey & key_)
        : ReadBufferFromFileBase(buf_size_, nullptr, 0)
        , buf_size(buf_size_)
        , decryptor(Decryptor(init_vector_, key_, evp_cipher_))
        , init_vector(init_vector_)
        , in(std::move(in_))
    { }

    off_t seek(off_t off, int whence) override
    {
        if (whence == SEEK_CUR)
        {
            if (off < 0 && -off > getPosition())
                throw Exception("SEEK_CUR shift out of bounds", ErrorCodes::ARGUMENT_OUT_OF_BOUND);

            if (!working_buffer.empty() && size_t(offset() + off) < working_buffer.end())
            {
                pos += off;
                return getPosition();
            }
            else
            {
                start_pos = off + getPosition();
            }
        }
        else if (whence == SEEK_SET)
        {
            if (off < 0)
                throw Exception("SEEK_SET underflow", ErrorCodes::ARGUMENT_OUT_OF_BOUND);

            if (!working_buffer.empty() && size_t(off) >= start_pos - working_buffer.size()
                && size_t(off) < start_pos)
            {
                pos = working_buffer.end() - (start_pos - offset_);
                return getPosition();
            }
            else
            {
                start_pos = off;
            }
        }
        else
            throw Exception("ReadEncryptedBuffer::seek expects SEEK_SET or SEEK_CUR as whence", ErrorCodes::ARGUMENT_OUT_OF_BOUND);

        initialize();
        return start_pos;
    }

    off_t getPosition() override { return bytes + offset(); }

    std::string getFileName() const override { return in->getFileName(); }

private:

    bool nextImpl() override
    {
        if (in->eof())
            return false;

        if (!initialized)
            start_pos += working_buffer.size();
        initialize();
        return true;
    }

    void initialize()
    {
        size_t in_pos = start_pos;
        size_t expected_size = decryptor.SizeByByfSize(buf_size);

        String data(expected_size);
        size_t data_size = 0;

        in->seek(in_pos, SEEK_SET);
        while (data_size < expected_size && !in->eof())
        {
            auto size = in->read(data.data() + data_size, buf_size - data_size);
            data_size += size;
            in_pos += size;
            in->seek(start_pos, SEEK_SET);
        }

        data.resize(data_size);
        decryptor.Decrypt(data.data(), working_buffer, data_size);
        pos = working_buffer.begin();
        initialized = true;
    }

    std::unique_ptr<ReadBufferFromFile> in;
    size_t buf_size;

    InitVector iv;
    Decryptor decryptor;
    bool initialized = false;
    size_t start_pos = 0;
};

}
