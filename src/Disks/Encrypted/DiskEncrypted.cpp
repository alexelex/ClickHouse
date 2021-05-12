#include "sys/random.h"

#include "Disks/DiskFactory.h"
#include "DiskEncrypted.h"
#include "ReadEncryptedBuffer.h"
#include "WriteEncryptedBuffer.h"

namespace DB {

using DiskEncryptedPtr = std::shared_ptr<DiskEncrypted>;
constexpr size_t kIVSize = 128;

class DiskEncryptedReservation : public IReservation
{
public:
    DiskEncryptedReservation(const DiskEncryptedPtr & disk_, std::unique_ptr<IReservation> reservation_)
        : disk(disk_), reservation(std::move(reservation_))
    {
    }

    UInt64 getSize() const override { return reservation->getSize(); }

    DiskPtr getDisk(size_t i) const override {
        if (i != 0)
        {
            throw Exception("Can't use i != 0 with single disk reservation", ErrorCodes::INCORRECT_DISK_INDEX);
        }
        return disk;
    }

    Disks getDisks() const override { return {disk}; }

    void update(UInt64 new_size) override { reservation->update(new_size); }

private:
    DiskEncryptedPtr disk;
    std::unique_ptr<IReservation> reservation;
};

ReservationPtr DiskEncrypted::reserve(UInt64 bytes)
{
    auto reservation = wrapped_disk->reserve(bytes);
    if (!reservation)
        return {};
    return std::make_unique<DiskEncryptedReservation>(std::static_pointer_cast<DiskEncrypted>(shared_from_this()), std::move(reservation));
}

std::unique_ptr<ReadBufferFromFileBase> DiskEncrypted::readFile(
    const String & path,
    size_t buf_size,
    size_t estimated_size,
    size_t aio_threshold,
    size_t mmap_threshold,
    MMappedFileCache * mmap_cache) const {
    return wrapped_disk->readFile(path, buf_size, estimated_size, aio_threshold, mmap_threshold, mmap_cache);
}

std::unique_ptr<WriteBufferFromFileBase> DiskEncrypted::writeFile(
    const String & path,
    size_t buf_size,
    WriteMode mode) {
    auto buffer = wrapped_disk->writeFile(path, buf_size, mode);
    // TODO
    // depends on mode (MODE::APPEND ? что делать с "незаконенными" блоками ? )
    // и что если buf_size не кратен 128 битам / т.е. 16 ?
    InitVector iv = GetRandomIV(kIVSize);
    try {
        iv = ReadInitVector(kIVSize, wrapped_disk->readFile(path, kIVSize));
    }
    catch ( ... ) { }
    return std::make_unique<WriteEncryptedBuffer>(buf_size, std::move(buffer), EVP_aes_128_gcm(), iv, key,
                                                  mode == WriteMode::Append ? wrapped_disk->getFileSize(path) : 0);
}

void DiskEncrypted::truncateFile(const String & path, size_t size) {
    wrapped_disk->truncateFile(path, size + sizeof(InitVector));
}

SyncGuardPtr DiskEncrypted::getDirectorySyncGuard(const String & path) const {
    // TODO
    return wrapped_disk->getDirectorySyncGuard(path);
}

void registerDiskEncrypted(DiskFactory & factory)
{
    LOG_ERROR(&Poco::Logger::get("DiskEncrypted"), "___***___\n\n\n"
                                                   "create ENCRYPTED disk creator"
                                                   "(src/Disks/Encrypted/DiskEncrypted.cpp::registerDiskEncrypted"
                                                   "\n\n\n___***___");
    auto creator = [](const String & name,
                      const Poco::Util::AbstractConfiguration & config,
                      const String & config_prefix,
                      ContextConstPtr context) -> DiskPtr {
        LOG_ERROR(&Poco::Logger::get("DiskEncrypted"), "___***___\n\n\n"
                                                       "ENCRYPTED disk creator"
                                                       "(src/Disks/Encrypted/DiskEncrypted.cpp::registerDiskEncrypted)"
                                                       "\n\n\n___***___");
        LOG_ERROR(&Poco::Logger::get("DiskEncrypted"), "___***___\n\n\n"
                                                       "it would be nice if it'll work ^^"
                                                       "\n\n\n___***___");
        String wrapped_disk_name = config.getString(config_prefix + ".disk", "");
        if (wrapped_disk_name.empty())
            throw Exception("The wrapped disk name can not be empty. An encrypted disk is a wrapper over another disk. "
                            "Disk " + name, ErrorCodes::UNKNOWN_ELEMENT_IN_CONFIG);

        String key = config.getString(config_prefix + ".key", "");
        if (key.empty())
            throw Exception("Encrypted disk key can not be empty. Disk " + name, ErrorCodes::UNKNOWN_ELEMENT_IN_CONFIG);

        auto& disks = context->getDisksMap();
        auto& wrapped_disk = disks.find(wrapped_disk_name);
        if (wrapped_disk == disks.end())
            throw Exception("The wrapped disk must have been announced earlier. No disk with name " + wrapped_disk_name ". Disk " + name,
                            ErrorCodes::UNKNOWN_ELEMENT_IN_CONFIG);

        return std::make_shared<DiskEncrypted>(name, wrapped_disk.second, key);
    };
    factory.registerDiskType("encrypted", creator);
}

}
