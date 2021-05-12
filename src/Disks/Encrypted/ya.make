OWNER(g:clickhouse)

LIBRARY()

PEERDIR(
    clickhouse/src/Common
)


SRCS(
    DiskEncrypted.cpp
    Encryption.cpp
)

END()
