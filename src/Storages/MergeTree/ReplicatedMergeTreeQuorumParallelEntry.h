#pragma once

#include <set>
#include <common/types.h>
#include <IO/ReadBuffer.h>
#include <IO/ReadBufferFromString.h>
#include <IO/WriteBuffer.h>
#include <IO/WriteBufferFromString.h>
#include <IO/Operators.h>
#include <Common/ZooKeeper/ZooKeeper.h>


namespace DB
{

/** To implement the functionality of the "quorum write".
  * Information about count of parallel writing
  */
struct ReplicatedMergeTreeQuorumParallelEntry
{
    std::set<String> part_names;
    bool is_parallel = false;

    ReplicatedMergeTreeQuorumParallelEntry() {}
    ReplicatedMergeTreeQuorumParallelEntry(const String & str)
    {
        fromString(str);
    }

    void writeText(WriteBuffer & out) const
    {
        out << "version: 1\n" // ?? ALEXELEXA need right version
            << "is_parallel: " << is_parallel << "\n"
            << "number_of_part_names: " << part_names.size() << "\n"
            << "part_names:\n";

        for (const auto & part_name : part_names)
            out << escape << part_name << "\n";
    }

    void readText(ReadBuffer & in)
    {
        size_t number_of_part_names = 0;

        in >> "version: 1" >> "\n"
            >> "is_parallel: " >> is_parallel >> "\n"
            >> "number_of_part_names: " >> number_of_part_names >> "\n"
            >> "part_names:\n";

        for (size_t i = 0; i < number_of_part_names; ++i)
        {
            String part_name;
            in >> escape >> part_name >> "\n";
            part_names.insert(part_name);
        }
    }

    String toString() const
    {
        WriteBufferFromOwnString out;
        writeText(out);
        return out.str();
    }

    void fromString(const String & str)
    {
        ReadBufferFromString in(str);
        readText(in);
    }
};

}
