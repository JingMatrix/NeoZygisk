#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Fossil {
/**
 * @struct MountInfoEntry
 * @brief Represents a single parsed line from /proc/self/mountinfo.
 *        Contains a flag indicating if the entry is suspicious, which is
 *        determined by a substring comparison on the raw line during parsing.
 */
struct MountInfoEntry {
    std::string source;
    std::string target;
    std::string filesystem_type;
    std::string mount_options;
    bool is_suspicious = false;
};

/**
 * @class MountArgvFossil
 * @brief A professional, safe toolkit to find, parse, and sanitize a fossilized mount command's
 argument vector.
 *
 * --- Safety and Ownership ---
 *
 * This class is an "owning" object. Upon construction, it performs a deep copy of all
 * string data from either a raw memory block or a MountInfoEntry into its own std::string members.
 * This makes it completely independent of the original stack memory, ensuring it is safe to hold
 * and use even if the underlying memory is modified or overwritten. This is critical for
 * performing memory sanitization operations.
 *
 * --- The `argv` Fossil Theory ---
 *
 * This class is based on the discovery that the Android 'init' process leaves a leftover
 * data artifact on its stack after performing mount operations before starting Zygote. This
 * artifact is the in-memory representation of the argument vector (argv) for that mount command.
 * The structure is a series of juxtaposed, null-terminated C-strings because they originate
 * from a single buffer that was tokenized in-place. When init calls fork() to start
 * Zygote, Zygote inherits a copy of this "dirty" stack.
 */
class MountArgv {
public:
    /**
     * @brief [Constructor 1] Parses a fossil from a raw memory location.
     * @param start A pointer to the beginning of the potential fossil.
     * @param search_limit A pointer to the end of the memory map, used as a boundary.
     */
    MountArgv(const char* start, const char* search_limit);

    /**
     * @brief [Constructor 2] Creates a new, "clean" fossil object from a legitimate MountInfoEntry.
     * This object can then be written to memory to perform a spoof.
     * @param clean_entry The legitimate MountInfoEntry to use as a template.
     * @param target_address The memory address where this fossil will eventually be written.
     * @param base_flags The base_flags integer to use (typically inherited from the original
     * fossil).
     */
    MountArgv(const MountInfoEntry& clean_entry, const char* target_address, uint32_t base_flags);

    /**
     * @brief Scans a memory range for the first valid MountArgvFossil.
     * @param search_from The start of the memory range to scan.
     * @param search_to The end (one past the last byte) of the range.
     * @return A valid, self-contained MountArgvFossil object if found, otherwise an invalid one.
     */
    static MountArgv find(char* search_from, char* search_to);

    /**
     * @brief Writes this object's internal data copies to its target memory address.
     */
    void writeToMemory() const;

    /**
     * @brief Zeroes out the remnant part of the trace *at this object's start address*.
     * This is the primary sanitization action to mimic a clean non-root environment.
     */
    void cleanMemory() const;

    // --- Accessors ---
    bool isValid() const;
    const std::string& getSource() const;
    const std::string& getTarget() const;
    const std::string& getFilesystemType() const;
    const std::string& getMountOptions() const;
    uint32_t getBaseFlags() const;
    size_t getRemnantSize() const;
    size_t getFossilSize() const;
    const char* getStartAddress() const;

    /**
     * @brief Dumps the parsed content to logcat for debugging and verification.
     */
    void dumpToLog() const;

private:
    // --- Private Implementation ---

    /**
     * @brief The core parsing logic for a fossil in raw memory.
     */
    void parseFromMemory(const char* start, const char* search_limit);

    /**
     * @brief Helper to safely find, copy, and advance past a null-terminated string.
     * @return True on success, false if parsing would go out of bounds.
     */
    bool parse_and_copy_string_field(std::string& out_str, const char*& ptr, const char* limit);

    /**
     * @brief Helper to find the first occurrence of two consecutive null bytes.
     * @return A pointer to the start of the double-null, or nullptr if not found.
     */
    const char* find_double_null(const char* start, const char* limit) const;

    /**
     * @brief Applies a set of strong heuristics to a parsed fossil to validate it.
     * @return True if the fossil is very likely to be authentic, false otherwise.
     */
    bool passesHeuristics() const;

    // --- Member Variables ---
    const char* m_start_address = nullptr;  // The absolute start address in memory.
    std::string m_source;
    std::string m_target;
    std::string m_filesystem_type;
    std::string m_mount_options;

    uint32_t m_base_flags = 0;
    size_t m_fossil_size = 0;
    size_t m_remnant_size = 0;
    bool m_valid = false;
};

/**
 * @brief Parses the entire /proc/self/mountinfo file. For each line, it determines if it is
 *        suspicious by a substring comparison and sets a flag in the returned struct.
 * @return A vector of MountInfoEntry structs, each annotated with its suspicion status.
 */
std::vector<MountInfoEntry> parseMountInfo();

}  // namespace Fossil
