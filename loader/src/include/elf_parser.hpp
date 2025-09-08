#pragma once

#include <link.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

// Define SHT_GNU_HASH if it's not available in the included headers.
#ifndef SHT_GNU_HASH
#define SHT_GNU_HASH 0x6ffffff6
#endif

namespace ElfParser {

/**
 * @class ElfImage
 * @brief Parses a loaded ELF binary (typically a shared library) from memory to find symbol
 * addresses.
 *
 * This class finds a shared library loaded in the current process's memory,
 * memory-maps its corresponding file, and parses the ELF structures to allow
 * for efficient symbol lookups. It supports GNU hash, System V hash, and linear
 * scanning of the symbol table.
 */
class ElfImage {
public:
    /**
     * @brief Constructs an ElfImage object for a given library.
     * @param library_name A view of the library's name (e.g., "libc.so").
     *        The class will find the full path of the loaded library.
     */
    explicit ElfImage(std::string_view library_name);

    /**
     * @brief Destructor that unmaps the memory-mapped ELF file.
     */
    ~ElfImage();

    // Disable copy and move operations to prevent issues with resource management.
    ElfImage(const ElfImage&) = delete;
    ElfImage& operator=(const ElfImage&) = delete;
    ElfImage(ElfImage&&) = delete;
    ElfImage& operator=(ElfImage&&) = delete;

    /**
     * @brief Retrieves the virtual memory address of a symbol.
     * @param symbol_name The name of the symbol to find.
     * @return The absolute virtual address of the symbol if found; otherwise, 0.
     */
    ElfW(Addr) findSymbolAddress(std::string_view symbol_name) const;

    /**
     * @brief A template helper to get the symbol address cast to a specific type.
     * @tparam T The function or pointer type to cast the address to.
     * @param symbol_name The name of the symbol to find.
     * @return The symbol's address cast to type T.
     */
    template <typename T>
    T findSymbolAddress(std::string_view symbol_name) const {
        return reinterpret_cast<T>(findSymbolAddress(symbol_name));
    }

    /**
     * @brief Finds the full name of a symbol that starts with a given prefix.
     * @param prefix The prefix to search for.
     * @return A string_view of the full symbol name if found; otherwise, an empty view.
     */
    std::string_view findSymbolNameByPrefix(std::string_view prefix);

    /**
     * @brief Checks if the ELF image was successfully loaded and parsed.
     * @return True if the object is valid, false otherwise.
     */
    bool isValid() const { return base_address_ != nullptr && header_ != nullptr; }

    /**
     * @brief Gets the full path of the loaded library file.
     * @return A constant reference to the library's path.
     */
    const std::string& getLibraryPath() const { return library_path_; }

private:
    /**
     * @brief Finds the file offset of a symbol using the most efficient available method.
     * @param symbol_name The name of the symbol.
     * @param gnu_hash The pre-calculated GNU hash of the symbol name.
     * @param sysv_hash The pre-calculated System V hash of the symbol name.
     * @return The file offset of the symbol if found; otherwise, 0.
     */
    ElfW(Addr)
        findSymbolOffset(std::string_view symbol_name, uint32_t gnu_hash, uint32_t sysv_hash) const;

    /**
     * @brief Symbol lookup using the .gnu.hash section.
     * @param symbol_name The name of the symbol.
     * @param gnu_hash The GNU hash of the symbol name.
     * @return The file offset of the symbol if found; otherwise, 0.
     */
    ElfW(Addr) findSymbolByGnuHash(std::string_view symbol_name, uint32_t gnu_hash) const;

    /**
     * @brief Symbol lookup using the .hash section (System V hash).
     * @param symbol_name The name of the symbol.
     * @param sysv_hash The System V hash of the symbol name.
     * @return The file offset of the symbol if found; otherwise, 0.
     */
    ElfW(Addr) findSymbolBySysvHash(std::string_view symbol_name, uint32_t sysv_hash) const;

    /**
     * @brief Symbol lookup via a linear scan of the .symtab section.
     * @param symbol_name The name of the symbol.
     * @return The file offset of the symbol if found; otherwise, 0.
     */
    ElfW(Addr) findSymbolByLinearScan(std::string_view symbol_name);

    /**
     * @brief Populates the internal symbol cache by reading the .symtab section.
     * This is called on-demand by linear scan lookups.
     */
    void buildSymbolCache();

    /**
     * @brief Calculates the System V hash for a symbol name.
     * @param name The symbol name.
     * @return The 32-bit hash value.
     */
    constexpr static uint32_t calculateSysvHash(std::string_view name);

    /**
     * @brief Calculates the GNU hash for a symbol name.
     * @param name The symbol name.
     * @return The 32-bit hash value.
     */
    constexpr static uint32_t calculateGnuHash(std::string_view name);

    /**
     * @brief Iterates through loaded libraries to find the base address and path of the target
     * library.
     * @param library_name The name of the library to find.
     * @return True if the library was found, false otherwise.
     */
    bool findLoadedLibraryInfo(std::string_view library_name);

    // --- Member Variables ---

    // Library and memory mapping info
    std::string library_path_;
    void* base_address_ = nullptr;
    void* map_base_ = nullptr;
    off_t map_size_ = 0;
    ElfW(Ehdr) * header_ = nullptr;
    off_t bias_ = -1;

    // Pointers to key ELF sections
    ElfW(Sym) * dynsym_ = nullptr;
    const char* dynstr_ = nullptr;
    ElfW(Sym) * symtab_ = nullptr;
    const char* strtab_ = nullptr;
    ElfW(Off) symtab_count_ = 0;

    // System V hash section data
    uint32_t nbucket_ = 0;
    uint32_t* bucket_ = nullptr;
    uint32_t* chain_ = nullptr;

    // GNU hash section data
    uint32_t gnu_nbucket_ = 0;
    uint32_t gnu_symindx_ = 0;
    uint32_t gnu_bloom_size_ = 0;
    uint32_t gnu_shift2_ = 0;
    ElfW(Addr) * gnu_bloom_filter_ = nullptr;
    uint32_t* gnu_bucket_ = nullptr;
    uint32_t* gnu_chain_ = nullptr;

    // Cache for linear symbol lookups
    std::unordered_map<std::string_view, const ElfW(Sym)*> symbol_cache_;
};

constexpr uint32_t ElfImage::calculateSysvHash(std::string_view name) {
    uint32_t h = 0;
    uint32_t g = 0;
    for (const unsigned char c : name) {
        h = (h << 4) + c;
        g = h & 0xf0000000;
        if (g != 0) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

constexpr uint32_t ElfImage::calculateGnuHash(std::string_view name) {
    uint32_t h = 5381;
    for (const unsigned char c : name) {
        h = (h << 5) + h + c;  // h * 33 + c
    }
    return h;
}

// --- Helper Functions for Symbol Lookups ---

/**
 * @brief Finds the virtual memory address of a symbol and returns a correctly-typed pointer.
 *
 * This function provides a convenient, unified interface for finding both data
 * variables and functions. It intelligently handles the type casting to ensure
 * that it always returns a usable pointer, saving the developer from needing
- * different functions for different symbol types.
 *
 * It uses compile-time checks (`if constexpr`) to differentiate between function pointers
 * and all other types (including data pointers). This ensures that function pointers
 * are not incorrectly wrapped in an extra layer of indirection.
 *
 * @tparam T The type of the requested symbol. This can be a data type (`size_t`),
 *           a data pointer type (`clazz*`), or a function pointer type (`void(*)()`).
 *
 * @return A usable pointer to the symbol's location in memory if found; otherwise, `nullptr`.
 */
template <typename T>
auto findDirectSymbol(const ElfImage& image, std::string_view symbol_name) {
    auto address = image.findSymbolAddress(symbol_name);

    // This trait checks: "Is T a pointer AND is the thing it points to a function?"
    constexpr bool is_function_pointer =
        std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;

    if constexpr (is_function_pointer) {
        // CASE 1: T is a function pointer (e.g., void(*)()).
        // The address from the ELF file is the function's entry point.
        // We cast the address directly to the function pointer type.
        return reinterpret_cast<T>(address);
    } else {
        // CASE 2: T is anything else (e.g., size_t, clazz*).
        // This is a data symbol. We return a pointer to it.
        // The simple, uniform `T*` behavior is correct for these cases.
        return reinterpret_cast<T*>(address);
    }
}

/**
 * @brief Finds the address of an "indirect" symbol, dereferences it, and returns the result.
 *
 * This function is used for the specific case where the symbol is not the object
 * itself, but rather a global **pointer to** the object. This function handles the
 * necessary level of indirection to resolve the final address.
 *
 * Memory Layout for Indirect Symbols:
 *
 *   Address of Symbol (returned by findSymbolAddress)
 *   +-------------------+
 *   | Address of Object |  <-- This is a pointer value.
 *   +-------------------+
 *           |
 *           +---------------> Address of Object (the final returned pointer)
 *                           +------------------+
 *                           | The actual       |
 *                           | object's data... |
 *                           +------------------+
 *
 * @tparam T The type of the final object being pointed to.
 * @param image An initialized ElfImage object to search within.
 * @param symbol_name The name of the symbol (which is a pointer).
 * @return A pointer of type `T*` to the final object if found and resolved; otherwise, `nullptr`.
 *
 * @usage
 * // Find the object pointed to by the global pointer "g_main_soinfo_ptr"
 * SoInfo* main_soinfo = ElfParser::resolveSymbolPointer<SoInfo>(linker, "g_main_soinfo_ptr");
 */
template <typename T>
T* resolveSymbolPointer(const ElfImage& image, std::string_view symbol_name) {
    auto* address = reinterpret_cast<T**>(image.findSymbolAddress(symbol_name));
    return (address == nullptr) ? nullptr : *address;
}

}  // namespace ElfParser
