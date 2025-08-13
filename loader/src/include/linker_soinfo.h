#pragma once

#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>

class LinkedList {
private:
    void* header;
};
typedef void (*linker_dtor_function_t)();
typedef void (*linker_ctor_function_t)(int, char**, char**);
typedef LinkedList
    soinfo_list_t;  // the original definition is LinkedList<soinfo, SoinfoListAllocator>

struct soinfo {
#if !defined(__LP64__)
private:
    char old_name_[128];
#endif
public:
    const ElfW(Phdr) * phdr;
    size_t phnum;
#if !defined(__LP64__)
    ElfW(Addr) unused0;  // DO NOT USE, maintained for compatibility.
#endif
    ElfW(Addr) base;
    size_t size;

#if !defined(__LP64__)
    uint32_t unused1;  // DO NOT USE, maintained for compatibility.
#endif

    ElfW(Dyn) * dynamic;

#if !defined(__LP64__)
    uint32_t unused2;  // DO NOT USE, maintained for compatibility
    uint32_t unused3;  // DO NOT USE, maintained for compatibility
#endif

    soinfo* next;

private:
    uint32_t flags_;

    const char* strtab_;
    ElfW(Sym) * symtab_;

    size_t nbucket_;
    size_t nchain_;
    uint32_t* bucket_;
    uint32_t* chain_;

#if !defined(__LP64__)
    ElfW(Addr) * *unused4;  // DO NOT USE, maintained for compatibility
#endif

#if defined(USE_RELA)
    ElfW(Rela) * plt_rela_;
    size_t plt_rela_count_;

    ElfW(Rela) * rela_;
    size_t rela_count_;
#else
    ElfW(Rel) * plt_rel_;
    size_t plt_rel_count_;

    ElfW(Rel) * rel_;
    size_t rel_count_;
#endif

    linker_ctor_function_t* preinit_array_;
    size_t preinit_array_count_;

    linker_ctor_function_t* init_array_;
    size_t init_array_count_;
    linker_dtor_function_t* fini_array_;
    size_t fini_array_count_;

    linker_ctor_function_t init_func_;
    linker_dtor_function_t fini_func_;

#if defined(__arm__)
public:
    // ARM EABI section used for stack unwinding.
    uint32_t* ARM_exidx;
    size_t ARM_exidx_count;

private:
#endif
    size_t ref_count_;

public:
    link_map link_map_head;

    bool constructors_called;

    // When you read a virtual address from the ELF file, add this
    // value to get the corresponding address in the process' address space.
    ElfW(Addr) load_bias;

#if !defined(__LP64__)
    bool has_text_relocations;
#endif
    bool has_DT_SYMBOLIC;

public:
    // soinfo(android_namespace_t* ns, const char* name, const struct stat* file_stat,
    //        off64_t file_offset, int rtld_flags);
    ~soinfo();

    void call_constructors();
    void call_destructors();
    void call_pre_init_constructors();
    bool prelink_image(bool deterministic_memtag_globals = false);
    // bool link_image(const SymbolLookupList& lookup_list, soinfo* local_group_root,
    //                 const android_dlextinfo* extinfo, size_t* relro_fd_offset);
    bool protect_relro();

    void tag_globals(bool deterministic_memtag_globals);
    ElfW(Addr) apply_memtag_if_mte_globals(ElfW(Addr) sym_addr) const;

    void add_child(soinfo* child);
    void remove_all_links();

    ino_t get_st_ino() const;
    dev_t get_st_dev() const;
    off64_t get_file_offset() const;

    uint32_t get_rtld_flags() const;
    uint32_t get_dt_flags_1() const;
    void set_dt_flags_1(uint32_t dt_flags_1);

    // soinfo_list_t& get_children();
    // const soinfo_list_t& get_children() const;

    // soinfo_list_t& get_parents();

    // const ElfW(Sym) * find_symbol_by_name(SymbolName& symbol_name, const version_info* vi) const;

    ElfW(Sym) * find_symbol_by_address(const void* addr);

    // ElfW(Addr) resolve_symbol_address(const ElfW(Sym) * s) const {
    //     if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) {
    //         return call_ifunc_resolver(s->st_value + load_bias);
    //     }

    //     return static_cast<ElfW(Addr)>(s->st_value + load_bias);
    // }

    const char* get_string(ElfW(Word) index) const;
    bool can_unload() const;
    bool is_gnu_hash() const;

    // inline bool is_lp64_or_has_min_version(uint32_t min_version __unused) const {
    // #if defined(__LP64__)
    //     return true;
    // #else
    //     return (flags_ & FLAG_NEW_SOINFO) != 0 && version_ >= min_version;
    // #endif
    // }

    // const ElfW(Versym) * get_versym_table() const {
    //     return is_lp64_or_has_min_version(2) ? versym_ : nullptr;
    // }

    bool is_linked() const;
    bool is_linker() const;
    bool is_main_executable() const;

    void set_linked();
    void set_linker_flag();
    void set_main_executable();
    void set_nodelete();

    size_t increment_ref_count();
    size_t decrement_ref_count();
    size_t get_ref_count() const;

    soinfo* get_local_group_root() const;

    void set_soname(const char* soname);
    const char* get_soname() const;
    void set_realpath(const char* path);
    const char* get_realpath() const;
    const ElfW(Versym) * get_versym(size_t n) const;
    ElfW(Addr) get_verneed_ptr() const;
    size_t get_verneed_cnt() const;
    ElfW(Addr) get_verdef_ptr() const;
    size_t get_verdef_cnt() const;

    int get_target_sdk_version() const;

    void set_dt_runpath(const char*);
    // const std::vector<std::string>& get_dt_runpath() const;
    // android_namespace_t* get_primary_namespace();
    // void add_secondary_namespace(android_namespace_t* secondary_ns);
    // android_namespace_list_t& get_secondary_namespaces();

    // soinfo_tls* get_tls() const { return is_lp64_or_has_min_version(5) ? tls_.get() : nullptr; }

    void set_mapped_by_caller(bool reserved_map);
    bool is_mapped_by_caller() const;

    uintptr_t get_handle() const;
    void generate_handle();
    void* to_handle();

    // SymbolLookupLib get_lookup_lib();

    void set_gap_start(ElfW(Addr) gap_start);
    ElfW(Addr) get_gap_start() const;

    void set_gap_size(size_t gap_size);
    size_t get_gap_size() const;

    // const memtag_dynamic_entries_t* memtag_dynamic_entries() const {
    // #if defined(__aarch64__)
    //     return &memtag_dynamic_entries_;
    // #else
    //     return nullptr;
    // #endif
    // }
    // void* memtag_globals() const {
    //     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    //     return entries ? entries->memtag_globals : nullptr;
    // }
    // size_t memtag_globalssz() const {
    //     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    //     return entries ? entries->memtag_globalssz : 0U;
    // }
    // bool has_memtag_mode() const {
    //     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    //     return entries ? entries->has_memtag_mode : false;
    // }
    // unsigned memtag_mode() const {
    //     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    //     return entries ? entries->memtag_mode : 0U;
    // }
    // bool memtag_heap() const {
    //     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    //     return entries ? entries->memtag_heap : false;
    // }
    // bool memtag_stack() const {
    //     const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    //     return entries ? entries->memtag_stack : false;
    // }

    // void set_should_pad_segments(bool should_pad_segments) {
    //     should_pad_segments_ = should_pad_segments;
    // }
    // bool should_pad_segments() const { return should_pad_segments_; }
    // bool should_tag_memtag_globals() const {
    //     return !is_linker() && memtag_globals() && memtag_globalssz() > 0 &&
    //     __libc_mte_enabled();
    // }
    // std::list<std::string>* vma_names() {
    // #if defined(__aarch64__)
    //     return &vma_names_;
    // #else
    //     return nullptr;
    // #endif
    // };

    // void set_should_use_16kib_app_compat(bool should_use_16kib_app_compat) {
    //     should_use_16kib_app_compat_ = should_use_16kib_app_compat;
    // }
    // bool should_use_16kib_app_compat() const { return should_use_16kib_app_compat_; }

    // void set_compat_relro_start(ElfW(Addr) start) { compat_relro_start_ = start; }
    // ElfW(Addr) compat_relro_start() const { return compat_relro_start_; }

    // void set_compat_relro_size(ElfW(Addr) size) { compat_relro_size_ = size; }
    // ElfW(Addr) compat_relro_size() const { return compat_relro_start_; }

private:
    bool is_image_linked() const;
    void set_image_linked();

    // const ElfW(Sym) * gnu_lookup(SymbolName& symbol_name, const version_info* vi) const;
    // const ElfW(Sym) * elf_lookup(SymbolName& symbol_name, const version_info* vi) const;
    ElfW(Sym) * gnu_addr_lookup(const void* addr);
    ElfW(Sym) * elf_addr_lookup(const void* addr);

public:
    // bool lookup_version_info(const VersionTracker& version_tracker, ElfW(Word) sym,
    //                          const char* sym_name, const version_info** vi);

private:
    // bool relocate(const SymbolLookupList& lookup_list);

    // This part of the structure is only available
    // when FLAG_NEW_SOINFO is set in this->flags.
    uint32_t version_;

    // version >= 0
    dev_t st_dev_;
    ino_t st_ino_;

    // dependency graph
    soinfo_list_t children_;
    soinfo_list_t parents_;

    // version >= 1
    off64_t file_offset_;
    uint32_t rtld_flags_;
    uint32_t dt_flags_1_;
    size_t strtab_size_;

    // version >= 2

    size_t gnu_nbucket_;
    uint32_t* gnu_bucket_;
    uint32_t* gnu_chain_;
    uint32_t gnu_maskwords_;
    uint32_t gnu_shift2_;
    ElfW(Addr) * gnu_bloom_filter_;

    soinfo* local_group_root_;

    uint8_t* android_relocs_;
    size_t android_relocs_size_;

    std::string soname_;
    std::string realpath_;

    const ElfW(Versym) * versym_;

    ElfW(Addr) verdef_ptr_;
    size_t verdef_cnt_;

    ElfW(Addr) verneed_ptr_;
    size_t verneed_cnt_;

    int target_sdk_version_;

    // // version >= 3
    // std::vector<std::string> dt_runpath_;
    // android_namespace_t* primary_namespace_;
    // android_namespace_list_t secondary_namespaces_;
    // uintptr_t handle_;

    // friend soinfo* get_libdl_info(const soinfo& linker_si);

    // // version >= 4
    // ElfW(Relr) * relr_;
    // size_t relr_count_;

    // // version >= 5
    // std::unique_ptr<soinfo_tls> tls_;
    // std::vector<TlsDynamicResolverArg> tlsdesc_args_;

    // // version >= 6
    // ElfW(Addr) gap_start_;
    // size_t gap_size_;

    // // __aarch64__ only, which does not use versioning.
    // memtag_dynamic_entries_t memtag_dynamic_entries_;
    // std::list<std::string> vma_names_;

    // // Pad gaps between segments when memory mapping?
    // bool should_pad_segments_ = false;

    // // Use app compat mode when loading 4KiB max-page-size ELFs on 16KiB page-size devices?
    // bool should_use_16kib_app_compat_ = false;

    // // RELRO region for 16KiB compat loading
    // ElfW(Addr) compat_relro_start_ = 0;
    // ElfW(Addr) compat_relro_size_ = 0;

public:
    static constexpr size_t get_size_offset() { return offsetof(soinfo, size); }

    static constexpr size_t get_next_offset() { return offsetof(soinfo, next); }

    static constexpr size_t get_constructors_called_offset() {
        return offsetof(soinfo, constructors_called);
    }

    static constexpr size_t get_realpath_offset() { return offsetof(soinfo, realpath_); }
};
