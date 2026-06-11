module core.dpatch.resolver;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;

// From dlfn.h / link.h
extern(C) {
    void* dlsym(void* handle, const(char)* symbol);
    alias dl_phdr_callback = int function(dl_phdr_info* info, size_t size, void* data) @system;
    int dl_iterate_phdr(dl_phdr_callback callback, void* data) @system;
}

enum RTLD_DEFAULT = cast(void*)0;

struct dl_phdr_info
{
    ulong dlpi_addr;
    const(char)* dlpi_name;
    // other fields omitted for simplicity
}

// ELF 64-bit definitions
struct Elf64_Ehdr {
    ubyte[16] e_ident;
    ushort    e_type;
    ushort    e_machine;
    uint      e_version;
    ulong     e_entry;
    ulong     e_phoff;
    ulong     e_shoff;
    uint      e_flags;
    ushort    e_ehsize;
    ushort    e_phentsize;
    ushort    e_phnum;
    ushort    e_shentsize;
    ushort    e_shnum;
    ushort    e_shstrndx;
}

struct Elf64_Shdr {
    uint      sh_name;
    uint      sh_type;
    ulong     sh_flags;
    ulong     sh_addr;
    ulong     sh_offset;
    ulong     sh_size;
    uint      sh_link;
    uint      sh_info;
    ulong     sh_addralign;
    ulong     sh_entsize;
}

struct Elf64_Sym {
    uint      st_name;
    ubyte     st_info;
    ubyte     st_other;
    ushort    st_shndx;
    ulong     st_value;
    ulong     st_size;
}

enum SHT_SYMTAB = 2;

__gshared ulong g_base_address = 0;
__gshared bool g_base_address_found = false;

extern(C) int dpatch_phdr_callback(dl_phdr_info* info, size_t size, void* data) @system
{
    g_base_address = info.dlpi_addr;
    g_base_address_found = true;
    return 1; // The main program is always the first visited entry
}

extern(C) ulong dpatch_get_base_address()
{
    if (!g_base_address_found)
    {
        dl_iterate_phdr(&dpatch_phdr_callback, null);
    }
    if (g_base_address_found && g_base_address == 0)
    {
        return 0x400000; // Default non-PIE base address
    }
    return g_base_address;
}

// Resolves a symbol address.
// 1. Tries dlsym
// 2. If not found, parses /proc/self/exe to read the ELF symbol table.
extern(C) void* dpatch_resolve_symbol(const(char)* name)
{
    // If the symbol name starts with '.', it's a section name
    if (name != null && name[0] == '.')
    {
        FILE* f = fopen("/proc/self/exe", "rb");
        if (!f) return null;
        scope(exit) fclose(f);

        Elf64_Ehdr ehdr;
        if (fread(&ehdr, Elf64_Ehdr.sizeof, 1, f) != 1) return null;

        // Read section headers
        if (fseek(f, cast(long)ehdr.e_shoff, SEEK_SET) != 0) return null;
        Elf64_Shdr[] shdrs = (cast(Elf64_Shdr*)malloc(Elf64_Shdr.sizeof * ehdr.e_shnum))[0 .. ehdr.e_shnum];
        if (!shdrs.ptr) return null;
        scope(exit) free(shdrs.ptr);

        if (fread(shdrs.ptr, Elf64_Shdr.sizeof, ehdr.e_shnum, f) != ehdr.e_shnum) return null;

        // Read section header string table
        Elf64_Shdr* shstr_shdr = &shdrs[ehdr.e_shstrndx];
        char[] shstrtab = (cast(char*)malloc(cast(size_t)shstr_shdr.sh_size))[0 .. cast(size_t)shstr_shdr.sh_size];
        if (!shstrtab.ptr) return null;
        scope(exit) free(shstrtab.ptr);

        if (fseek(f, cast(long)shstr_shdr.sh_offset, SEEK_SET) != 0) return null;
        if (fread(shstrtab.ptr, 1, cast(size_t)shstr_shdr.sh_size, f) != cast(size_t)shstr_shdr.sh_size) return null;

        ulong base_addr = dpatch_get_base_address();

        for (int i = 0; i < ehdr.e_shnum; i++)
        {
            if (shdrs[i].sh_name < shstr_shdr.sh_size)
            {
                const(char)* sec_name = &shstrtab[shdrs[i].sh_name];
                if (strcmp(sec_name, name) == 0)
                {
                    if (ehdr.e_type == 3)
                        return cast(void*)(base_addr + shdrs[i].sh_addr);
                    else
                        return cast(void*)(shdrs[i].sh_addr);
                }
            }
        }
        return null;
    }

    // First try dlsym
    void* addr = dlsym(RTLD_DEFAULT, name);
    if (addr != null)
    {
        return addr;
    }

    // Fall back to reading /proc/self/exe ELF symbol table
    FILE* f = fopen("/proc/self/exe", "rb");
    if (!f)
    {
        return null;
    }
    scope(exit) fclose(f);

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, Elf64_Ehdr.sizeof, 1, f) != 1)
    {
        return null;
    }

    // Verify ELF header
    if (ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F')
    {
        return null;
    }

    // Read section headers
    if (fseek(f, cast(long)ehdr.e_shoff, SEEK_SET) != 0)
    {
        return null;
    }

    Elf64_Shdr[] shdrs = (cast(Elf64_Shdr*)malloc(Elf64_Shdr.sizeof * ehdr.e_shnum))[0 .. ehdr.e_shnum];
    if (!shdrs.ptr)
    {
        return null;
    }
    scope(exit) free(shdrs.ptr);

    if (fread(shdrs.ptr, Elf64_Shdr.sizeof, ehdr.e_shnum, f) != ehdr.e_shnum)
    {
        return null;
    }

    // Find symbol table (.symtab) and its associated string table
    Elf64_Shdr* symtab_shdr = null;
    Elf64_Shdr* strtab_shdr = null;

    for (int i = 0; i < ehdr.e_shnum; i++)
    {
        if (shdrs[i].sh_type == SHT_SYMTAB)
        {
            symtab_shdr = &shdrs[i];
            if (symtab_shdr.sh_link < ehdr.e_shnum)
            {
                strtab_shdr = &shdrs[symtab_shdr.sh_link];
            }
            break;
        }
    }

    if (!symtab_shdr || !strtab_shdr)
    {
        return null;
    }

    // Read symbol table entries
    size_t num_syms = cast(size_t)(symtab_shdr.sh_size / Elf64_Sym.sizeof);
    Elf64_Sym[] syms = (cast(Elf64_Sym*)malloc(symtab_shdr.sh_size))[0 .. num_syms];
    if (!syms.ptr)
    {
        return null;
    }
    scope(exit) free(syms.ptr);

    if (fseek(f, cast(long)symtab_shdr.sh_offset, SEEK_SET) != 0)
    {
        return null;
    }
    if (fread(syms.ptr, Elf64_Sym.sizeof, num_syms, f) != num_syms)
    {
        return null;
    }

    // Read string table
    char[] strtab = (cast(char*)malloc(cast(size_t)strtab_shdr.sh_size))[0 .. cast(size_t)strtab_shdr.sh_size];
    if (!strtab.ptr)
    {
        return null;
    }
    scope(exit) free(strtab.ptr);

    if (fseek(f, cast(long)strtab_shdr.sh_offset, SEEK_SET) != 0)
    {
        return null;
    }
    if (fread(strtab.ptr, 1, cast(size_t)strtab_shdr.sh_size, f) != cast(size_t)strtab_shdr.sh_size)
    {
        return null;
    }

    // Search for symbol by name
    ulong base_addr = dpatch_get_base_address();

    for (size_t i = 0; i < num_syms; i++)
    {
        if (syms[i].st_shndx == 0) continue;
        if (syms[i].st_name < strtab_shdr.sh_size)
        {
            const(char)* sym_name = &strtab[syms[i].st_name];
            if (strcmp(sym_name, name) == 0)
            {
                // Found it!
                // PIE binaries need symbol value offset by base address
                // Non-PIE binaries have the absolute address directly in st_value
                // A simple check: if e_type == 3 (ET_DYN, which is PIE/shared lib), we offset it.
                if (ehdr.e_type == 3)
                {
                    return cast(void*)(base_addr + syms[i].st_value);
                }
                else
                {
                    return cast(void*)(syms[i].st_value);
                }
            }
        }
    }

    return null;
}
