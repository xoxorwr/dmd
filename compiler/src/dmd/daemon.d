module dmd.daemon;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import core.sys.posix.unistd;
import core.sys.posix.sys.stat;
import core.sys.posix.sys.socket;
import core.sys.posix.sys.un;
import core.sys.posix.dirent;
import core.sys.posix.stdio : popen, pclose;

import dmd.globals;
import dmd.dmodule;
import dmd.arraytypes;
import dmd.errors;
import dmd.main;
import dmd.root.file;
import dmd.root.filename;
import dmd.root.string;
import dmd.common.outbuffer;

struct Reloc
{
    uint offset;
    ubyte type;
    string symbol;
    long addend;
}

struct Patch
{
    string mangledName;
    ubyte[] code;
    ubyte[] rodata;
    Reloc[] relocs;
}

__gshared bool g_has_watched = false;

// Simple helpers
private bool canFind(const(string)[] arr, string val)
{
    foreach (item; arr)
        if (item == val) return true;
    return false;
}

private bool endsWith(const(char)[] str, const(char)[] suffix)
{
    return str.length >= suffix.length && str[$ - suffix.length .. $] == suffix;
}

private bool startsWith(const(char)[] str, const(char)[] prefix)
{
    return str.length >= prefix.length && str[0 .. prefix.length] == prefix;
}

private string dirName(string path)
{
    if (path.length == 0) return "";
    for (size_t idx = path.length; idx > 0; idx--)
    {
        size_t i = idx - 1;
        if (path[i] == '/')
        {
            return i == 0 ? "/" : path[0 .. i];
        }
    }
    return "";
}

private string baseName(string path)
{
    if (path.length == 0) return "";
    for (size_t idx = path.length; idx > 0; idx--)
    {
        size_t i = idx - 1;
        if (path[i] == '/')
        {
            return path[i + 1 .. $];
        }
    }
    return path;
}

private string stripExtension(string path)
{
    if (path.length == 0) return "";
    for (size_t idx = path.length; idx > 0; idx--)
    {
        size_t i = idx - 1;
        if (path[i] == '/')
            break;
        if (path[i] == '.')
        {
            return path[0 .. i];
        }
    }
    return path;
}

private string strip(string s)
{
    while (s.length > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n'))
        s = s[1 .. $];
    while (s.length > 0 && (s[$ - 1] == ' ' || s[$ - 1] == '\t' || s[$ - 1] == '\r' || s[$ - 1] == '\n'))
        s = s[0 .. $ - 1];
    return s;
}

private string join(const(string)[] arr, string sep)
{
    OutBuffer buf;
    foreach (i, item; arr)
    {
        if (i > 0)
            buf.write(sep);
        buf.write(item);
    }
    return cast(string)buf[].idup;
}

private long getFileMtime(string path)
{
    import dmd.root.string : toCString;
    stat_t statbuf;
    if (stat(toCString(path).ptr, &statbuf) == 0)
    {
        return statbuf.st_mtime;
    }
    return 0;
}

private void scanDirRecursive(string path, ref string[] files, ref string[] dirs)
{
    import dmd.root.string : toCString;
    DIR* d = opendir(toCString(path).ptr);
    if (!d) return;
    scope(exit) closedir(d);

    while (auto entry = readdir(d))
    {
        string name = entry.d_name.ptr.toDString().idup;
        if (name == "." || name == "..")
            continue;

        string fullPath = path;
        if (fullPath.length > 0 && fullPath[$ - 1] != '/')
            fullPath ~= "/";
        fullPath ~= name;

        stat_t statbuf;
        if (stat(toCString(fullPath).ptr, &statbuf) == 0)
        {
            if (S_ISDIR(statbuf.st_mode))
            {
                if (!dirs.canFind(fullPath))
                {
                    dirs ~= fullPath;
                    scanDirRecursive(fullPath, files, dirs);
                }
            }
            else if (S_ISREG(statbuf.st_mode))
            {
                if (endsWith(name, ".d") && !files.canFind(fullPath))
                {
                    files ~= fullPath;
                }
            }
        }
    }
}

void dmd_watch_loop(const(char)[][] argv, ref Param params, ref Strings files)
{
    printf("[daemon] Entering watch mode...\n");

    // Get list of source files explicitly passed, and their directories
    string[] watchFiles;
    string[] watchDirs;

    for (size_t i = 0; i < files.length; i++)
    {
        string f = files[i].toDString().idup;
        if (endsWith(f, ".d"))
        {
            if (!watchFiles.canFind(f))
                watchFiles ~= f;

            string dir = dirName(f);
            if (dir.length > 0 && !watchDirs.canFind(dir))
                watchDirs ~= dir;
        }
    }

    // Parse -I flags from argv to find source directories
    for (size_t i = 1; i < argv.length; i++)
    {
        string arg = argv[i].idup;
        if (startsWith(arg, "-I"))
        {
            string dir = arg[2 .. $];
            if (dir.length > 0)
            {
                if (!watchDirs.canFind(dir))
                    watchDirs ~= dir;
            }
            else if (i + 1 < argv.length)
            {
                dir = argv[i + 1].idup;
                if (!watchDirs.canFind(dir))
                    watchDirs ~= dir;
                i++; // skip next arg
            }
        }
    }

    // Initial table of watched functions and their last known code hashes/sizes
    struct FuncCache
    {
        ubyte[] code;
        ubyte[] rodata;
    }
    FuncCache[string] cachedFuncs;

    // Track file timestamps
    long[string] lastModified;

    // Helper to scan watchDirs recursively for .d files
    void scanDirectories()
    {
        foreach (dir; watchDirs)
        {
            if (FileName.exists(dir) == 2) // exists and is directory
            {
                scanDirRecursive(dir, watchFiles, watchDirs);
            }
        }
    }

    // Scan directories to find imported/project files recursively
    scanDirectories();

    // Initialize timestamps for all watched files
    foreach (f; watchFiles)
    {
        lastModified[f] = getFileMtime(f);
    }

    if (watchFiles.length == 0)
    {
        printf("[daemon] No source files to watch. Exiting.\n");
        return;
    }

    printf("[daemon] Watching %d files recursively across %d source directories.\n", cast(int)watchFiles.length, cast(int)watchDirs.length);

    // Determine the child compiler path
    string dmdPath = argv[0].idup;

    // Build the command line for child compiler:
    // We want to compile the files to .o, but not link.
    // So we replace the link/run/etc options or simply run with `-c`.
    string[] compileArgs = [dmdPath, "-c"];
    for (size_t i = 1; i < argv.length; i++)
    {
        string arg = argv[i].idup;
        // Strip flags that might trigger running/linking
        if (arg == "-run" || arg == "--run" || arg == "-watch" || arg == "--watch")
            continue;
        if (startsWith(arg, "-of="))
        {
            string outPath = arg["-of=".length .. $];
            if (!endsWith(outPath, ".o"))
            {
                compileArgs ~= "-of=" ~ outPath ~ ".o";
                continue;
            }
        }
        else if (startsWith(arg, "-of") && arg.length > 3)
        {
            string outPath = arg[3 .. $];
            if (!endsWith(outPath, ".o"))
            {
                compileArgs ~= "-of" ~ outPath ~ ".o";
                continue;
            }
        }
        compileArgs ~= arg;
    }

    // Watch loop
    bool running = true;
    while (running)
    {
        // Sleep for 100ms
        usleep(100_000);

        // Check if any file changed
        string[] changedFiles;
        foreach (f; watchFiles)
        {
            auto mt = getFileMtime(f);
            auto p = f in lastModified;
            if (!p)
            {
                lastModified[f] = mt;
            }
            else if (mt > *p)
            {
                lastModified[f] = mt;
                changedFiles ~= f;
            }
        }

        if (changedFiles.length == 0)
            continue;

        string changedFilesJoined = changedFiles.join(", ");
        printf("\n[daemon] Files changed: %.*s\n", cast(int)changedFilesJoined.length, changedFilesJoined.ptr);
        printf("[daemon] Recompiling...\n");

        printf("[daemon] Spawning child compiler: ");
        foreach (arg; compileArgs)
        {
            printf("%.*s ", cast(int)arg.length, arg.ptr);
        }
        printf("\n");

        // Run child compiler process
        // We capture the output using popen to read the [dpatch-watched] list
        OutBuffer cmdBuf;
        foreach (i, arg; compileArgs)
        {
            if (i > 0)
                cmdBuf.writeByte(' ');
            cmdBuf.write(arg);
        }
        cmdBuf.write(" 2>&1");
        cmdBuf.writeByte(0);

        FILE* f = popen(cast(char*)cmdBuf.peekChars(), "r");
        if (!f)
        {
            printf("[daemon] Error: failed to spawn child compiler\n");
            continue;
        }

        char[2048] lineBuf;
        string[] watchedNames;
        while (fgets(lineBuf.ptr, lineBuf.length, f))
        {
            string line = lineBuf.ptr.toDString().idup;
            while (line.length > 0 && (line[$ - 1] == '\n' || line[$ - 1] == '\r'))
                line = line[0 .. $ - 1];

            if (startsWith(line, "[dpatch-watched] "))
            {
                watchedNames ~= strip(line["[dpatch-watched] ".length .. $]);
            }
            else
            {
                printf("%.*s\n", cast(int)line.length, line.ptr);
            }
        }

        int status = pclose(f);
        int exitStatus = (status >> 8) & 0xFF;

        if (exitStatus != 0)
        {
            printf("[daemon] Compilation failed (exit code %d). Waiting for changes.\n", exitStatus);
            continue;
        }

        // Scan for any new files added during development
        scanDirectories();

        if (watchedNames.length == 0)
        {
            printf("[daemon] No @watch functions detected.\n");
            continue;
        }

        string[] objFiles;

        // If -of was specified, check it. Otherwise, look for .o files corresponding to watched files.
        string outObj = null;
        for (size_t i = 0; i < compileArgs.length; i++)
        {
            if (startsWith(compileArgs[i], "-of="))
            {
                outObj = compileArgs[i]["-of=".length .. $];
                break;
            }
        }

        if (outObj)
        {
            if (endsWith(outObj, ".o"))
                objFiles ~= outObj;
            else
                objFiles ~= outObj ~ ".o";
        }
        else
        {
            foreach (wf; watchFiles)
            {
                string base = baseName(wf);
                string baseNoExt = stripExtension(base);
                string obj = baseNoExt ~ ".o";
                if (FileName.exists(obj) == 1)
                    objFiles ~= obj;
            }
        }

        Patch[] patches;

        foreach (obj; objFiles)
        {
            auto extracted = extractPatchesFromObj(obj, watchedNames);
            foreach (p; extracted)
            {
                patches ~= p;
            }
        }

        // Filter patches to keep only those that changed
        Patch[] changedPatches;
        foreach (p; patches)
        {
            auto cache = p.mangledName in cachedFuncs;
            if (cache is null || cache.code != p.code || cache.rodata != p.rodata)
            {
                cachedFuncs[p.mangledName] = FuncCache(p.code, p.rodata);
                changedPatches ~= p;
            }
        }

        if (changedPatches.length == 0)
        {
            printf("[daemon] Compilation succeeded but no @watch function bodies changed.\n");
            continue;
        }

        // Send patches to all active targets
        dmd_send_patches(changedPatches);
    }
}

// Binary layout structures matching the wire protocol
private struct Elf64_Ehdr {
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

private struct Elf64_Shdr {
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

private struct Elf64_Sym {
    uint      st_name;
    ubyte     st_info;
    ubyte     st_other;
    ushort    st_shndx;
    ulong     st_value;
    ulong     st_size;
}

private struct Elf64_Rela {
    ulong      r_offset;
    ulong      r_info;
    long       r_addend;
}

private ulong ELF64_R_SYM(ulong info) { return info >> 32; }
private ulong ELF64_R_TYPE(ulong info) { return info & 0xFFFFFFFF; }

private enum SHT_SYMTAB = 2;
private enum SHT_RELA = 4;

private string find_symbol_for_offset(Elf64_Sym* syms, size_t num_syms, char* strtab, ushort shndx, ref long addend)
{
    Elf64_Sym* best_sym = null;
    for (size_t i = 0; i < num_syms; i++)
    {
        auto sym = &syms[i];
        if (sym.st_shndx != shndx) continue;
        if (sym.st_name == 0) continue;

        ubyte type = sym.st_info & 0xf;
        if (type == 3) continue; // Skip section symbols

        if (sym.st_value <= addend)
        {
            if (best_sym is null || sym.st_value > best_sym.st_value)
            {
                best_sym = sym;
            }
        }
    }

    if (best_sym !is null)
    {
        string name = (&strtab[best_sym.st_name]).toDString().idup;
        if (name.length > 0)
        {
            addend -= best_sym.st_value;
            return name;
        }
    }
    return null;
}

// Parses ELF file to extract function code and relocations
private Patch[] extractPatchesFromObj(string objFile, string[] watchedNames)
{
    Patch[] result;

    OutBuffer buf;
    if (File.read(objFile, buf) == true) // Failure
        return result;

    auto data = buf[];
    if (data.length < Elf64_Ehdr.sizeof) return result;

    auto ehdr = cast(Elf64_Ehdr*)data.ptr;
    if (ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F')
        return result;

    // Get section headers
    if (ehdr.e_shoff + ehdr.e_shnum * Elf64_Shdr.sizeof > data.length) return result;
    auto shdrs = cast(Elf64_Shdr*)(data.ptr + ehdr.e_shoff);
    if (ehdr.e_shstrndx >= ehdr.e_shnum) return result;
    auto shstr_shdr = &shdrs[ehdr.e_shstrndx];
    if (shstr_shdr.sh_offset + shstr_shdr.sh_size > data.length) return result;
    auto shstrtab = cast(char*)(data.ptr + shstr_shdr.sh_offset);

    // Find symbol table (.symtab) and string table (.strtab)
    Elf64_Shdr* symtab_shdr = null;
    Elf64_Shdr* strtab_shdr = null;
    for (int i = 0; i < ehdr.e_shnum; i++)
    {
        if (shdrs[i].sh_type == SHT_SYMTAB)
        {
            symtab_shdr = &shdrs[i];
            if (symtab_shdr.sh_link >= ehdr.e_shnum) return result;
            strtab_shdr = &shdrs[symtab_shdr.sh_link];
            break;
        }
    }

    if (!symtab_shdr || !strtab_shdr) return result;

    if (symtab_shdr.sh_offset + symtab_shdr.sh_size > data.length) return result;
    if (strtab_shdr.sh_offset + strtab_shdr.sh_size > data.length) return result;

    auto syms = cast(Elf64_Sym*)(data.ptr + symtab_shdr.sh_offset);
    size_t num_syms = cast(size_t)(symtab_shdr.sh_size / Elf64_Sym.sizeof);
    auto strtab = cast(char*)(data.ptr + strtab_shdr.sh_offset);

    uint[ushort] sectionOffsets;
    ubyte[] rodataBytes;

    for (int i = 0; i < ehdr.e_shnum; i++)
    {
        if (shdrs[i].sh_name >= shstr_shdr.sh_size) continue;
        const(char)* secName = &shstrtab[shdrs[i].sh_name];
        if (strncmp(secName, ".rodata", 7) == 0)
        {
            sectionOffsets[cast(ushort)i] = cast(uint)rodataBytes.length;
            if (shdrs[i].sh_size > 0)
            {
                auto offset = cast(size_t)shdrs[i].sh_offset;
                auto size = cast(size_t)shdrs[i].sh_size;
                if (offset + size > data.length) continue;
                auto secData = cast(ubyte[])data[offset .. offset + size];
                auto oldLen = rodataBytes.length;
                rodataBytes.length = oldLen + secData.length;
                rodataBytes[oldLen .. $] = secData[];
            }
        }
    }

    foreach (name; watchedNames)
    {
        // Find symbol for name
        Elf64_Sym* func_sym = null;
        for (size_t i = 0; i < num_syms; i++)
        {
            if (syms[i].st_name >= strtab_shdr.sh_size) continue;
            string symName = (&strtab[syms[i].st_name]).toDString().idup;
            if (symName == name)
            {
                func_sym = &syms[i];
                break;
            }
        }

        if (!func_sym || func_sym.st_shndx >= ehdr.e_shnum)
            continue;

        // Get function code using symbol's offset and size within its section
        auto func_sec = &shdrs[func_sym.st_shndx];
        auto func_offset_in_sec = cast(size_t)func_sym.st_value;
        auto func_size = cast(size_t)func_sym.st_size;
        if (func_size == 0)
            func_size = cast(size_t)func_sec.sh_size; // fallback if st_size not set
        auto func_file_offset = cast(size_t)func_sec.sh_offset + func_offset_in_sec;
        if (func_file_offset + func_size > data.length)
            continue;
        ubyte[] code = cast(ubyte[])data[func_file_offset .. func_file_offset + func_size].dup;

        // Find relocation section for this section
        Elf64_Shdr* rela_sec = null;
        for (int i = 0; i < ehdr.e_shnum; i++)
        {
            if (shdrs[i].sh_type == SHT_RELA && shdrs[i].sh_info == func_sym.st_shndx)
            {
                rela_sec = &shdrs[i];
                break;
            }
        }

        Reloc[] relocs;
        if (rela_sec)
        {
            if (rela_sec.sh_offset + rela_sec.sh_size > data.length) continue;
            auto relas = cast(Elf64_Rela*)(data.ptr + rela_sec.sh_offset);
            size_t num_relas = cast(size_t)(rela_sec.sh_size / Elf64_Rela.sizeof);

            for (size_t r = 0; r < num_relas; r++)
            {
                // Skip relocations outside this function's range
                if (relas[r].r_offset < func_offset_in_sec ||
                    relas[r].r_offset >= func_offset_in_sec + func_size)
                    continue;
                auto rela = &relas[r];
                ulong sym_idx = ELF64_R_SYM(rela.r_info);
                ulong rel_type = ELF64_R_TYPE(rela.r_info);

                if (sym_idx >= num_syms) continue;
                if (syms[sym_idx].st_name >= strtab_shdr.sh_size) continue;
                string sym_name = (&strtab[syms[sym_idx].st_name]).toDString().idup;
                ushort shndx = syms[sym_idx].st_shndx;
                long addend = rela.r_addend;

                if (shndx < ehdr.e_shnum && (shndx in sectionOffsets))
                {
                    sym_name = ".rodata";
                    addend += syms[sym_idx].st_value;
                    addend += sectionOffsets[shndx];
                }
                else
                {
                    ubyte st_type = syms[sym_idx].st_info & 0xf;
                    bool is_section_reloc = (st_type == 3); // STT_SECTION

                    if (is_section_reloc && sym_name.length == 0)
                    {
                        if (shndx < ehdr.e_shnum)
                        {
                            if (shdrs[shndx].sh_name >= shstr_shdr.sh_size) continue;
                            sym_name = (&shstrtab[shdrs[shndx].sh_name]).toDString().idup;
                        }
                    }

                    if (is_section_reloc && shndx < ehdr.e_shnum)
                    {
                        string named_sym = find_symbol_for_offset(syms, num_syms, strtab, shndx, addend);
                        if (named_sym.length > 0)
                        {
                            sym_name = named_sym;
                        }
                    }
                }

                ubyte type = 0;
                if (rel_type == 1) // R_X86_64_64 (abs64)
                    type = 1;
                else if (rel_type == 2 || rel_type == 4) // R_X86_64_PC32 / R_X86_64_PLT32 (rel32)
                    type = 2;
                else if (rel_type == 9 || rel_type == 41 || rel_type == 42) // R_X86_64_GOTPCREL / GOTPCRELX / REX_GOTPCRELX (gotpcrel32)
                    type = 3;
                else if (rel_type == 19) // R_X86_64_TLSGD (tlsgd32)
                    type = 4;

                if (type != 0)
                {
                    // Adjust offset to be relative to function start, not section start
                    uint func_relative_offset = cast(uint)(rela.r_offset - func_offset_in_sec);
                    relocs ~= Reloc(func_relative_offset, type, sym_name, addend);
                }
            }
        }

        result ~= Patch(name, code, rodataBytes, relocs);
    }

    return result;
}

// Sends patches over Unix domain sockets to all /tmp/dpatch-*.sock
private void dmd_send_patches(Patch[] patches)
{
    // Search for all active socket files
    string[] sockets;
    DIR* d = opendir("/tmp");
    if (d)
    {
        scope(exit) closedir(d);
        while (auto entry = readdir(d))
        {
            string name = entry.d_name.ptr.toDString().idup;
            if (startsWith(name, "dpatch-") && endsWith(name, ".sock"))
            {
                sockets ~= "/tmp/" ~ name;
            }
        }
    }

    if (sockets.length == 0)
    {
        printf("[daemon] No active dpatch socket targets found in /tmp. Make sure your program is running.\n");
        return;
    }

    ubyte[] payload;

    uint magic = 0x44505443;
    payload ~= (cast(ubyte*)&magic)[0..4];

    ushort version_ = 2;
    payload ~= (cast(ubyte*)&version_)[0..2];

    ushort num_funcs = cast(ushort)patches.length;
    payload ~= (cast(ubyte*)&num_funcs)[0..2];

    foreach (p; patches)
    {
        ushort name_len = cast(ushort)p.mangledName.length;
        payload ~= (cast(ubyte*)&name_len)[0..2];

        payload ~= cast(ubyte[])p.mangledName;

        uint code_len = cast(uint)p.code.length;
        payload ~= (cast(ubyte*)&code_len)[0..4];

        payload ~= p.code;

        uint rodata_len = cast(uint)p.rodata.length;
        payload ~= (cast(ubyte*)&rodata_len)[0..4];

        payload ~= p.rodata;

        ushort num_relocs = cast(ushort)p.relocs.length;
        payload ~= (cast(ubyte*)&num_relocs)[0..2];

        foreach (r; p.relocs)
        {
            payload ~= (cast(ubyte*)&r.offset)[0..4];

            payload ~= r.type;

            ushort sym_len = cast(ushort)r.symbol.length;
            payload ~= (cast(ubyte*)&sym_len)[0..2];

            payload ~= cast(ubyte[])r.symbol;

            payload ~= (cast(ubyte*)&r.addend)[0..8];
        }
    }

    int activeSocketsCount = 0;
    int successfulSends = 0;

    foreach (sockPath; sockets)
    {
        import dmd.root.string : toCString;
        auto sockPathC = toCString(sockPath);

        // Parse PID from name "dpatch-<pid>.sock"
        string base = baseName(sockPath);
        if (startsWith(base, "dpatch-") && endsWith(base, ".sock"))
        {
            string pidStr = base["dpatch-".length .. $ - ".sock".length];
            import core.stdc.stdlib : atoi;
            int pid = atoi(toCString(pidStr).ptr);
            if (pid > 0)
            {
                import core.sys.posix.signal : kill;
                import core.stdc.errno : errno, ESRCH;
                if (kill(pid, 0) == -1 && errno == ESRCH)
                {
                    // Process is dead! Remove the stale socket file
                    unlink(sockPathC.ptr);
                    continue;
                }
            }
        }

        activeSocketsCount++;
        printf("[daemon] Pushing patches to %.*s...\n", cast(int)sockPath.length, sockPath.ptr);

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0)
        {
            sockaddr_un addr;
            addr.sun_family = AF_UNIX;

            if (sockPath.length < addr.sun_path.sizeof)
            {
                memcpy(addr.sun_path.ptr, sockPath.ptr, sockPath.length);
                addr.sun_path[sockPath.length] = '\0';

                if (connect(fd, cast(sockaddr*)&addr, addr.sizeof) == 0)
                {
                    size_t sent = 0;
                    bool success = true;
                    while (sent < payload.length)
                    {
                        auto s = send(fd, payload.ptr + sent, payload.length - sent, 0);
                        if (s <= 0)
                        {
                            success = false;
                            break;
                        }
                        sent += s;
                    }
                    if (success)
                    {
                        printf("[daemon] Successfully sent patch payload (%d bytes, %d functions).\n", cast(int)payload.length, cast(int)patches.length);
                        successfulSends++;
                    }
                    else
                    {
                        printf("[daemon] Send failed to %.*s\n", cast(int)sockPath.length, sockPath.ptr);
                    }
                }
                else
                {
                    printf("[daemon] Connect failed to %.*s\n", cast(int)sockPath.length, sockPath.ptr);
                }
            }
            else
            {
                printf("[daemon] Socket path too long: %.*s (max: %d bytes)\n", cast(int)sockPath.length, sockPath.ptr, cast(int)addr.sun_path.sizeof - 1);
            }
            close(fd);
        }
    }

    if (activeSocketsCount == 0 || successfulSends == 0)
    {
        printf("[daemon] Warning: No active running target processes received the patch.\n");
        printf("         Make sure your program is running with libdpatch.so initialized.\n");
        printf("         If using manual initialization, ensure dpatch_init() was called.\n");
        printf("         If using LD_PRELOAD, run your program with:\n");
        printf("         LD_PRELOAD=<path-to>/libdpatch.so ./<your-program>\n");
    }
}
