module core.dpatch.dpatch;

import core.sys.posix.sys.socket;
import core.sys.posix.sys.un;
import core.sys.posix.unistd;
import core.sys.posix.fcntl;
import core.sys.posix.poll;
import core.sys.posix.sys.time;
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import core.stdc.errno;

import core.dpatch.trampoline;
import core.dpatch.codepage;
import core.dpatch.resolver;

extern(C):

struct TlsSlot
{
    const(char)* sym_name;
    long offset;
    bool inited;
}

private void* dpatch_get_tls_base()
{
    void* tp;
    asm
    {
        xor RAX, RAX;
        mov RAX, FS:[RAX];
        mov tp, RAX;
    }
    return tp;
}

extern(C) void* dpatch_tls_get_addr(void* ti)
{
    auto slot = cast(TlsSlot*)ti;
    if (!slot.inited)
    {
        void* addr = dpatch_resolve_symbol(slot.sym_name);
        if (!addr)
        {
            printf("[dpatch] TLS Error: Failed to resolve symbol %s\n", slot.sym_name);
            return null;
        }
        void* tp = dpatch_get_tls_base();
        slot.offset = cast(long)addr - cast(long)tp;
        slot.inited = true;
    }
    void* tp = dpatch_get_tls_base();
    return cast(void*)(cast(long)tp + slot.offset);
}

__gshared int g_server_fd = -1;
__gshared char[256] g_sock_path;

struct RelocHeader
{
    uint offset;
    ubyte type; // 1 = R_X86_64_64 (abs64), 2 = R_X86_64_PC32/PLT32 (rel32)
    ushort symbol_len;
    long addend;
}

// Call once at startup. Opens the Unix socket.
int dpatch_init(const(char)* sock_path)
{
    if (g_server_fd != -1)
        return 0; // Already initialized

    // Determine socket path
    if (sock_path != null)
    {
        strncpy(g_sock_path.ptr, sock_path, g_sock_path.length - 1);
    }
    else
    {
        snprintf(g_sock_path.ptr, g_sock_path.length, "/tmp/dpatch-%d.sock", getpid());
    }

    // Remove old socket if exists
    unlink(g_sock_path.ptr);

    // Create Unix socket
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0)
    {
        return -1;
    }

    // Set non-blocking on server socket
    int flags = fcntl(g_server_fd, F_GETFL, 0);
    fcntl(g_server_fd, F_SETFL, flags | O_NONBLOCK);

    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(cast(char*)addr.sun_path.ptr, g_sock_path.ptr, addr.sun_path.length - 1);

    if (bind(g_server_fd, cast(sockaddr*)&addr, addr.sizeof) < 0)
    {
        close(g_server_fd);
        g_server_fd = -1;
        return -2;
    }

    if (listen(g_server_fd, 5) < 0)
    {
        close(g_server_fd);
        g_server_fd = -1;
        return -3;
    }

    printf("[dpatch] Listening for patches on %s\n", g_sock_path.ptr);
    return 0;
}

// Helper to read the exact number of bytes from a socket descriptor, handling non-blocking sockets.
private bool read_all(int fd, void* buf, size_t size)
{
    ubyte* p = cast(ubyte*)buf;
    size_t remaining = size;
    while (remaining > 0)
    {
        long n = read(fd, p, remaining);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                usleep(100); // Sleep 100 microseconds and retry
                continue;
            }
            return false;
        }
        else if (n == 0)
        {
            return false; // EOF
        }
        p += n;
        remaining -= n;
    }
    return true;
}

// Processes one patch payload received over the client socket
private int dpatch_process_payload(int fd)
{
    printf("[dpatch] Processing payload from daemon...\n");
    // Read header: magic (4 bytes), version (2 bytes), num_functions (2 bytes)
    uint magic;
    ushort version_;
    ushort num_functions;

    if (!read_all(fd, &magic, 4))
    {
        printf("[dpatch] Failed to read magic header (errno=%d)\n", errno);
        return -1;
    }
    if (magic != 0x44505443) // "DPTC"
    {
        printf("[dpatch] Invalid magic: %08X\n", magic);
        return -2;
    }

    if (!read_all(fd, &version_, 2) || !read_all(fd, &num_functions, 2))
    {
        printf("[dpatch] Failed to read version or function count (errno=%d)\n", errno);
        return -3;
    }

    printf("[dpatch] Header: Magic=DPTC, Version=%d, Functions=%d\n", cast(int)version_, cast(int)num_functions);

    int num_patched = 0;

    for (int f_idx = 0; f_idx < num_functions; f_idx++)
    {
        // Read function header: name_len (2 bytes)
        ushort name_len;
        if (!read_all(fd, &name_len, 2))
        {
            printf("[dpatch] Failed to read name_len for function %d (errno=%d)\n", f_idx, errno);
            return -4;
        }

        char* mangled_name = cast(char*)malloc(name_len + 1);
        if (!read_all(fd, mangled_name, name_len))
        {
            printf("[dpatch] Failed to read mangled_name for function %d (errno=%d)\n", f_idx, errno);
            free(mangled_name);
            return -5;
        }
        mangled_name[name_len] = '\0';

        // Read code_len (4 bytes)
        uint code_len;
        if (!read_all(fd, &code_len, 4))
        {
            printf("[dpatch] Failed to read code_len for %s (errno=%d)\n", mangled_name, errno);
            free(mangled_name);
            return -6;
        }

        printf("[dpatch] Function %d: Name=%s, CodeSize=%d bytes\n", f_idx, mangled_name, code_len);

        // Allocate temporary buffer for code
        ubyte* temp_code = cast(ubyte*)malloc(code_len);
        if (!temp_code)
        {
            printf("[dpatch] Failed to allocate temporary code buffer\n");
            free(mangled_name);
            return -7;
        }

        if (!read_all(fd, temp_code, code_len))
        {
            printf("[dpatch] Failed to read code bytes for %s (errno=%d)\n", mangled_name, errno);
            free(temp_code);
            free(mangled_name);
            return -8;
        }

        // Read rodata_len (4 bytes)
        uint rodata_len;
        if (!read_all(fd, &rodata_len, 4))
        {
            printf("[dpatch] Failed to read rodata_len for %s (errno=%d)\n", mangled_name, errno);
            free(temp_code);
            free(mangled_name);
            return -9;
        }

        // Allocate contiguous mmap page for code + rodata + GOT/stubs
        size_t total_len = code_len + rodata_len + 8192;
        void* new_code = dpatch_alloc_code_page(total_len);
        if (!new_code)
        {
            printf("[dpatch] Failed to allocate executable page for %s\n", mangled_name);
            free(temp_code);
            free(mangled_name);
            return -10;
        }

        // Copy code from temporary buffer to mmap page
        memcpy(new_code, temp_code, code_len);
        free(temp_code);

        void* new_rodata = null;
        if (rodata_len > 0)
        {
            new_rodata = new_code + code_len;
            if (!read_all(fd, new_rodata, rodata_len))
            {
                printf("[dpatch] Failed to read rodata bytes for %s (errno=%d)\n", mangled_name, errno);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -11;
            }
        }

        // Read num_relocs (2 bytes)
        ushort num_relocs;
        if (!read_all(fd, &num_relocs, 2))
        {
            printf("[dpatch] Failed to read num_relocs for %s (errno=%d)\n", mangled_name, errno);
            dpatch_free_code_page(new_code, total_len);
            free(mangled_name);
            return -12;
        }

        printf("[dpatch] Relocations count: %d\n", cast(int)num_relocs);

        // Process and apply relocations
        int stub_slot_idx = 0;
        int got_slot_idx = 0;
        for (int r_idx = 0; r_idx < num_relocs; r_idx++)
        {
            uint offset;
            ubyte type;
            ushort symbol_len;
            long addend;

            if (!read_all(fd, &offset, 4))
            {
                printf("[dpatch] Failed to read reloc offset %d for %s (errno=%d)\n", r_idx, mangled_name, errno);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -13;
            }
            if (!read_all(fd, &type, 1))
            {
                printf("[dpatch] Failed to read reloc type %d for %s (errno=%d)\n", r_idx, mangled_name, errno);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -14;
            }
            if (!read_all(fd, &symbol_len, 2))
            {
                printf("[dpatch] Failed to read reloc symbol_len %d for %s (errno=%d)\n", r_idx, mangled_name, errno);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -15;
            }

            char* sym_name = cast(char*)malloc(symbol_len + 1);
            if (!read_all(fd, sym_name, symbol_len))
            {
                printf("[dpatch] Failed to read reloc symbol name %d for %s (errno=%d)\n", r_idx, mangled_name, errno);
                free(sym_name);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -16;
            }
            sym_name[symbol_len] = '\0';

            if (!read_all(fd, &addend, 8))
            {
                printf("[dpatch] Failed to read reloc addend %d for %s (errno=%d)\n", r_idx, mangled_name, errno);
                free(sym_name);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -17;
            }

            // Resolve target symbol address
            void* target_sym_addr = null;
            if (strcmp(sym_name, ".rodata") == 0)
            {
                target_sym_addr = new_rodata;
            }
            else if (strcmp(sym_name, "__tls_get_addr") == 0)
            {
                target_sym_addr = cast(void*)&dpatch_tls_get_addr;
            }
            else
            {
                target_sym_addr = dpatch_resolve_symbol(sym_name);
            }

            if (!target_sym_addr)
            {
                printf("[dpatch] Failed to resolve relocation symbol: '%s'\n", sym_name);
                free(sym_name);
                dpatch_free_code_page(new_code, total_len);
                free(mangled_name);
                return -18;
            }

            printf("[dpatch] Reloc %d: '%s' resolved to %p, type=%d, addend=%ld, offset=%u\n",
                   r_idx, sym_name, target_sym_addr, cast(int)type, addend, offset);

            bool free_sym = true;

            // Apply relocation based on type
            size_t patch_ptr = cast(size_t)new_code + offset;
            if (type == 1) // R_X86_64_64 (abs64)
            {
                *cast(ulong*)patch_ptr = cast(ulong)target_sym_addr + addend;
                printf("[dpatch] Applied abs64: *%p = %lx\n", cast(void*)patch_ptr, *cast(ulong*)patch_ptr);
            }
            else if (type == 2) // R_X86_64_PC32/PLT32 (rel32)
            {
                long target_offset = (cast(long)target_sym_addr + addend) - cast(long)patch_ptr;
                if (target_offset < -2147483648L || target_offset > 2147483647L)
                {
                    // Target is too far (> 2GB)! Generate absolute JMP stub
                    size_t stub_addr = cast(size_t)new_code + code_len + rodata_len + (stub_slot_idx * 32);

                    ubyte* stub_bytes = cast(ubyte*)stub_addr;
                    stub_bytes[0] = 0xFF;
                    stub_bytes[1] = 0x25;
                    stub_bytes[2] = 0x00;
                    stub_bytes[3] = 0x00;
                    stub_bytes[4] = 0x00;
                    stub_bytes[5] = 0x00;

                    ulong absolute_target = cast(ulong)target_sym_addr + addend + 4;
                    *cast(ulong*)(stub_bytes + 6) = absolute_target;

                    target_offset = cast(long)stub_addr - 4 - cast(long)patch_ptr;
                    stub_slot_idx++;
                    printf("[dpatch] Far reloc %d: generated PLT stub at %p -> jumping to %p\n",
                           r_idx, cast(void*)stub_addr, cast(void*)absolute_target);
                }

                *cast(uint*)patch_ptr = cast(uint)(target_offset & 0xFFFFFFFF);
                printf("[dpatch] Applied rel32: *%p = %x (target_offset=%ld)\n", cast(void*)patch_ptr, *cast(uint*)patch_ptr, target_offset);
            }
            else if (type == 3) // R_X86_64_GOTPCREL (gotpcrel32)
            {
                // Allocate a GOT slot in the extra space of the code page
                size_t got_slot_addr = cast(size_t)new_code + code_len + rodata_len + 4096 + (got_slot_idx * 32);
                *cast(ulong*)got_slot_addr = cast(ulong)target_sym_addr + addend + 4;
                got_slot_idx++;

                long target_offset = got_slot_addr - 4 - cast(long)patch_ptr;
                *cast(uint*)patch_ptr = cast(uint)(target_offset & 0xFFFFFFFF);
                printf("[dpatch] Applied gotpcrel32: *%p = %x (got_slot=%p -> target=%p)\n",
                       cast(void*)patch_ptr, *cast(uint*)patch_ptr, cast(void*)got_slot_addr, cast(void*)(target_sym_addr + addend + 4));
            }
            else if (type == 4) // R_X86_64_TLSGD
            {
                // Allocate a TlsSlot in the extra space of the code page
                size_t slot_addr = cast(size_t)new_code + code_len + rodata_len + 4096 + (got_slot_idx * 32);
                got_slot_idx++;
                auto tls_slot = cast(TlsSlot*)slot_addr;
                tls_slot.sym_name = sym_name;
                tls_slot.offset = 0;
                tls_slot.inited = false;

                free_sym = false; // Do not free the symbol name since the slot references it

                long target_offset = cast(long)slot_addr + addend - cast(long)patch_ptr;
                *cast(uint*)patch_ptr = cast(uint)(target_offset & 0xFFFFFFFF);
                printf("[dpatch] Applied tlsgd32: *%p = %x (tls_slot=%p for symbol='%s')\n",
                       cast(void*)patch_ptr, *cast(uint*)patch_ptr, cast(void*)slot_addr, sym_name);
            }

            if (free_sym)
            {
                free(sym_name);
            }
        }

        // Make the new code executable
        if (dpatch_protect_code_page(new_code, total_len) != 0)
        {
            printf("[dpatch] Failed to protect code page for %s\n", mangled_name);
            dpatch_free_code_page(new_code, total_len);
            free(mangled_name);
            return -19;
        }

        // Find the original function address
        void* original_func = dpatch_resolve_symbol(mangled_name);
        if (!original_func)
        {
            printf("[dpatch] Failed to resolve watched function: %s\n", mangled_name);
            dpatch_free_code_page(new_code, total_len);
            free(mangled_name);
            return -20;
        }

        // Apply JMP trampoline to original NOP prologue
        int err = dpatch_write_trampoline(original_func, new_code);
        if (err != 0)
        {
            printf("[dpatch] Failed to write trampoline for %s: err=%d\n", mangled_name, err);
            dpatch_free_code_page(new_code, total_len);
            free(mangled_name);
            return -21;
        }

        printf("[dpatch] Successfully patched function: %s (%p -> %p)\n", mangled_name, original_func, new_code);
        free(mangled_name);
        num_patched++;
    }

    return num_patched;
}

// Non-blocking poll for incoming connections and patches
int dpatch_poll()
{
    if (g_server_fd == -1)
        return 0;

    int client_fd = accept(g_server_fd, null, null);
    if (client_fd < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("[dpatch] accept error: %d\n", errno);
        }
        return 0;
    }

    printf("[dpatch] Connection accepted: fd=%d\n", client_fd);

    // Set a 1-second receive timeout on the client socket to prevent read_all from blocking forever
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, tv.sizeof);

    fcntl(client_fd, F_SETFL, 0);

    int patched = dpatch_process_payload(client_fd);
    close(client_fd);

    return patched < 0 ? 0 : patched;
}

// Blocking wait for the next patch
int dpatch_wait()
{
    if (g_server_fd == -1)
        return 0;

    pollfd pfd;
    pfd.fd = g_server_fd;
    pfd.events = POLLIN;

    while (g_server_fd != -1)
    {
        int ret = poll(&pfd, 1, 100); // Poll with 100ms timeout
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (ret > 0 && (pfd.revents & POLLIN))
        {
            break;
        }
    }

    if (g_server_fd == -1)
        return 0;

    int client_fd = accept(g_server_fd, null, null);
    if (client_fd == -1)
        return -1;

    // Set a 1-second receive timeout on the client socket to prevent read_all from blocking forever
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, tv.sizeof);

    fcntl(client_fd, F_SETFL, 0);

    int patched = dpatch_process_payload(client_fd);
    close(client_fd);

    return patched;
}

// Cleanup socket and uninstall signal handler
void dpatch_shutdown()
{
    if (g_server_fd != -1)
    {
        close(g_server_fd);
        g_server_fd = -1;
        unlink(g_sock_path.ptr);
    }
    dpatch_uninstall_signal_handler();
}

// Background thread loop for receiving patches
private extern(C) void* dpatch_worker_thread(void* arg)
{
    while (g_server_fd != -1)
    {
        dpatch_wait();
    }
    return null;
}

// Auto-initialize using CRT constructor
extern(C) pragma(crt_constructor) void dpatch_auto_init()
{
    import core.sys.posix.pthread : pthread_t, pthread_create, pthread_detach;

    // Auto-init socket
    if (dpatch_init(null) != 0)
    {
        return;
    }

    // Spawn thread to monitor for hotpatching events
    pthread_t thread;
    if (pthread_create(&thread, null, &dpatch_worker_thread, null) == 0)
    {
        pthread_detach(thread);
    }
}

// Auto-cleanup using CRT destructor
extern(C) pragma(crt_destructor) void dpatch_auto_shutdown()
{
    dpatch_shutdown();
}
