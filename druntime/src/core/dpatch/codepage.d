module core.dpatch.codepage;

import core.sys.posix.sys.mman;
import core.stdc.stdio;

extern(C):

// Define MAP_ANONYMOUS for Linux if not defined in core.sys.posix.sys.mman
enum MAP_ANONYMOUS = 0x20;

extern(C) ulong dpatch_get_base_address();

// Allocates a memory block for incoming patch code.
// The page is allocated as Readable + Writable first, and we probe locations close
// to the base address of the main executable to ensure 32-bit PC-relative jumps/calls
// fit within the 2GB range.
void* dpatch_alloc_code_page(size_t size)
{
    // Round size to page boundary
    size_t page_size = 4096;
    size_t rounded_size = (size + page_size - 1) & ~(page_size - 1);

    ulong base_addr = dpatch_get_base_address();
    if (base_addr == 0)
    {
        void* addr = mmap(null, rounded_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return addr == MAP_FAILED ? null : addr;
    }

    // Try various offsets within 2GB (+/- 512MB) to find a close mapping VMA
    long[8] offsets = [
        0x04000000,   // +64MB
        0x08000000,   // +128MB
        0x10000000,   // +256MB
        0x20000000,   // +512MB
        -0x04000000,  // -64MB
        -0x08000000,  // -128MB
        -0x10000000,  // -256MB
        -0x20000000   // -512MB
    ];

    for (int i = 0; i < offsets.length; i++)
    {
        ulong hint = base_addr + offsets[i];
        hint = hint & ~(page_size - 1); // Align to page boundary

        void* addr = mmap(cast(void*)hint, rounded_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr != MAP_FAILED && addr != null)
        {
            // Verify if the allocated address is within 2GB of base_addr
            long diff = cast(long)addr - cast(long)base_addr;
            if (diff >= -2147483648L && diff <= 2147483647L)
            {
                return addr;
            }
            munmap(addr, rounded_size);
        }
    }

    // Fallback if no close address is found
    void* addr = mmap(null, rounded_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return addr == MAP_FAILED ? null : addr;
}

// Changes memory permissions to Read + Exec after the code has been written.
int dpatch_protect_code_page(void* addr, size_t size)
{
    size_t page_size = 4096;
    size_t rounded_size = (size + page_size - 1) & ~(page_size - 1);

    if (mprotect(addr, rounded_size, PROT_READ | PROT_EXEC) != 0)
    {
        return -1;
    }
    return 0;
}

// Changes memory permissions to Read-only after the rodata has been written.
int dpatch_protect_rodata_page(void* addr, size_t size)
{
    size_t page_size = 4096;
    size_t rounded_size = (size + page_size - 1) & ~(page_size - 1);

    if (mprotect(addr, rounded_size, PROT_READ) != 0)
    {
        return -1;
    }
    return 0;
}

// Free allocated memory
int dpatch_free_code_page(void* addr, size_t size)
{
    size_t page_size = 4096;
    size_t rounded_size = (size + page_size - 1) & ~(page_size - 1);

    if (munmap(addr, rounded_size) != 0)
    {
        return -1;
    }
    return 0;
}
