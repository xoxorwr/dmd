module core.dpatch.trampoline;

import core.sys.posix.signal;
import core.sys.posix.sys.mman;
import core.stdc.stdio;

extern(C):

// Define structure for tracking active hooks
struct HookRecord
{
    void* original_addr;
    void* target_addr;
}

__gshared HookRecord[512] g_hooks;
__gshared int g_num_hooks;
__gshared sigaction_t g_old_sigaction;
__gshared bool g_signal_handler_installed;

// Linux x86_64 ucontext definition
struct mcontext_t
{
    long[32] gregs;
}

struct ucontext_t
{
    ulong uc_flags;
    ucontext_t* uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
}

enum REG_RIP = 16;

// Signal handler to catch INT3 breakpoints and redirect execution
extern(C) void dpatch_sigtrap_handler(int sig, siginfo_t* info, void* context_void)
{
    auto context = cast(ucontext_t*)context_void;
    void* rip = cast(void*)context.uc_mcontext.gregs[REG_RIP];

    // Note: when INT3 triggers, RIP points to the instruction *after* the INT3 (i.e. original_addr + 1)
    void* trigger_addr = cast(void*)(cast(size_t)rip - 1);

    for (int i = 0; i < g_num_hooks; i++)
    {
        if (g_hooks[i].original_addr == trigger_addr)
        {
            // Redirect RIP to target function
            context.uc_mcontext.gregs[REG_RIP] = cast(long)g_hooks[i].target_addr;
            return;
        }
    }

    // If we didn't handle it, forward to the old handler or restore default
    if (g_old_sigaction.sa_sigaction)
    {
        g_old_sigaction.sa_sigaction(sig, info, context_void);
    }
    else
    {
        // Crash or ignore
        signal(sig, SIG_DFL);
    }
}

int dpatch_install_signal_handler()
{
    if (g_signal_handler_installed)
        return 0;

    sigaction_t sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = &dpatch_sigtrap_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, &g_old_sigaction) != 0)
    {
        return -1;
    }

    g_signal_handler_installed = true;
    return 0;
}

void dpatch_uninstall_signal_handler()
{
    if (!g_signal_handler_installed)
        return;

    sigaction(SIGTRAP, &g_old_sigaction, null);
    g_signal_handler_installed = false;
}

// Overwrite NOP prologue with jump instruction:
// JMP [RIP+0] -> FF 25 00 00 00 00
// Followed by 8-byte absolute address
int dpatch_write_trampoline(void* original, void* target)
{
    // Ensure signal handler is installed
    if (dpatch_install_signal_handler() != 0)
    {
        return -1;
    }

    // Align to page boundary
    size_t page_size = 4096; // Standard x86_64 page size
    size_t addr = cast(size_t)original;
    size_t page_start = addr & ~(page_size - 1);

    // Make code page writable
    if (mprotect(cast(void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        return -2;
    }

    // Save hook details
    int hook_idx = -1;
    for (int i = 0; i < g_num_hooks; i++)
    {
        if (g_hooks[i].original_addr == original)
        {
            hook_idx = i;
            break;
        }
    }

    if (hook_idx == -1)
    {
        if (g_num_hooks >= g_hooks.length)
        {
            mprotect(cast(void*)page_start, page_size, PROT_READ | PROT_EXEC);
            return -3; // Too many hooks
        }
        hook_idx = g_num_hooks++;
        g_hooks[hook_idx].original_addr = original;
    }
    g_hooks[hook_idx].target_addr = target;

    // Step 1: Write INT3 breakpoint at byte 0 atomically
    ubyte* dest = cast(ubyte*)original;
    dest[0] = 0xCC;

    // Step 2: Use mfence to ensure memory write is visible
    asm { mfence; }

    // Step 3: Write bytes 1 to 13 of the absolute jump instruction
    // FF 25 00 00 00 00 <8-byte address>
    dest[1] = 0x25;
    dest[2] = 0x00;
    dest[3] = 0x00;
    dest[4] = 0x00;
    dest[5] = 0x00;

    ulong target_val = cast(ulong)target;
    for (int i = 0; i < 8; i++)
    {
        dest[6 + i] = cast(ubyte)(target_val >> (i * 8));
    }

    // Step 4: Use mfence again
    asm { mfence; }

    // Step 5: Replace INT3 with the real first byte of the JMP (0xFF)
    dest[0] = 0xFF;

    // Step 6: Use mfence
    asm { mfence; }

    // Restore page permissions to Read-Execute
    mprotect(cast(void*)page_start, page_size, PROT_READ | PROT_EXEC);

    return 0;
}
