#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __linux__
#include <sys/mman.h>
#endif

#include "Hook.hpp"
#include "lde.hpp"

int Hook::get_stolen_len(void * addr, int arch)
{
    // 14 is the minimum size for our Hook in 64 bits.
    // It's 5 in 32 bits;
    int min = arch ? 14 : 5;
    int64_t len = 0;

	while ( len < min ){
		len += ldisasm((void*)((long)addr + len), arch);
    }
    return len;
}

#ifdef _WIN32
int Hook::get_win_protections(int hproc)
{
    DWORD prot;
    if (    hproc & Hook::HOOK_PROT_READ &&
            hproc & Hook::HOOK_PROT_EXEC &&
            hproc & Hook::HOOK_PROT_WRITE)
    {
        prot = PAGE_EXECUTE_READWRITE; 
    }
    else if (   hproc & Hook::HOOK_PROT_READ &&
                hproc & Hook::HOOK_PROT_EXEC)
    {
        prot = PAGE_EXECUTE_READ; 
    }
    else if (   hproc & Hook::HOOK_PROT_READ &&
                hproc & Hook::HOOK_PROT_WRITE)
    {
        prot = PAGE_READWRITE; 
    }
    else if (   hproc & Hook::HOOK_PROT_READ)
    {
        prot = PAGE_READONLY; 
    }
    else 
    {
        prot = -1;
    }
    return prot;
}

int Hook::get_hprotections(int windows_proc)
{
    int prot;
    if (windows_proc == PAGE_EXECUTE_READWRITE)
    {
        prot = Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE;
    }
    else if (windows_proc == PAGE_EXECUTE_READ)
    {
        prot = Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ;
    }
    else if (windows_proc == PAGE_READWRITE)
    {
        prot = Hook::HOOK_PROT_WRITE | Hook::HOOK_PROT_READ;
    }
    else if (windows_proc == PAGE_READONLY)
    {
        prot = Hook::HOOK_PROT_READ;
    }
    else 
    {
        prot = -1;
    }
    return prot;
}
#endif

void * Hook::alloc(
    long size,
    int protection
)
{
    void* ret;
#ifdef _WIN32
    int tmp_proc = Hook::get_win_protections(protection);

    ret = VirtualAlloc 
    (
        NULL, 
        size,
        MEM_COMMIT | MEM_RESERVE,
        tmp_proc 
    );

    if (!ret)
    {
        ret = (void*)-1;
    }
#endif
#ifdef __linux__
    long page_size = getpagesize();
    int size_aligned = (1 + (size / page_size)) * page_size;
    ret = mmap(
        NULL,
        page_size,
        protection,
        MAP_ANON | MAP_PRIVATE,
        0,
        0
    );
#endif 
    return ret;
}


int Hook::change_protection (
    char * addr,
    long size,
    int new_protection
#ifdef _WIN32
    , PDWORD old_protection
#endif
    )
{
    int ret;
#ifdef _WIN32
    int tmp_proc = Hook::get_win_protections(new_protection);
    ret = VirtualProtect
    (
        addr, 
        size, 
        tmp_proc, 
        old_protection 
    ); 
    tmp_proc = Hook::get_hprotections(*old_protection);
    if (!ret || tmp_proc == -1)
    {
        ret = -1;
    }
    *old_protection = tmp_proc;
#endif
#ifdef __linux__
    long page_size = getpagesize();
    int size_aligned = (1 + (size / page_size)) * page_size;
    ret = mprotect(
        (void*)((long)addr & (~page_size + 1)),
        size_aligned,
        new_protection 
    );
#endif
    return ret;
}

int 
Hook::patch (
    char * addr_to_patch, 
    char * bytes_to_copy, 
    long size
#ifdef __linux__
    , int current_protection
#endif
)
{
    int r;
    int protection;

    // Make addr_to_patch writable
    r = Hook::change_protection(
        addr_to_patch, 
        size, 
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

#ifdef __linux__
    protection = current_protection;
#endif


    // Do the patch
    memcpy((void*)addr_to_patch, (void*) bytes_to_copy, size);

    // Then restore original protections
    r = Hook::change_protection(
        addr_to_patch, 
        size, 
        protection
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    return 0;
}



int 
Hook::Hook32::do_hook (
    char *original_addr,
    char *hook_addr 
#ifdef __linux__
    , int current_protection
#endif
)
{
    int r;
    long protection;

    // Set original function as writable
    r = Hook::change_protection(
        original_addr, 
        5, 
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

#ifdef __linux__
    protection = current_protection;
#endif
    
    // Write the trampoline
    *original_addr = 0xE9;
    *(long*)((char*)original_addr + 1) = 
        (char*)hook_addr - 
        (char*)original_addr - 5; 

    // Set back protection
    r = Hook::change_protection(
        original_addr, 
        5, 
        protection
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    printf("[+] Hook done: %p --> %p\n", original_addr, hook_addr);
    return 0;
}

int
Hook::Hook32::do_hook_stolen (
    char **stolen_bytes_out,  // OUT ARGUMENT
    char *original_addr, 
    char *hook_addr
#ifdef __linux__
    , int current_protection
#endif
)
{
    int r; 
    long protection;
    
    // Allocate some space for the stolen bytes
    // 20 + 5 because large instuction (20 to be safe) + the jump
    // Don't even know if mmap allow size < PAGESIZE

    char * stolen_bytes = 
        (char*) Hook::alloc(
            20 + 5, 
            Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
        );

    if ( stolen_bytes == (void*)-1)
    {
        printf("alloc failed");
        exit(0);
    }

    *stolen_bytes_out = stolen_bytes;

    int size_stolen_bytes = 
        Hook::get_stolen_len(original_addr, Hook::HOOK_ARCH_32);


    // Copy the first original bytes to our stolen_bytes location
    memcpy(stolen_bytes, original_addr, size_stolen_bytes);

    // Write the jump back to the function after the stolen bytes
    *((char*)stolen_bytes + size_stolen_bytes) = 0xe9;
    *(uint32_t*)((char*)stolen_bytes + size_stolen_bytes + 1) = 
        (char*)original_addr + 
        size_stolen_bytes -
        (stolen_bytes + size_stolen_bytes) - 
        5; 

    // Restore proper rights
    Hook::change_protection(
        stolen_bytes, 
        size_stolen_bytes + 5,
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    // Prepare the hook (patch with a jump)
    Hook::change_protection(
        original_addr, 
        5,
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

#ifdef __linux__
    protection = current_protection;
#endif

    // Write trampoline
    *original_addr = 0xE9;
    *(uint32_t*)((char*)original_addr + 1) = 
        (char*)hook_addr - 
        (char*)original_addr - 5; 

    // Restore proper rights
    Hook::change_protection(
        original_addr, 
        5,
        protection
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    printf("[+] Hook done: %p --> %p\n", original_addr, hook_addr);
    return 0;
}

int 
Hook::Hook64::do_hook (
    char *original_addr,
    char *hook_addr 
#ifdef __linux__
    , int current_protection
#endif
)
{
    int r;
    long protection;

    // Set original function as writable
    r = Hook::change_protection(
        original_addr, 
        14, 
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

#ifdef __linux__
    protection = current_protection;
#endif

    // Write the trampoline
    *(long long*)original_addr = 0x25ff;
    *(long long*)((char*)original_addr + 6) = (long long)hook_addr;
    
    // Set back protection
    r = Hook::change_protection(
        original_addr, 
        5, 
        protection
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    printf("[+] Hook done: %p --> %p\n", original_addr, hook_addr);
    return 0;
}

int
Hook::Hook64::do_hook_stolen (
    char** stolen_bytes_out, 
    char *original_addr, 
    char *hook_addr
#ifdef __linux__
    , int current_protection
#endif
)
{
    int r; 
    long protection;
    // Allocate some space for the stolen bytes
    // 30 + 14 because large instuction (30 to be safe) + the jump
    // Don't even know if mmap allow size < PAGESIZE
    
    char * stolen_bytes = 
        (char*) Hook::alloc(
            20 + 5, 
            Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
        );

    if ( stolen_bytes == (void*)-1)
    {
        printf("alloc failed");
        exit(0);
    }

    *stolen_bytes_out = stolen_bytes;

    int size_stolen_bytes = 
        Hook::get_stolen_len(original_addr, Hook::HOOK_ARCH_64);
    printf("%d\n", size_stolen_bytes);

    // Copy the first original bytes to our stolen_bytes location
    memcpy(stolen_bytes, original_addr, size_stolen_bytes);


    // Write the jump back to the function after the stolen bytes
    *(long long*)((char*)stolen_bytes + size_stolen_bytes) = 0x25ff;
    *(long long*)((char*)stolen_bytes + size_stolen_bytes + 6) = 
        (long long)(original_addr + size_stolen_bytes);
    
    // Restore proper rights
    Hook::change_protection(
        stolen_bytes, 
        size_stolen_bytes + 14,
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    // Prepare the hook (patch with a jump)
    Hook::change_protection(
        original_addr, 
        14,
        Hook::HOOK_PROT_EXEC | Hook::HOOK_PROT_READ | Hook::HOOK_PROT_WRITE
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

#ifdef __linux__
    protection = current_protection;
#endif

    // Write trampoline
    *(long long*)original_addr = 0x25ff;
    *(long long*)((char*)original_addr + 6) = (long long)hook_addr;
    
    // Restore proper rights
    Hook::change_protection(
        original_addr, 
        14,
        protection
#ifdef _WIN32
        , (PDWORD)&protection
#endif
    );

    if ( r == -1)
    {
        printf("change protection failed");
        exit(0);
    }

    printf("[+] Hook done: %p --> %p\n", original_addr, hook_addr);
    printf("%02x%02x\n", stolen_bytes[0], stolen_bytes[1]);
    return 0;
}
