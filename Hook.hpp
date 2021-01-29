#ifndef DEF_HOOK
#define DEF_HOOK

namespace Hook
{
    const long HOOK_ARCH_32 = 0; 
    const long HOOK_ARCH_64 = 1; 

    const long HOOK_PROT_READ = 1 << 0;
    const long HOOK_PROT_WRITE = 1 << 1;
    const long HOOK_PROT_EXEC = 1 << 2;

    int get_stolen_len(void * addr, int arch);
    
#ifdef _WIN32
    int get_win_protections(int hproc);
    int get_hprotections(int hproc);
#endif

    int patch (
        char * addr_to_patch,
        char * bytes_to_copy,
        long size
        // Fuck POSIX that can't give a simple way to retrieve memory
        // protection of a page
#ifdef __linux__
        , int current_protection
#endif
    );

    int change_protection (
        char * addr,
        long size,
        int new_protection
#ifdef _WIN32
        , PDWORD old_protection
#endif
    );

    void *alloc(
        long size,
        int protection
    );

    // 32 bits hook
    class Hook32
    {
        // e9 00 11 22 33 jmp 0x33221105 
        //
        // Classical hook, do not write the stolen bytes in memory.
        // The first five bytes of the original function are replaced with 
        // the trampoline to the hook. It's probably better to write the hook
        // in asm, as we will handle calling convention correctly
        public:
            static 
            int do_hook (
                char *original_addr,
                char *hook_addr 

                // Fuck POSIX that can't give a simple way to retrieve memory
                // protection of a page
#ifdef __linux__
                , int current_protection
#endif
                );

        //
        // Classic Hook where the stolen byte are written in memory, at the end
        // of the hook, we just have to call object->stolen, with the right
        // calling convention. It will call the allocated memory, composed
        // with the stolen bytes, then a jump to the original function + size
        // of stolen bytes.
        // The function return the address of the stolen bytes
            static 
            int do_hook_stolen (
                char **stolen_bytes_out, 
                char *original_addr, 
                char *hook_addr 
                
                // Fuck POSIX that can't give a simple way to retrieve memory
                // protection of a page
#ifdef __linux__
                , int current_protection
#endif
                );

    };

    // 64 bits hook
    class Hook64
    {
        // ff 25 00 00 00 00            jmp QWORD PTR [RIP]
        // 00 11 22 33 44 55 66 77      my addr 
        //
        // Classical hook, do not write the stolen bytes in memory.
        // The first fourteen bytes (is it possible to reduce size?)
        // of the original function are replaced with 
        // the trampoline to the hook. It's probably better to write the hook
        // in asm, as we will handle calling convention correctly
        public:
            static 
            int do_hook (
                char *original_addr,
                char *hook_addr 

                // Fuck POSIX that can't give a simple way to retrieve memory
                // protection of a page
#ifdef __linux__
                , int current_protection
#endif
                );

        //
        // Classic Hook where the stolen byte are written in memory, at the end
        // of the hook, we just have to call object->stolen, with the right
        // calling convention. It will call the allocated memory, composed
        // with the stolen bytes, then a jump to the original function + size
        // of stolen bytes.
        // The function return the address of the stolen bytes.
            static
            int do_hook_stolen (
                char **stolen_bytes_out, 
                char *original_addr, 
                char *hook_addr 
                
                // Fuck POSIX that can't give a simple way to retrieve memory
                // protection of a page
#ifdef __linux__
                , int current_protection
#endif
                );
    };
}
#endif
