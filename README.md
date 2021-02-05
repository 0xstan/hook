# Hook

Small library that helps you hook function in a process (windows + linux).

## Usage

Include `#include "Hook.hpp"` in your file and add "Hook.cpp" to the
compilation chain. 

## API
### windows

`Hook::patch(char* addr_to_patch, char* bytes_to_copy, long size);`

`Hook::patch` replaces `size` bytes at address `addr_to_patch` with the bytes
at address `bytes_to_copy`

`Hook::Hook32::do_hook(char* original_addr, char* hook_addr);`

`Hook::Hook64::do_hook(char* original_addr, char* hook_addr);`

`Hook::HookXX::do_hook` hook the function at address `original_addr` and 
redirect the control flow to `hook_addr`

`Hook::Hook32::do_hook_stolen(char** stolen_bytes_out, char* original_addr, char* hook_addr);`

`Hook::Hook64::do_hook_stolen(char** stolen_bytes_out, char* original_addr, char* hook_addr);`

`Hook::HookXX::do_hook_stolen` hook the function at address `original_addr` and 
redirect the control flow to `hook_addr`. The original function is still
callable (by calling `stolen_bytes_out`)

### Linux

Exactly the same functions as windows, except that each function takes one more
argument which is `int current_protection` (`HOOK_PROT_READ`, `HOOK_PROT_WRITE`
, and `HOOK_PROT_EXEC`). `current_protection` is the last argument.
