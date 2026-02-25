#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace process
{
    // Process enumeration and handle helpers.
    DWORD get_process_id(const std::wstring& process_name);
    HANDLE open_process(DWORD process_id, DWORD access_rights);

    // Process state control.
    bool suspend_process(HANDLE process_handle);
    bool resume_process(HANDLE process_handle);
    bool unmap_process_memory(HANDLE process_handle);

    // Remote memory operations.
    LPVOID allocate_remote_memory(HANDLE process_handle, SIZE_T size_t, DWORD protect);
    bool write_remote_memory(HANDLE process_handle, LPVOID lp_address, LPVOID lp_buffer, SIZE_T size_t);

    // PE parsing and reading.
    LPVOID get_process_base_address(HANDLE process_handle);
    bool read_pe_from_process(HANDLE process_handle, LPVOID lp_base_address, std::vector<BYTE>& vec_buffer);
    PIMAGE_NT_HEADERS get_nt_headers(LPVOID address);

    // PE patching, must be done locally before write_pe_sections.
    bool fix_relocations(LPVOID base_address, LPVOID pe_buffer);
    bool fix_imports(LPVOID pe_buffer);

    // PE writing, writes the fully patched buffer into the remote process.
    bool write_pe_sections(HANDLE process_handle, LPVOID base_address, LPVOID pe_buffer);

    // Thread context and entry point.
    bool set_thread_context(HANDLE thread_handle, LPVOID entry_point);
    HANDLE get_main_thread(DWORD process_id);

    // The hollowing function itself that utilizes all previous functions to do what the program is inteded to do.
    bool hollow_process(DWORD host_process_id, DWORD hider_process_id);
}