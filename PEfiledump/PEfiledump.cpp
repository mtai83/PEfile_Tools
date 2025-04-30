#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

const char* directoryNames[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug Directory",
    "Architecture Specific Data",
    "Global Ptr",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "IAT (Import Address Table)",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved"
};

DWORD RvaToOffset(DWORD rva, IMAGE_SECTION_HEADER* sections, int sectionCount) {
    for (int i = 0; i < sectionCount; i++) {
        DWORD sectionVA = sections[i].VirtualAddress;
        DWORD sectionSize = sections[i].Misc.VirtualSize;
        if (rva >= sectionVA && rva < sectionVA + sectionSize) {
            return rva - sectionVA + sections[i].PointerToRawData;
        }
    }
    return 0; // Không tìm thấy
}

DWORD importRVA = 0;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PE_File_Path>\n", argv[0]);
        return 1;
    }

    // Mở file nhị phân để đọc
    FILE* file = NULL;
    if (fopen_s(&file, argv[1], "rb") != 0 || file == NULL) {
        perror("Error opening file");
        return 1;
    }

    if (!file) {
        perror("Error opening file");
        return 1;
    }

    // Đọc DOS header
    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {  // 'MZ'
        printf("Not a valid PE file (missing MZ signature)\n");
        fclose(file);
        return 1;
    }

    // Nhảy đến offset chứa PE header
    fseek(file, dosHeader.e_lfanew, SEEK_SET);

    DWORD peSignature;
    fread(&peSignature, sizeof(DWORD), 1, file);
    if (peSignature != IMAGE_NT_SIGNATURE) { // 'PE\0\0'
        printf("Invalid PE signature\n");
        fclose(file);
        return 1;
    }

    // Đọc FILE HEADER
    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, file);

    printf("===== PE File Info =====\n");
    printf("___File header___\n");
    printf("Machine: 0x%X\n", fileHeader.Machine);
    printf("Number of Sections: %d\n", fileHeader.NumberOfSections);
    printf("TimeDateStamp: 0x%X\n", fileHeader.TimeDateStamp);
    printf("Size of Optional Header: %d\n", fileHeader.SizeOfOptionalHeader);
    printf("Characteristics: 0x%X\n", fileHeader.Characteristics);


    // Kiểm tra Magic để xác định PE32 hay PE64
    if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        IMAGE_OPTIONAL_HEADER32 optionalHeader;
        fread(&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file);
        printf("\n___PE32 Optional header___\n");
        printf("Magic: 0x%X\n", optionalHeader.Magic);
        printf("MajorLinkerVersion: 0x%X\n", optionalHeader.MajorLinkerVersion);
        printf("MinorLinkerVersion: 0x%X\n", optionalHeader.MinorLinkerVersion);
        printf("SizeOfCode: 0x%X\n", optionalHeader.SizeOfCode);
        printf("SizeOfInitializedData: 0x%X\n", optionalHeader.SizeOfInitializedData);
        printf("SizeOfUninitializedData: 0x%X\n", optionalHeader.SizeOfUninitializedData);
        printf("AddressOfEntryPoint: 0x%X\n", optionalHeader.AddressOfEntryPoint);
        printf("BaseOfCode: 0x%X\n", optionalHeader.BaseOfCode);
        printf("ImageBase: 0x%X\n", optionalHeader.ImageBase);
        printf("SectionAlignment: 0x%X\n", optionalHeader.SectionAlignment);
        printf("FileAlignment: 0x%X\n", optionalHeader.FileAlignment);
        printf("MajorOperatingSystemVersion: 0x%X\n", optionalHeader.MajorOperatingSystemVersion);
        printf("MinorOperatingSystemVersion: 0x%X\n", optionalHeader.MinorOperatingSystemVersion);
        printf("MajorImageVersion: 0x%X\n", optionalHeader.MajorImageVersion);
        printf("MinorImageVersion: 0x%X\n", optionalHeader.MinorImageVersion);
        printf("MajorSubsystemVersion: 0x%X\n", optionalHeader.MajorSubsystemVersion);
        printf("MinorSubsystemVersion: 0x%X\n", optionalHeader.MinorSubsystemVersion);
        printf("Win32VersionValue: 0x%X\n", optionalHeader.Win32VersionValue);
        printf("SizeOfImage: 0x%X\n", optionalHeader.SizeOfImage);
        printf("SizeOfHeaders: 0x%X\n", optionalHeader.SizeOfHeaders);
        printf("CheckSum: 0x%X\n", optionalHeader.CheckSum);
        printf("Subsystem: 0x%X\n", optionalHeader.Subsystem);
        printf("DllCharacteristics: 0x%X\n", optionalHeader.DllCharacteristics);
        printf("SizeOfStackReserve: 0x%X\n", optionalHeader.SizeOfStackReserve);
        printf("SizeOfStackCommit: 0x%X\n", optionalHeader.SizeOfStackCommit);
        printf("SizeOfHeapReserve: 0x%X\n", optionalHeader.SizeOfHeapReserve);
        printf("SizeOfHeapCommit: 0x%X\n", optionalHeader.SizeOfHeapCommit);
        printf("LoaderFlags: 0x%X\n", optionalHeader.LoaderFlags);
        printf("NumberOfRvaAndSizes: 0x%X\n", optionalHeader.NumberOfRvaAndSizes);

        // In thông tin Data Directory
        printf("\n___ (Data directory) ___\n");
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            printf(" [%d] %s \n", i, directoryNames[i]);
            printf("   RVA: 0x%X\n", optionalHeader.DataDirectory[i].VirtualAddress);
            printf("   Size: 0x%X\n", optionalHeader.DataDirectory[i].Size);
        }

        importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    }
    else if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        fread(&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64), 1, file);
        printf("\n___PE64 Optional header___\n");
        printf("Magic: 0x%X\n", optionalHeader.Magic);
        printf("MajorLinkerVersion: 0x%X\n", optionalHeader.MajorLinkerVersion);
        printf("MinorLinkerVersion: 0x%X\n", optionalHeader.MinorLinkerVersion);
        printf("SizeOfCode: 0x%X\n", optionalHeader.SizeOfCode);
        printf("SizeOfInitializedData: 0x%X\n", optionalHeader.SizeOfInitializedData);
        printf("SizeOfUninitializedData: 0x%X\n", optionalHeader.SizeOfUninitializedData);
        printf("AddressOfEntryPoint: 0x%X\n", optionalHeader.AddressOfEntryPoint);
        printf("BaseOfCode: 0x%X\n", optionalHeader.BaseOfCode);
        printf("ImageBase: 0x%llX\n", optionalHeader.ImageBase);
        printf("SectionAlignment: 0x%X\n", optionalHeader.SectionAlignment);
        printf("FileAlignment: 0x%X\n", optionalHeader.FileAlignment);
        printf("MajorOperatingSystemVersion: 0x%X\n", optionalHeader.MajorOperatingSystemVersion);
        printf("MinorOperatingSystemVersion: 0x%X\n", optionalHeader.MinorOperatingSystemVersion);
        printf("MajorImageVersion: 0x%X\n", optionalHeader.MajorImageVersion);
        printf("MinorImageVersion: 0x%X\n", optionalHeader.MinorImageVersion);
        printf("MajorSubsystemVersion: 0x%X\n", optionalHeader.MajorSubsystemVersion);
        printf("MinorSubsystemVersion: 0x%X\n", optionalHeader.MinorSubsystemVersion);
        printf("Win32VersionValue: 0x%X\n", optionalHeader.Win32VersionValue);
        printf("SizeOfImage: 0x%X\n", optionalHeader.SizeOfImage);
        printf("SizeOfHeaders: 0x%X\n", optionalHeader.SizeOfHeaders);
        printf("CheckSum: 0x%X\n", optionalHeader.CheckSum);
        printf("Subsystem: 0x%X\n", optionalHeader.Subsystem);
        printf("DllCharacteristics: 0x%X\n", optionalHeader.DllCharacteristics);
        printf("SizeOfStackReserve: 0x%llX\n", optionalHeader.SizeOfStackReserve);
        printf("SizeOfStackCommit: 0x%llX\n", optionalHeader.SizeOfStackCommit);
        printf("SizeOfHeapReserve: 0x%llX\n", optionalHeader.SizeOfHeapReserve);
        printf("SizeOfHeapCommit: 0x%llX\n", optionalHeader.SizeOfHeapCommit);
        printf("LoaderFlags: 0x%X\n", optionalHeader.LoaderFlags);
        printf("NumberOfRvaAndSizes: 0x%X\n", optionalHeader.NumberOfRvaAndSizes);

        // In thông tin Data Directory
        printf("\n___ (Data directory) ___\n");
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            printf(" [%d] %s \n", i, directoryNames[i]);
            printf("   RVA: 0x%X\n", optionalHeader.DataDirectory[i].VirtualAddress);
            printf("   Size: 0x%X\n", optionalHeader.DataDirectory[i].Size);
        }
        importRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    }
    else {
        printf("Unknown Optional Header size: %d\n", fileHeader.SizeOfOptionalHeader);
        fclose(file);
        return 1;
    }


    bool isPE32 = (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32));

    long sectionTableOffset =
        dosHeader.e_lfanew
        + sizeof(DWORD)                    // PE signature
        + sizeof(IMAGE_FILE_HEADER)
        + fileHeader.SizeOfOptionalHeader; // SizeOfOptionalHeader đã đọc

    fseek(file, sectionTableOffset, SEEK_SET);

    // Cấp phát mảng sections
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)
        malloc(sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections);
    if (!sections) {
        perror("malloc");
        fclose(file);
        return 1;
    }

    printf("\n___SECTION HEADER___\n");
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        // Đọc thẳng vào phần tử i của mảng
        if (fread(&sections[i], sizeof(IMAGE_SECTION_HEADER), 1, file) != 1) {
            fprintf(stderr, "Failed to read section %d\n", i);
            free(sections);
            fclose(file);
            return 1;
        }

        printf("[%d] Name %s \n", i+1, sections[i].Name);
        printf("   Virtual Address: %X\n", sections[i].VirtualAddress);
        printf("   Virtual Size: %X\n", sections[i].Misc.VirtualSize);
        printf("   Raw Address: %X\n", sections[i].PointerToRawData);
        printf("   Size Of Raw Data: %X\n", sections[i].SizeOfRawData);
        printf("   Reloccation Address: %X\n", sections[i].PointerToRelocations);
        printf("   Relocations Number: %X\n", sections[i].NumberOfRelocations);
        printf("   LineNumber: %X\n", sections[i].PointerToLinenumbers);
        printf("   Linenumbers Number: %X\n", sections[i].NumberOfLinenumbers);
        printf("   Characteristics: %X\n", sections[i].Characteristics);
    }

   
    DWORD importOffset = RvaToOffset(importRVA, sections, fileHeader.NumberOfSections);

    if (importOffset == 0) {
        printf("Cannot locate Import Directory\n");
    }
    else {
        // importOffset là file-offset của Import Directory (đã tính bằng RvaToOffset trước đó)

        DWORD descCount = 0;
        long   baseDescOffset = importOffset;
        printf("\n___IMPORT TABLE___\n");
        while (1) {
            // 1) Đọc descriptor thứ descCount
            IMAGE_IMPORT_DESCRIPTOR impDesc;
            fseek(file, baseDescOffset + descCount * sizeof(impDesc), SEEK_SET);
            if (fread(&impDesc, sizeof(impDesc), 1, file) != 1) break;
            if (impDesc.Name == 0) break;   // gặp null-descriptor → hết

            // 2) In tên DLL
            DWORD nameOff = RvaToOffset(impDesc.Name, sections, fileHeader.NumberOfSections);
            fseek(file, nameOff, SEEK_SET);
            char dllName[256];
            fgets(dllName, sizeof(dllName), file);
            printf("DLL: %s\n", dllName);

            // 3) Duyệt các thunk entry
            DWORD thunkRVA = impDesc.OriginalFirstThunk
                ? impDesc.OriginalFirstThunk
                : impDesc.FirstThunk;
            DWORD baseThunkOffset = RvaToOffset(thunkRVA, sections, fileHeader.NumberOfSections);

            if (isPE32) {
                // --- XỬ LÝ THUNK 32-BIT ---
                for (DWORD t = 0; ; t++) {
                    DWORD thunkData32;
                    fseek(file, baseThunkOffset + t * sizeof(DWORD), SEEK_SET);
                    if (fread(&thunkData32, sizeof(thunkData32), 1, file) != 1 || thunkData32 == 0)
                        break;

                    if (!(thunkData32 & IMAGE_ORDINAL_FLAG32)) {
                        DWORD hintNameRVA = thunkData32;
                        DWORD hintNameOff = RvaToOffset(hintNameRVA, sections, fileHeader.NumberOfSections);
                        fseek(file, hintNameOff + 2, SEEK_SET);
                        char funcName[256];
                        fgets(funcName, sizeof(funcName), file);
                        printf("    %s\n", funcName);
                    }
                    else {
                        printf("    Ordinal: 0x%X\n", thunkData32 & 0xFFFF);
                    }
                }
            }
            else {
                // --- XỬ LÝ THUNK 64-BIT ---
                for (DWORD t = 0; ; t++) {
                    ULONGLONG thunkData64;
                    fseek(file, baseThunkOffset + t * sizeof(ULONGLONG), SEEK_SET);
                    if (fread(&thunkData64, sizeof(thunkData64), 1, file) != 1 || thunkData64 == 0)
                        break;

                    if (!(thunkData64 & IMAGE_ORDINAL_FLAG64)) {
                        // thấp 32 bit mới là RVA tới IMAGE_IMPORT_BY_NAME
                        DWORD hintNameRVA = (DWORD)thunkData64;
                        DWORD hintNameOff = RvaToOffset(hintNameRVA, sections, fileHeader.NumberOfSections);
                        fseek(file, hintNameOff + 2, SEEK_SET);
                        char funcName[256];
                        fgets(funcName, sizeof(funcName), file);
                        printf("    %s\n", funcName);
                    }
                    else {
                        printf("    Ordinal: 0x%llX\n", thunkData64 & 0xFFFF);
                    }
                }
            }

            // 4) Chuyển sang descriptor tiếp theo
            descCount++;
        }

    }

    fclose(file);
    return 0;
}
