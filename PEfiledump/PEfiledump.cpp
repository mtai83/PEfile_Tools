#include <stdio.h>
#include <windows.h>

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


    // Đọc OPTIONAL HEADER
    IMAGE_OPTIONAL_HEADER32 optionalHeader;
    fread(&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file);
    printf("\n___Option header___\n");
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

    fclose(file);
    return 0;
}
