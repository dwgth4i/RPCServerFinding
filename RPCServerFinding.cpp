#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <set>
#include <windows.h>

namespace fs = std::filesystem;

// Dangerous APIs to check for potential vulnerabilities
struct DangerousAPI {
    const char* dllName;
    const char* functionName;
    const char* description;
};

const DangerousAPI DANGEROUS_APIS[] = {
    {"advapi32.dll", "SetNamedSecurityInfo", "arbitrary DACL modification"},
    {"advapi32.dll", "SetNamedSecurityInfoA", "arbitrary DACL modification"},
    {"advapi32.dll", "SetNamedSecurityInfoW", "arbitrary DACL modification"},
    {"kernel32.dll", "DeleteFileW", "arbitrary deletion"},
    {"kernel32.dll", "DeleteFileA", "arbitrary deletion"},
    {"kernel32.dll", "MoveFileW", "arbitrary file modification with move"},
    {"kernel32.dll", "MoveFileA", "arbitrary file modification with move"},
    {"kernel32.dll", "MoveFileExW", "arbitrary file modification with move"},
    {"kernel32.dll", "MoveFileExA", "arbitrary file modification with move"},
};

// Convert RVA to File Offset
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= pSectionHeader->VirtualAddress &&
            rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) {
            return rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
        }
        pSectionHeader++;
    }

    return rva;
}

struct AnalysisResult {
    bool isRpcServer;
    bool isRpcClient;
    std::vector<std::string> foundApis;
};

DWORD AnalyzePEImports(LPVOID pBase, DWORD fileSize, bool* pIsRpcServer, bool* pIsRpcClient,
    char foundApis[][256], int* apiCount, int maxApis) {
    *pIsRpcServer = false;
    *pIsRpcClient = false;
    *apiCount = 0;

    __try {
        if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
            return 1;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return 1;
        }

        if (fileSize < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
            return 1;
        }

        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return 1;
        }

        DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (importRVA == 0 || importSize == 0) {
            return 0;
        }

        DWORD importOffset = RvaToFileOffset(pNtHeaders, importRVA);
        if (importOffset >= fileSize) {
            return 1;
        }

        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + importOffset);

        while (pImportDesc->Name != 0 && (BYTE*)pImportDesc < (BYTE*)pBase + fileSize) {
            DWORD nameOffset = RvaToFileOffset(pNtHeaders, pImportDesc->Name);

            if (nameOffset >= fileSize) {
                pImportDesc++;
                continue;
            }

            char* dllName = (char*)((BYTE*)pBase + nameOffset);

            // Check if it imports from rpcrt4.dll
            if (_stricmp(dllName, "rpcrt4.dll") == 0) {
                // Now check which specific RPC functions it imports
                DWORD thunkRVA = pImportDesc->OriginalFirstThunk;
                if (thunkRVA == 0) {
                    thunkRVA = pImportDesc->FirstThunk;
                }

                if (thunkRVA != 0) {
                    DWORD thunkOffset = RvaToFileOffset(pNtHeaders, thunkRVA);
                    if (thunkOffset < fileSize) {
                        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBase + thunkOffset);

                        while (pThunk->u1.AddressOfData != 0 && (BYTE*)pThunk < (BYTE*)pBase + fileSize) {
                            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                                DWORD nameRVA = (DWORD)(pThunk->u1.AddressOfData & 0xFFFFFFFF);
                                DWORD importNameOffset = RvaToFileOffset(pNtHeaders, nameRVA);

                                if (importNameOffset < fileSize - sizeof(IMAGE_IMPORT_BY_NAME)) {
                                    PIMAGE_IMPORT_BY_NAME pImportByName =
                                        (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + importNameOffset);

                                    // Check for RPC server functions
                                    if (_stricmp((char*)pImportByName->Name, "RpcServerListen") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerRegisterIf") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerRegisterIf2") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerRegisterIfEx") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerUseProtseq") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerUseProtseqEp") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerUseProtseqEpA") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcServerUseProtseqEpW") == 0) {
                                        *pIsRpcServer = true;
                                    }

                                    // Check for RPC client functions
                                    if (_stricmp((char*)pImportByName->Name, "RpcStringBindingCompose") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcStringBindingComposeA") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcStringBindingComposeW") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcBindingFromStringBinding") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcBindingFromStringBindingA") == 0 ||
                                        _stricmp((char*)pImportByName->Name, "RpcBindingFromStringBindingW") == 0) {
                                        *pIsRpcClient = true;
                                    }
                                }
                            }
                            pThunk++;
                        }
                    }
                }
            }

            // Check for dangerous APIs
            for (const auto& dangerousApi : DANGEROUS_APIS) {
                if (_stricmp(dllName, dangerousApi.dllName) != 0) {
                    continue;
                }

                DWORD thunkRVA = pImportDesc->OriginalFirstThunk;
                if (thunkRVA == 0) {
                    thunkRVA = pImportDesc->FirstThunk;
                }

                if (thunkRVA == 0) {
                    continue;
                }

                DWORD thunkOffset = RvaToFileOffset(pNtHeaders, thunkRVA);
                if (thunkOffset >= fileSize) {
                    continue;
                }

                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBase + thunkOffset);

                while (pThunk->u1.AddressOfData != 0 && (BYTE*)pThunk < (BYTE*)pBase + fileSize) {
                    if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        DWORD nameRVA = (DWORD)(pThunk->u1.AddressOfData & 0xFFFFFFFF);
                        DWORD importNameOffset = RvaToFileOffset(pNtHeaders, nameRVA);

                        if (importNameOffset < fileSize - sizeof(IMAGE_IMPORT_BY_NAME)) {
                            PIMAGE_IMPORT_BY_NAME pImportByName =
                                (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + importNameOffset);

                            if (_stricmp((char*)pImportByName->Name, dangerousApi.functionName) == 0) {
                                if (*apiCount < maxApis) {
                                    sprintf_s(foundApis[*apiCount], 256, "%s:%s",
                                        dangerousApi.functionName, dangerousApi.description);
                                    (*apiCount)++;
                                }
                            }
                        }
                    }
                    pThunk++;
                }
            }

            pImportDesc++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }

    return 0;
}

// Check if PE file is an RPC server and what dangerous APIs it imports
void AnalyzePEFile(const std::string& filePath) {
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    bool isRpcServer = false;
    bool isRpcClient = false;
    char foundApis[100][256];
    int apiCount = 0;

    AnalyzePEImports(pBase, fileSize, &isRpcServer, &isRpcClient, foundApis, &apiCount, 100);

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // Print results
    std::string filename = fs::path(filePath).filename().string();

    // Only report RPC servers (not clients)
    if (isRpcServer) {
        std::cout << "[+] Target: " << filename << "\n";
        std::cout << "       [*] Is RPC server file\n";

        if (apiCount > 0) {
            std::set<std::string> uniqueApis;
            for (int i = 0; i < apiCount; i++) {
                uniqueApis.insert(foundApis[i]);
            }

            for (const auto& api : uniqueApis) {
                size_t colonPos = api.find(':');
                std::string apiName = api.substr(0, colonPos);
                std::string description = api.substr(colonPos + 1);

                // Format output based on file type and API
                std::string ext = fs::path(filePath).extension().string();
                for (auto& c : ext) c = tolower(c);

                std::string fileType = (ext == ".dll") ? "DLL" : "executable";

                std::cout << "       [*] Potential " << fileType << " with " << description << ": " << filename << "\n";
            }
        }
        std::cout << "\n";
    }
}

void ProcessFile(const std::string& filePath) {
    std::string ext = fs::path(filePath).extension().string();

    for (auto& c : ext) c = tolower(c);

    if (ext == ".dll" || ext == ".exe") {
        AnalyzePEFile(filePath);
    }
}

void ProcessDirectory(const std::string& dirPath) {
    int fileCount = 0;
    int rpcServerCount = 0;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(dirPath,
            fs::directory_options::skip_permission_denied)) {

            try {
                if (entry.is_regular_file()) {
                    fileCount++;
                    std::string ext = entry.path().extension().string();
                    for (auto& c : ext) c = tolower(c);

                    if (ext == ".dll" || ext == ".exe") {
                        // Store current position to count RPC servers
                        auto beforePos = std::cout.tellp();
                        AnalyzePEFile(entry.path().string());
                        auto afterPos = std::cout.tellp();

                        if (afterPos > beforePos) {
                            rpcServerCount++;
                        }
                    }
                }
            }
            catch (const fs::filesystem_error& e) {
                // Skip files we can't access
                continue;
            }
        }

        std::cout << "[*] Scanned " << fileCount << " files, found " << rpcServerCount << " RPC server(s)\n";
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "[-] Filesystem error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        try {
            // Reconstruct the full path from all arguments (handles spaces in paths)
            std::string pathName;
            for (int i = 1; i < argc; i++) {
                if (i > 1) {
                    pathName += " ";
                }
                pathName += argv[i];
            }

            // Remove leading and trailing quotes if present
            while (!pathName.empty() && (pathName.front() == '"' || pathName.front() == ' ')) {
                pathName.erase(0, 1);
            }
            while (!pathName.empty() && (pathName.back() == '"' || pathName.back() == ' ')) {
                pathName.pop_back();
            }

            // Remove trailing backslash if present (except for root drives like C:\)
            if (pathName.length() > 3 && pathName.back() == '\\') {
                pathName.pop_back();
            }

            if (pathName.empty()) {
                std::cerr << "[-] Empty path provided" << std::endl;
                return 1;
            }

            fs::path inputPath(pathName);
            if (fs::exists(inputPath)) {
                if (fs::is_directory(inputPath)) {
                    std::cout << "[*] Scanning directory: " << inputPath.string() << "\n\n";
                    ProcessDirectory(inputPath.string());
                }
                else if (fs::is_regular_file(inputPath)) {
                    std::cout << "[*] Scanning file: " << inputPath.string() << "\n\n";
                    ProcessFile(inputPath.string());
                }
                else {
                    std::cerr << "[-] Path is neither a file nor directory: " << pathName << std::endl;
                    return 1;
                }
            }
            else {
                std::cerr << "[-] Path does not exist: " << pathName << std::endl;
                return 1;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[-] Error: " << e.what() << std::endl;
            return 1;
        }
    }
    else {
        std::cout << "Usage:\n\n";
        std::cout << "RPCServerFinding.exe \"Path\\to\\directory\"\n";
        std::cout << "RPCServerFinding.exe \"Path\\to\\PE\"\n";
        std::cout << "RPCServerFinding.exe Path\\with spaces\\to\\directory\n";
        return 1;
    }

    return 0;
}