#line 119 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef enum tagEFaultRepRetVal
{
    frrvOk = 0,
    frrvOkManifest,
    frrvOkQueued,
    frrvErr,
    frrvErrNoDW,
    frrvErrTimeout,
    frrvLaunchDebugger,
    frrvOkHeadless,
    frrvErrAnotherInstance
} EFaultRepRetVal;
#line 215 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef short int int16_t;
typedef unsigned short int uint16_t;
typedef char int8_t;
typedef unsigned char uint8_t;
#line 235 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef void VOID;

typedef int LONG;
typedef unsigned int ULONG;

typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef ULONGLONG DWORD64;
typedef DWORD64 *PDWORD64;
typedef LONGLONG *PLONG64;
typedef ULONGLONG *PULONG64;
typedef ULONGLONG *PULONGLONG;
typedef ULONG *PULONG;
typedef short SHORT;
typedef SHORT *PSHORT;
typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
typedef char *PSZ;
typedef ULONGLONG DWORDLONG;

typedef unsigned int DWORD;
typedef unsigned int DWORD32, *PDWORD32;

typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef float FLOAT;
typedef double DOUBLE;
typedef BOOL *PBOOL;
typedef BOOL *LPBOOL;
typedef BYTE *PBYTE;
typedef BYTE *LPBYTE;
typedef const BYTE *LPCBYTE;
typedef int *PINT;
typedef int *LPINT;
typedef WORD *PWORD;
typedef WORD *LPWORD;
typedef LONG *LPLONG;
typedef LPLONG PLONG;
typedef DWORD *PDWORD;
typedef DWORD *LPDWORD;
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned int *PUINT;
typedef BYTE BOOLEAN;
typedef BOOLEAN *PBOOLEAN;

typedef unsigned char UINT8;
typedef signed char INT8;
typedef unsigned short int UINT16;
typedef signed short int INT16;
typedef unsigned int UINT32, *PUINT32;
typedef signed int INT32, *PINT32;
typedef unsigned long long UINT64, *PUINT64;
typedef signed long long INT64, *PINT64;

typedef unsigned int ULONG32, *PULONG32;
typedef signed int LONG32, *PLONG32;
typedef unsigned long long ULONG64;
typedef signed long long LONG64;
#line 504 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef int INT_PTR;
typedef unsigned int UINT_PTR;

typedef int LONG_PTR;
typedef unsigned int ULONG_PTR, *PULONG_PTR;
typedef unsigned int DWORD_PTR, *PDWORD_PTR;
#line 546 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef LONG_PTR SSIZE_T, *PSSIZE_T;
#line 567 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef unsigned int size_t;
typedef int ptrdiff_t;
#line 577 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef LONG_PTR LPARAM;
#line 586 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef uint16_t WCHAR;
#line 595 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef int intptr_t;
typedef unsigned int uintptr_t;
#line 608 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef DWORD LCID;
typedef PDWORD PLCID;
typedef WORD LANGID;

typedef DWORD LCTYPE;

typedef WCHAR *PWCHAR;
typedef WCHAR *LPWCH, *PWCH;
typedef const WCHAR *LPCWCH, *PCWCH;
typedef WCHAR *NWPSTR;
typedef WCHAR *LPWSTR, *PWSTR;

typedef const WCHAR *LPCWSTR, *PCWSTR;

typedef char CHAR;
typedef CHAR *PCHAR;
typedef CHAR *LPCH, *PCH;
typedef const CHAR *LPCCH, *PCCH;
typedef CHAR *NPSTR;
typedef CHAR *LPSTR, *PSTR;
typedef const CHAR *LPCSTR, *PCSTR;





typedef CHAR TCHAR;
typedef CHAR _TCHAR;

typedef TCHAR *PTCHAR;
typedef TCHAR *LPTSTR, *PTSTR;
typedef const TCHAR *LPCTSTR;
#line 648 "../../dotnet/runtime/src/coreclr/pal/inc/pal_mstypes.h"
typedef VOID *HANDLE;
typedef HANDLE HWND;
typedef struct __PAL_RemoteHandle__ { HANDLE h; } *RHANDLE;
typedef HANDLE *PHANDLE;
typedef HANDLE *LPHANDLE;



typedef HANDLE HMODULE;
typedef HANDLE HINSTANCE;
typedef HANDLE HGLOBAL;
typedef HANDLE HLOCAL;
typedef HANDLE HRSRC;

typedef LONG HRESULT;
typedef LONG NTSTATUS;

typedef union _LARGE_INTEGER {
    struct {




        DWORD LowPart;
        LONG HighPart;

    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;


typedef struct _GUID {
    ULONG   Data1;
    USHORT  Data2;
    USHORT  Data3;
    UCHAR   Data4[ 8 ];
} GUID;
typedef const GUID *LPCGUID;



typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;





typedef PVOID PSID;
#line 75 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef PVOID NATIVE_LIBRARY_HANDLE;
#line 241 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef char * va_list;
#line 299 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
PAL_IsDebuggerPresent();
#line 337 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef long long time_t;
#line 372 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef DWORD ( *PTHREAD_START_ROUTINE)(LPVOID lpThreadParameter);
typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;




int
__attribute__((visibility("default")))
PAL_Initialize(
    int argc,
    char * const argv[]);


void
__attribute__((visibility("default")))
PAL_InitializeWithFlags(
    DWORD flags);


int
__attribute__((visibility("default")))
PAL_InitializeDLL();


void
__attribute__((visibility("default")))
PAL_SetInitializeDLLFlags(
    DWORD flags);


DWORD
__attribute__((visibility("default")))
PAL_InitializeCoreCLR(
    const char *szExePath, BOOL runningInExe);
#line 411 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
void
__attribute__((visibility("default")))
PAL_Shutdown(
    void);
#line 420 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
void
__attribute__((visibility("default")))
PAL_Terminate(
    void);
#line 430 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
void
__attribute__((visibility("default")))
PAL_TerminateEx(
    int exitCode);

typedef VOID (*PSHUTDOWN_CALLBACK)(BOOL isExecutingOnAltStack);


VOID
__attribute__((visibility("default")))
PAL_SetShutdownCallback(
     PSHUTDOWN_CALLBACK callback);


enum
{
    GenerateDumpFlagsNone = 0x00,
    GenerateDumpFlagsLoggingEnabled = 0x01,
    GenerateDumpFlagsVerboseLoggingEnabled = 0x02,
    GenerateDumpFlagsCrashReportEnabled = 0x04
};


BOOL
__attribute__((visibility("default")))
PAL_GenerateCoreDump(
     LPCSTR dumpName,
     INT dumpType,
     ULONG32 flags,
    LPSTR errorMessageBuffer,
    INT cbErrorMessageBuffer);

typedef VOID (*PPAL_STARTUP_CALLBACK)(
    char *modulePath,
    HMODULE hModule,
    PVOID parameter);


DWORD
__attribute__((visibility("default")))
PAL_RegisterForRuntimeStartup(
     DWORD dwProcessId,
     LPCWSTR lpApplicationGroupId,
     PPAL_STARTUP_CALLBACK pfnCallback,
     PVOID parameter,
     PVOID *ppUnregisterToken);


DWORD
__attribute__((visibility("default")))
PAL_UnregisterForRuntimeStartup(
     PVOID pUnregisterToken);


BOOL
__attribute__((visibility("default")))
PAL_NotifyRuntimeStarted();


LPCSTR
__attribute__((visibility("default")))
PAL_GetApplicationGroupId();

static const unsigned int MAX_DEBUGGER_TRANSPORT_PIPE_NAME_LENGTH = 260;


VOID
__attribute__((visibility("default")))
PAL_GetTransportName(
    const unsigned int MAX_TRANSPORT_NAME_LENGTH,
     char *name,
     const char *prefix,
     DWORD id,
     const char *applicationGroupId,
     const char *suffix);


VOID
__attribute__((visibility("default")))
PAL_GetTransportPipeName(
     char *name,
     DWORD id,
     const char *applicationGroupId,
     const char *suffix);


void
__attribute__((visibility("default")))
PAL_IgnoreProfileSignal(int signalNum);


HINSTANCE
__attribute__((visibility("default")))
PAL_RegisterModule(
     LPCSTR lpLibFileName);


VOID
__attribute__((visibility("default")))
PAL_UnregisterModule(
     HINSTANCE hInstance);


VOID
__attribute__((visibility("default")))
PAL_Random(
      LPVOID lpBuffer,
     DWORD dwLength);


BOOL
__attribute__((visibility("default")))
PAL_OpenProcessMemory(
     DWORD processId,
     DWORD* pHandle
);


VOID
__attribute__((visibility("default")))
PAL_CloseProcessMemory(
     DWORD handle
);


BOOL
__attribute__((visibility("default")))
PAL_ReadProcessMemory(
     DWORD handle,
     ULONG64 address,
     LPVOID buffer,
     SIZE_T size,
     SIZE_T* numberOfBytesRead
);


BOOL
__attribute__((visibility("default")))
PAL_ProbeMemory(
    PVOID pBuffer,
    DWORD cbBuffer,
    BOOL fWriteAccess);


int
__attribute__((visibility("default")))

PAL_PerfJitDump_Start(const char* path);


int
__attribute__((visibility("default")))

PAL_PerfJitDump_LogMethod(void* pCode, size_t codeSize, const char* symbol, void* debugInfo, void* unwindInfo);


int
__attribute__((visibility("default")))

PAL_PerfJitDump_Finish();
#line 618 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct _SECURITY_ATTRIBUTES {
            DWORD nLength;
            LPVOID lpSecurityDescriptor;
            BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
#line 666 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
CreateFileW(
         LPCWSTR lpFileName,
         DWORD dwDesiredAccess,
         DWORD dwShareMode,
         LPSECURITY_ATTRIBUTES lpSecurityAttributes,
         DWORD dwCreationDisposition,
         DWORD dwFlagsAndAttributes,
         HANDLE hTemplateFile);
#line 685 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
DWORD
__attribute__((visibility("default")))
SearchPathW(
     LPCWSTR lpPath,
     LPCWSTR lpFileName,
     LPCWSTR lpExtension,
     DWORD nBufferLength,
     LPWSTR lpBuffer,
     LPWSTR *lpFilePart
    );




BOOL
__attribute__((visibility("default")))
CopyFileW(
       LPCWSTR lpExistingFileName,
       LPCWSTR lpNewFileName,
       BOOL bFailIfExists);
#line 713 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
DeleteFileW(
         LPCWSTR lpFileName);
#line 728 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
MoveFileExW(
         LPCWSTR lpExistingFileName,
         LPCWSTR lpNewFileName,
         DWORD dwFlags);
#line 741 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[ 260 ];
    CHAR cAlternateFileName[ 14 ];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[ 260 ];
    WCHAR cAlternateFileName[ 14 ];
} WIN32_FIND_DATAW, *PWIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;






typedef WIN32_FIND_DATAA WIN32_FIND_DATA;
typedef PWIN32_FIND_DATAA PWIN32_FIND_DATA;
typedef LPWIN32_FIND_DATAA LPWIN32_FIND_DATA;



HANDLE
__attribute__((visibility("default")))
FindFirstFileW(
            LPCWSTR lpFileName,
            LPWIN32_FIND_DATAW lpFindFileData);
#line 791 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
FindNextFileW(
           HANDLE hFindFile,
           LPWIN32_FIND_DATAW lpFindFileData);
#line 804 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
FindClose(
        HANDLE hFindFile);


DWORD
__attribute__((visibility("default")))
GetFileAttributesW(
            LPCWSTR lpFileName);
#line 821 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef enum _GET_FILEEX_INFO_LEVELS {
  GetFileExInfoStandard
} GET_FILEEX_INFO_LEVELS;

typedef enum _FINDEX_INFO_LEVELS {
    FindExInfoStandard,
    FindExInfoBasic,
    FindExInfoMaxInfoLevel
} FINDEX_INFO_LEVELS;

typedef enum _FINDEX_SEARCH_OPS {
    FindExSearchNameMatch,
    FindExSearchLimitToDirectories,
    FindExSearchLimitToDevices,
    FindExSearchMaxSearchOp
} FINDEX_SEARCH_OPS;

typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
    DWORD      dwFileAttributes;
    FILETIME   ftCreationTime;
    FILETIME   ftLastAccessTime;
    FILETIME   ftLastWriteTime;
    DWORD      nFileSizeHigh;
    DWORD      nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;


BOOL
__attribute__((visibility("default")))
GetFileAttributesExW(
              LPCWSTR lpFileName,
              GET_FILEEX_INFO_LEVELS fInfoLevelId,
              LPVOID lpFileInformation);





typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    DWORD Offset;
    DWORD OffsetHigh;
    HANDLE  hEvent;
} OVERLAPPED, *LPOVERLAPPED;


BOOL
__attribute__((visibility("default")))
WriteFile(
       HANDLE hFile,
       LPCVOID lpBuffer,
       DWORD nNumberOfBytesToWrite,
       LPDWORD lpNumberOfBytesWritten,
       LPOVERLAPPED lpOverlapped);


BOOL
__attribute__((visibility("default")))
ReadFile(
      HANDLE hFile,
      LPVOID lpBuffer,
      DWORD nNumberOfBytesToRead,
      LPDWORD lpNumberOfBytesRead,
      LPOVERLAPPED lpOverlapped);






HANDLE
__attribute__((visibility("default")))
GetStdHandle(
          DWORD nStdHandle);


BOOL
__attribute__((visibility("default")))
SetEndOfFile(
          HANDLE hFile);


DWORD
__attribute__((visibility("default")))
SetFilePointer(
            HANDLE hFile,
            LONG lDistanceToMove,
            PLONG lpDistanceToMoveHigh,
            DWORD dwMoveMethod);


BOOL
__attribute__((visibility("default")))
SetFilePointerEx(
            HANDLE hFile,
            LARGE_INTEGER liDistanceToMove,
            PLARGE_INTEGER lpNewFilePointer,
            DWORD dwMoveMethod);


DWORD
__attribute__((visibility("default")))
GetFileSize(
         HANDLE hFile,
         LPDWORD lpFileSizeHigh);


BOOL
__attribute__((visibility("default"))) GetFileSizeEx(
           HANDLE hFile,
          PLARGE_INTEGER lpFileSize);


VOID
__attribute__((visibility("default")))
GetSystemTimeAsFileTime(
             LPFILETIME lpSystemTimeAsFileTime);

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;


VOID
__attribute__((visibility("default")))
GetSystemTime(
           LPSYSTEMTIME lpSystemTime);


BOOL
__attribute__((visibility("default")))
FileTimeToSystemTime(
             const FILETIME *lpFileTime,
             LPSYSTEMTIME lpSystemTime);




BOOL
__attribute__((visibility("default")))
FlushFileBuffers(
          HANDLE hFile);


UINT
__attribute__((visibility("default")))
GetConsoleOutputCP();


DWORD
__attribute__((visibility("default")))
GetFullPathNameW(
          LPCWSTR lpFileName,
          DWORD nBufferLength,
          LPWSTR lpBuffer,
          LPWSTR *lpFilePart);
#line 993 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
UINT
__attribute__((visibility("default")))
GetTempFileNameW(
          LPCWSTR lpPathName,
          LPCWSTR lpPrefixString,
          UINT uUnique,
          LPWSTR lpTempFileName);
#line 1008 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
DWORD
__attribute__((visibility("default")))
GetTempPathW(
          DWORD nBufferLength,
          LPWSTR lpBuffer);


DWORD
__attribute__((visibility("default")))
GetTempPathA(
          DWORD nBufferLength,
          LPSTR lpBuffer);
#line 1029 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
DWORD
__attribute__((visibility("default")))
GetCurrentDirectoryW(
              DWORD nBufferLength,
              LPWSTR lpBuffer);
#line 1042 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
CreateSemaphoreExW(
         LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
         LONG lInitialCount,
         LONG lMaximumCount,
         LPCWSTR lpName,
            DWORD dwFlags,
         DWORD dwDesiredAccess);


HANDLE
__attribute__((visibility("default")))
OpenSemaphoreW(
     DWORD dwDesiredAccess,
     BOOL bInheritHandle,
     LPCWSTR lpName);




BOOL
__attribute__((visibility("default")))
ReleaseSemaphore(
          HANDLE hSemaphore,
          LONG lReleaseCount,
          LPLONG lpPreviousCount);


HANDLE
__attribute__((visibility("default")))
CreateEventW(
          LPSECURITY_ATTRIBUTES lpEventAttributes,
          BOOL bManualReset,
          BOOL bInitialState,
          LPCWSTR lpName);


HANDLE
__attribute__((visibility("default")))
CreateEventExW(
          LPSECURITY_ATTRIBUTES lpEventAttributes,
          LPCWSTR lpName,
          DWORD dwFlags,
          DWORD dwDesiredAccess);
#line 1095 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
SetEvent(
      HANDLE hEvent);


BOOL
__attribute__((visibility("default")))
ResetEvent(
        HANDLE hEvent);


HANDLE
__attribute__((visibility("default")))
OpenEventW(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        LPCWSTR lpName);






HANDLE
__attribute__((visibility("default")))
CreateMutexW(
     LPSECURITY_ATTRIBUTES lpMutexAttributes,
     BOOL bInitialOwner,
     LPCWSTR lpName);


HANDLE
__attribute__((visibility("default")))
CreateMutexExW(
     LPSECURITY_ATTRIBUTES lpMutexAttributes,
     LPCWSTR lpName,
     DWORD dwFlags,
     DWORD dwDesiredAccess);
#line 1141 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
OpenMutexW(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        LPCWSTR lpName);






BOOL
__attribute__((visibility("default")))
ReleaseMutex(
     HANDLE hMutex);


DWORD
__attribute__((visibility("default")))
GetCurrentProcessId();


DWORD
__attribute__((visibility("default")))
GetCurrentSessionId();


HANDLE
__attribute__((visibility("default")))
GetCurrentProcess();


DWORD
__attribute__((visibility("default")))
GetCurrentThreadId();


size_t
__attribute__((visibility("default")))
PAL_GetCurrentOSThreadId();




HANDLE
__attribute__((visibility("default")))
PAL_GetCurrentThread();




typedef struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved_PAL_Undefined;
    LPWSTR lpDesktop_PAL_Undefined;
    LPWSTR lpTitle_PAL_Undefined;
    DWORD dwX_PAL_Undefined;
    DWORD dwY_PAL_Undefined;
    DWORD dwXSize_PAL_Undefined;
    DWORD dwYSize_PAL_Undefined;
    DWORD dwXCountChars_PAL_Undefined;
    DWORD dwYCountChars_PAL_Undefined;
    DWORD dwFillAttribute_PAL_Undefined;
    DWORD dwFlags;
    WORD wShowWindow_PAL_Undefined;
    WORD cbReserved2_PAL_Undefined;
    LPBYTE lpReserved2_PAL_Undefined;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

typedef STARTUPINFOW STARTUPINFO;
typedef LPSTARTUPINFOW LPSTARTUPINFO;





typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId_PAL_Undefined;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;


BOOL
__attribute__((visibility("default")))
CreateProcessW(
            LPCWSTR lpApplicationName,
            LPWSTR lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL bInheritHandles,
            DWORD dwCreationFlags,
            LPVOID lpEnvironment,
            LPCWSTR lpCurrentDirectory,
            LPSTARTUPINFOW lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation);




__attribute__((noreturn))
VOID
__attribute__((visibility("default")))
ExitProcess(
         UINT uExitCode);


BOOL
__attribute__((visibility("default")))
TerminateProcess(
          HANDLE hProcess,
          UINT uExitCode);


BOOL
__attribute__((visibility("default")))
GetExitCodeProcess(
            HANDLE hProcess,
            LPDWORD lpExitCode);


BOOL
__attribute__((visibility("default")))
GetProcessTimes(
         HANDLE hProcess,
         LPFILETIME lpCreationTime,
         LPFILETIME lpExitTime,
         LPFILETIME lpKernelTime,
         LPFILETIME lpUserTime);
#line 1286 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
DWORD
__attribute__((visibility("default")))
WaitForSingleObject(
             HANDLE hHandle,
             DWORD dwMilliseconds);


DWORD
__attribute__((visibility("default")))
PAL_WaitForSingleObjectPrioritized(
             HANDLE hHandle,
             DWORD dwMilliseconds);


DWORD
__attribute__((visibility("default")))
WaitForSingleObjectEx(
             HANDLE hHandle,
             DWORD dwMilliseconds,
             BOOL bAlertable);


DWORD
__attribute__((visibility("default")))
WaitForMultipleObjects(
                DWORD nCount,
                const HANDLE *lpHandles,
                BOOL bWaitAll,
                DWORD dwMilliseconds);


DWORD
__attribute__((visibility("default")))
WaitForMultipleObjectsEx(
              DWORD nCount,
              const HANDLE *lpHandles,
              BOOL bWaitAll,
              DWORD dwMilliseconds,
              BOOL bAlertable);


DWORD
__attribute__((visibility("default")))
SignalObjectAndWait(
     HANDLE hObjectToSignal,
     HANDLE hObjectToWaitOn,
     DWORD dwMilliseconds,
     BOOL bAlertable);





BOOL
__attribute__((visibility("default")))
DuplicateHandle(
         HANDLE hSourceProcessHandle,
         HANDLE hSourceHandle,
         HANDLE hTargetProcessHandle,
         LPHANDLE lpTargetHandle,
         DWORD dwDesiredAccess,
         BOOL bInheritHandle,
         DWORD dwOptions);


VOID
__attribute__((visibility("default")))
Sleep(
       DWORD dwMilliseconds);


DWORD
__attribute__((visibility("default")))
SleepEx(
     DWORD dwMilliseconds,
     BOOL bAlertable);


BOOL
__attribute__((visibility("default")))
SwitchToThread();
#line 1374 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
CreateThread(
          LPSECURITY_ATTRIBUTES lpThreadAttributes,
          DWORD dwStackSize,
          LPTHREAD_START_ROUTINE lpStartAddress,
          LPVOID lpParameter,
          DWORD dwCreationFlags,
          LPDWORD lpThreadId);


HANDLE
__attribute__((visibility("default")))
PAL_CreateThread64(
     LPSECURITY_ATTRIBUTES lpThreadAttributes,
     DWORD dwStackSize,
     LPTHREAD_START_ROUTINE lpStartAddress,
     LPVOID lpParameter,
     DWORD dwCreationFlags,
     SIZE_T* pThreadId);


__attribute__((noreturn))
VOID
__attribute__((visibility("default")))
ExitThread(
        DWORD dwExitCode);


DWORD
__attribute__((visibility("default")))
ResumeThread(
          HANDLE hThread);

typedef VOID ( *PAPCFUNC)(ULONG_PTR dwParam);


DWORD
__attribute__((visibility("default")))
QueueUserAPC(
          PAPCFUNC pfnAPC,
          HANDLE hThread,
          ULONG_PTR dwData);
#line 1566 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct __attribute__ ((aligned(16))) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

typedef struct _XMM_SAVE_AREA32 {
    WORD   ControlWord;
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE  Reserved4[96];
} XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;
#line 1623 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct __attribute__ ((aligned(16))) _CONTEXT {
#line 1632 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
#line 1643 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    DWORD ContextFlags;
    DWORD MxCsr;
#line 1650 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    WORD   SegCs;
    WORD   SegDs;
    WORD   SegEs;
    WORD   SegFs;
    WORD   SegGs;
    WORD   SegSs;
    DWORD EFlags;
#line 1662 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
#line 1673 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
#line 1694 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    DWORD64 Rip;
#line 1700 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    union {
        XMM_SAVE_AREA32 FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };
    };
#line 1728 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    M128A VectorRegister[26];
    DWORD64 VectorControl;
#line 1735 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT, *LPCONTEXT;
#line 1746 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        } ;
    } ;

    union {
        PDWORD64 IntegerContext[16];
        struct {
            PDWORD64 Rax;
            PDWORD64 Rcx;
            PDWORD64 Rdx;
            PDWORD64 Rbx;
            PDWORD64 Rsp;
            PDWORD64 Rbp;
            PDWORD64 Rsi;
            PDWORD64 Rdi;
            PDWORD64 R8;
            PDWORD64 R9;
            PDWORD64 R10;
            PDWORD64 R11;
            PDWORD64 R12;
            PDWORD64 R13;
            PDWORD64 R14;
            PDWORD64 R15;
        } ;
    } ;

} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;
#line 2559 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
GetThreadContext(
          HANDLE hThread,
           LPCONTEXT lpContext);


BOOL
__attribute__((visibility("default")))
SetThreadContext(
          HANDLE hThread,
          const CONTEXT *lpContext);
#line 2588 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
int
__attribute__((visibility("default")))
GetThreadPriority(
           HANDLE hThread);


BOOL
__attribute__((visibility("default")))
SetThreadPriority(
           HANDLE hThread,
           int nPriority);


BOOL
__attribute__((visibility("default")))
GetThreadTimes(
         HANDLE hThread,
         LPFILETIME lpCreationTime,
         LPFILETIME lpExitTime,
         LPFILETIME lpKernelTime,
         LPFILETIME lpUserTime);


HRESULT
__attribute__((visibility("default")))
SetThreadDescription(
     HANDLE hThread,
     PCWSTR lpThreadDescription
);




PVOID
__attribute__((visibility("default")))
PAL_GetStackBase();


PVOID
__attribute__((visibility("default")))
PAL_GetStackLimit();


DWORD
__attribute__((visibility("default")))
PAL_GetLogicalCpuCountFromOS();


DWORD
__attribute__((visibility("default")))
PAL_GetTotalCpuCount();


size_t
__attribute__((visibility("default")))
PAL_GetRestrictedPhysicalMemoryLimit();


BOOL
__attribute__((visibility("default")))
PAL_GetPhysicalMemoryUsed(size_t* val);


BOOL
__attribute__((visibility("default")))
PAL_GetCpuLimit(UINT* val);


size_t
__attribute__((visibility("default")))
PAL_GetLogicalProcessorCacheSizeFromOS();

typedef BOOL(*UnwindReadMemoryCallback)(PVOID address, PVOID buffer, SIZE_T size);

 BOOL __attribute__((visibility("default"))) PAL_VirtualUnwind(CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS *contextPointers);

 BOOL __attribute__((visibility("default"))) PAL_VirtualUnwindOutOfProc(CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS *contextPointers, PULONG64 functionStart, SIZE_T baseAddress, UnwindReadMemoryCallback readMemoryCallback);
#line 2708 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct _CRITICAL_SECTION {
    PVOID DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    ULONG_PTR SpinCount;




    volatile DWORD dwInitState;

    union CSNativeDataStorage
    {
        BYTE rgNativeDataStorage[96];
        PVOID pvAlign;
    } csnds;
} CRITICAL_SECTION, *PCRITICAL_SECTION, *LPCRITICAL_SECTION;

 VOID __attribute__((visibility("default"))) EnterCriticalSection( LPCRITICAL_SECTION lpCriticalSection);
 VOID __attribute__((visibility("default"))) LeaveCriticalSection( LPCRITICAL_SECTION lpCriticalSection);
 VOID __attribute__((visibility("default"))) InitializeCriticalSection( LPCRITICAL_SECTION lpCriticalSection);
 BOOL __attribute__((visibility("default"))) InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags);
 VOID __attribute__((visibility("default"))) DeleteCriticalSection( LPCRITICAL_SECTION lpCriticalSection);
 BOOL __attribute__((visibility("default"))) TryEnterCriticalSection( LPCRITICAL_SECTION lpCriticalSection);





UINT
__attribute__((visibility("default")))
SetErrorMode(
          UINT uMode);
#line 2765 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
CreateFileMappingW(
            HANDLE hFile,
            LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
            DWORD flProtect,
            DWORD dwMaxmimumSizeHigh,
            DWORD dwMaximumSizeLow,
            LPCWSTR lpName);
#line 2788 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
OpenFileMappingW(
          DWORD dwDesiredAccess,
          BOOL bInheritHandle,
          LPCWSTR lpName);



typedef INT_PTR ( *FARPROC)();


LPVOID
__attribute__((visibility("default")))
MapViewOfFile(
           HANDLE hFileMappingObject,
           DWORD dwDesiredAccess,
           DWORD dwFileOffsetHigh,
           DWORD dwFileOffsetLow,
           SIZE_T dwNumberOfBytesToMap);


LPVOID
__attribute__((visibility("default")))
MapViewOfFileEx(
           HANDLE hFileMappingObject,
           DWORD dwDesiredAccess,
           DWORD dwFileOffsetHigh,
           DWORD dwFileOffsetLow,
           SIZE_T dwNumberOfBytesToMap,
           LPVOID lpBaseAddress);


BOOL
__attribute__((visibility("default")))
UnmapViewOfFile(
         LPCVOID lpBaseAddress);



HMODULE
__attribute__((visibility("default")))
LoadLibraryW(
         LPCWSTR lpLibFileName);


HMODULE
__attribute__((visibility("default")))
LoadLibraryExW(
         LPCWSTR lpLibFileName,
           HANDLE hFile,
         DWORD dwFlags);


NATIVE_LIBRARY_HANDLE
__attribute__((visibility("default")))
PAL_LoadLibraryDirect(
         LPCWSTR lpLibFileName);


BOOL
__attribute__((visibility("default")))
PAL_FreeLibraryDirect(
         NATIVE_LIBRARY_HANDLE dl_handle);


HMODULE
__attribute__((visibility("default")))
PAL_GetPalHostModule();


FARPROC
__attribute__((visibility("default")))
PAL_GetProcAddressDirect(
         NATIVE_LIBRARY_HANDLE dl_handle,
         LPCSTR lpProcName);
#line 2882 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
PVOID
__attribute__((visibility("default")))
PAL_LOADLoadPEFile(HANDLE hFile, size_t offset);
#line 2899 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
PAL_LOADUnloadPEFile(PVOID ptr);
#line 2915 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
PAL_LOADMarkSectionAsNotNeeded(void * ptr);
#line 2928 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
FARPROC
__attribute__((visibility("default")))
GetProcAddress(
     HMODULE hModule,
     LPCSTR lpProcName);


BOOL
__attribute__((visibility("default")))
FreeLibrary(
      HMODULE hLibModule);


__attribute__((noreturn))
VOID
__attribute__((visibility("default")))
FreeLibraryAndExitThread(
     HMODULE hLibModule,
     DWORD dwExitCode);


BOOL
__attribute__((visibility("default")))
DisableThreadLibraryCalls(
     HMODULE hLibModule);


DWORD
__attribute__((visibility("default")))
GetModuleFileNameW(
     HMODULE hModule,
     LPWSTR lpFileName,
     DWORD nSize);
#line 2970 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
LPCVOID
__attribute__((visibility("default")))
PAL_GetSymbolModuleBase(PVOID symbol);


int
__attribute__((visibility("default")))
PAL_CopyModuleData(PVOID moduleBase, PVOID destinationBufferStart, PVOID destinationBufferEnd);;


LPCSTR
__attribute__((visibility("default")))
PAL_GetLoadLibraryError();


LPVOID
__attribute__((visibility("default")))
PAL_VirtualReserveFromExecutableMemoryAllocatorWithinRange(
     LPCVOID lpBeginAddress,
     LPCVOID lpEndAddress,
     SIZE_T dwSize,
     BOOL storeAllocationInfo);


void
__attribute__((visibility("default")))
PAL_GetExecutableMemoryAllocatorPreferredRange(
     PVOID *start,
     PVOID *end);


LPVOID
__attribute__((visibility("default")))
VirtualAlloc(
          LPVOID lpAddress,
          SIZE_T dwSize,
          DWORD flAllocationType,
          DWORD flProtect);


BOOL
__attribute__((visibility("default")))
VirtualFree(
         LPVOID lpAddress,
         SIZE_T dwSize,
         DWORD dwFreeType);
#line 3029 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
VirtualProtect(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flNewProtect,
            PDWORD lpflOldProtect);

typedef struct _MEMORYSTATUSEX {
  DWORD     dwLength;
  DWORD     dwMemoryLoad;
  DWORDLONG ullTotalPhys;
  DWORDLONG ullAvailPhys;
  DWORDLONG ullTotalPageFile;
  DWORDLONG ullAvailPageFile;
  DWORDLONG ullTotalVirtual;
  DWORDLONG ullAvailVirtual;
  DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;


BOOL
__attribute__((visibility("default")))
GlobalMemoryStatusEx(
              LPMEMORYSTATUSEX lpBuffer);

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase_PAL_Undefined;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;


SIZE_T
__attribute__((visibility("default")))
VirtualQuery(
          LPCVOID lpAddress,
          PMEMORY_BASIC_INFORMATION lpBuffer,
          SIZE_T dwLength);
#line 3079 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
FlushInstructionCache(
               HANDLE hProcess,
               LPCVOID lpBaseAddress,
               SIZE_T dwSize);





UINT
__attribute__((visibility("default")))
GetACP(void);

typedef struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
} CPINFO, *LPCPINFO;





int
__attribute__((visibility("default")))
MultiByteToWideChar(
             UINT CodePage,
             DWORD dwFlags,
             LPCSTR lpMultiByteStr,
             int cbMultiByte,
             LPWSTR lpWideCharStr,
             int cchWideChar);




int
__attribute__((visibility("default")))
WideCharToMultiByte(
             UINT CodePage,
             DWORD dwFlags,
             LPCWSTR lpWideCharStr,
             int cchWideChar,
             LPSTR lpMultiByteStr,
             int cbMultyByte,
             LPCSTR lpDefaultChar,
             LPBOOL lpUsedDefaultChar);
#line 3154 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS, *LPEXCEPTION_POINTERS;

typedef LONG EXCEPTION_DISPOSITION;

enum {
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExceptionNestedException,
    ExceptionCollidedUnwind,
};
#line 3180 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;



    DWORD UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#line 3219 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
HANDLE
__attribute__((visibility("default")))
OpenProcess(
     DWORD dwDesiredAccess,
     BOOL bInheritHandle,
     DWORD dwProcessId
    );


VOID
__attribute__((visibility("default")))
OutputDebugStringA(
     LPCSTR lpOutputString);


VOID
__attribute__((visibility("default")))
OutputDebugStringW(
     LPCWSTR lpOutputStrig);
#line 3246 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
VOID
__attribute__((visibility("default")))
DebugBreak();


DWORD
__attribute__((visibility("default")))
GetEnvironmentVariableW(
             LPCWSTR lpName,
             LPWSTR lpBuffer,
             DWORD nSize);
#line 3265 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
SetEnvironmentVariableW(
             LPCWSTR lpName,
             LPCWSTR lpValue);
#line 3278 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
LPWSTR
__attribute__((visibility("default")))
GetEnvironmentStringsW();




BOOL
__attribute__((visibility("default")))
FreeEnvironmentStringsW(
             LPWSTR);




BOOL
__attribute__((visibility("default")))
CloseHandle(
          HANDLE hObject);


VOID
__attribute__((visibility("default")))
RaiseException(
            DWORD dwExceptionCode,
            DWORD dwExceptionFlags,
            DWORD nNumberOfArguments,
            const ULONG_PTR *lpArguments);


VOID
__attribute__((visibility("default")))
__attribute__((noreturn))
RaiseFailFastException(
     PEXCEPTION_RECORD pExceptionRecord,
     PCONTEXT pContextRecord,
     DWORD dwFlags);


DWORD
__attribute__((visibility("default")))
GetTickCount();


ULONGLONG
__attribute__((visibility("default")))
GetTickCount64();


BOOL
__attribute__((visibility("default")))
QueryPerformanceCounter(
     LARGE_INTEGER *lpPerformanceCount
    );


BOOL
__attribute__((visibility("default")))
QueryPerformanceFrequency(
     LARGE_INTEGER *lpFrequency
    );


BOOL
__attribute__((visibility("default")))
QueryThreadCycleTime(
     HANDLE ThreadHandle,
     PULONG64 CycleTime);


INT
__attribute__((visibility("default")))
PAL_nanosleep(
     long timeInNs);

typedef EXCEPTION_DISPOSITION ( *PVECTORED_EXCEPTION_HANDLER)(
                           struct _EXCEPTION_POINTERS *ExceptionPointers);
#line 3367 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
unsigned char
__attribute__((visibility("default")))
BitScanForward(
      PDWORD Index,
     UINT qwMask)
{
    int iIndex = __builtin_ffs(qwMask);

    *Index = (DWORD)(iIndex - 1);


    return qwMask != 0 ? 1 : 0;
}



inline
unsigned char
__attribute__((visibility("default")))
BitScanForward64(
      PDWORD Index,
     UINT64 qwMask)
{
    int iIndex = __builtin_ffsll(qwMask);

    *Index = (DWORD)(iIndex - 1);


    return qwMask != 0 ? 1 : 0;
}
#line 3412 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
unsigned char
__attribute__((visibility("default")))
BitScanReverse(
      PDWORD Index,
     UINT qwMask)
{
#line 3424 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    int lzcount = __builtin_clzl(qwMask);
    *Index = (DWORD)(31 - lzcount);
    return qwMask != 0;
}



inline
unsigned char
__attribute__((visibility("default")))
BitScanReverse64(
      PDWORD Index,
     UINT64 qwMask)
{
#line 3443 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
    int lzcount = __builtin_clzll(qwMask);
    *Index = (DWORD)(63 - lzcount);
    return qwMask != 0;
}

inline void PAL_ArmInterlockedOperationBarrier()
{
#line 3467 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
}
#line 3491 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONG
__attribute__((visibility("default")))
InterlockedAdd(
      LONG volatile *lpAddend,
     LONG value)
{
    LONG result = __sync_add_and_fetch(lpAddend, value);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}



inline
LONGLONG
__attribute__((visibility("default")))
InterlockedAdd64(
      LONGLONG volatile *lpAddend,
     LONGLONG value)
{
    LONGLONG result = __sync_add_and_fetch(lpAddend, value);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3538 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONG
__attribute__((visibility("default")))
InterlockedIncrement(
      LONG volatile *lpAddend)
{
    LONG result = __sync_add_and_fetch(lpAddend, (LONG)1);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}



inline
LONGLONG
__attribute__((visibility("default")))
InterlockedIncrement64(
      LONGLONG volatile *lpAddend)
{
    LONGLONG result = __sync_add_and_fetch(lpAddend, (LONGLONG)1);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3583 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONG
__attribute__((visibility("default")))
InterlockedDecrement(
      LONG volatile *lpAddend)
{
    LONG result = __sync_sub_and_fetch(lpAddend, (LONG)1);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}





inline
LONGLONG
__attribute__((visibility("default")))
InterlockedDecrement64(
      LONGLONG volatile *lpAddend)
{
    LONGLONG result = __sync_sub_and_fetch(lpAddend, (LONGLONG)1);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3632 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONG
__attribute__((visibility("default")))
InterlockedExchange(
      LONG volatile *Target,
     LONG Value)
{
    LONG result = __atomic_exchange_n(Target, Value, __ATOMIC_ACQ_REL);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}



inline
LONGLONG
__attribute__((visibility("default")))
InterlockedExchange64(
      LONGLONG volatile *Target,
     LONGLONG Value)
{
    LONGLONG result = __atomic_exchange_n(Target, Value, __ATOMIC_ACQ_REL);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3683 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONG
__attribute__((visibility("default")))
InterlockedCompareExchange(
      LONG volatile *Destination,
     LONG Exchange,
     LONG Comperand)
{
    LONG result =
        __sync_val_compare_and_swap(
            Destination,
            Comperand,
            Exchange );
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3706 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONGLONG
__attribute__((visibility("default")))
InterlockedCompareExchange64(
      LONGLONG volatile *Destination,
     LONGLONG Exchange,
     LONGLONG Comperand)
{
    LONGLONG result =
        __sync_val_compare_and_swap(
            Destination,
            Comperand,
            Exchange );
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3742 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
LONG
__attribute__((visibility("default")))
InterlockedExchangeAdd(
      LONG volatile *Addend,
     LONG Value)
{
    LONG result = __sync_fetch_and_add(Addend, Value);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}



inline
LONGLONG
__attribute__((visibility("default")))
InterlockedExchangeAdd64(
      LONGLONG volatile *Addend,
     LONGLONG Value)
{
    LONGLONG result = __sync_fetch_and_add(Addend, Value);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}



inline
LONG
__attribute__((visibility("default")))
InterlockedAnd(
      LONG volatile *Destination,
     LONG Value)
{
    LONG result = __sync_fetch_and_and(Destination, Value);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}



inline
LONG
__attribute__((visibility("default")))
InterlockedOr(
      LONG volatile *Destination,
     LONG Value)
{
    LONG result = __sync_fetch_and_or(Destination, Value);
    PAL_ArmInterlockedOperationBarrier();
    return result;
}
#line 3819 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
VOID
__attribute__((visibility("default")))
MemoryBarrier()
{
    __sync_synchronize();
}



inline
VOID
__attribute__((visibility("default")))
YieldProcessor()
{

    __asm__ __volatile__(
        "rep\n"
        "nop");
#line 3845 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
}


DWORD
__attribute__((visibility("default")))
GetCurrentProcessorNumber();
#line 3860 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
PAL_HasGetCurrentProcessorNumber();
#line 3872 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
DWORD
__attribute__((visibility("default")))
FormatMessageW(
            DWORD dwFlags,
            LPCVOID lpSource,
            DWORD dwMessageId,
            DWORD dwLanguageId,
            LPWSTR lpBffer,
            DWORD nSize,
            va_list *Arguments);
#line 3889 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
DWORD
__attribute__((visibility("default")))
GetLastError();


VOID
__attribute__((visibility("default")))
SetLastError(
          DWORD dwErrCode);


LPWSTR
__attribute__((visibility("default")))
GetCommandLineW();






VOID
__attribute__((visibility("default")))
RtlRestoreContext(
   PCONTEXT ContextRecord,
   PEXCEPTION_RECORD ExceptionRecord
);


VOID
__attribute__((visibility("default")))
RtlCaptureContext(
   PCONTEXT ContextRecord
);


VOID
__attribute__((visibility("default")))
FlushProcessWriteBuffers();

typedef void (*PAL_ActivationFunction)(CONTEXT *context);
typedef BOOL (*PAL_SafeActivationCheckFunction)(SIZE_T ip, BOOL checkingCurrentThread);


VOID
__attribute__((visibility("default")))
PAL_SetActivationFunction(
     PAL_ActivationFunction pActivationFunction,
     PAL_SafeActivationCheckFunction pSafeActivationCheckFunction);


BOOL
__attribute__((visibility("default")))
PAL_InjectActivation(
     HANDLE hThread
);






typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[ 128 ];
} OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA;

typedef struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[ 128 ];
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW;






typedef OSVERSIONINFOA OSVERSIONINFO;
typedef POSVERSIONINFOA POSVERSIONINFO;
typedef LPOSVERSIONINFOA LPOSVERSIONINFO;


typedef struct _OSVERSIONINFOEXA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[ 128 ];
    WORD  wServicePackMajor;
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType;
    BYTE  wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;

typedef struct _OSVERSIONINFOEXW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[ 128 ];
    WORD  wServicePackMajor;
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType;
    BYTE  wReserved;
} OSVERSIONINFOEXW, *POSVERSIONINFOEXW, *LPOSVERSIONINFOEXW;






typedef OSVERSIONINFOEXA OSVERSIONINFOEX;
typedef POSVERSIONINFOEXA POSVERSIONINFOEX;
typedef LPOSVERSIONINFOEXA LPOSVERSIONINFOEX;


typedef struct _SYSTEM_INFO {
    WORD wProcessorArchitecture_PAL_Undefined;
    WORD wReserved_PAL_Undefined;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask_PAL_Undefined;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType_PAL_Undefined;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel_PAL_Undefined;
    WORD wProcessorRevision_PAL_Undefined;
} SYSTEM_INFO, *LPSYSTEM_INFO;


VOID
__attribute__((visibility("default")))
GetSystemInfo(
           LPSYSTEM_INFO lpSystemInfo);


BOOL
__attribute__((visibility("default")))
CreatePipe(
     PHANDLE hReadPipe,
     PHANDLE hWritePipe,
     LPSECURITY_ATTRIBUTES lpPipeAttributes,
     DWORD nSize
    );
#line 4051 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
BOOL
__attribute__((visibility("default")))
GetNumaHighestNodeNumber(
   PULONG HighestNodeNumber
);


BOOL
__attribute__((visibility("default")))
PAL_GetNumaProcessorNode(WORD procNo, WORD* node);


LPVOID
__attribute__((visibility("default")))
VirtualAllocExNuma(
   HANDLE hProcess,
    LPVOID lpAddress,
   SIZE_T dwSize,
   DWORD flAllocationType,
   DWORD flProtect,
   DWORD nndPreferred
);


BOOL
__attribute__((visibility("default")))
PAL_SetCurrentThreadAffinity(WORD procNo);


BOOL
__attribute__((visibility("default")))
PAL_GetCurrentThreadAffinitySet(SIZE_T size, UINT_PTR* data);
#line 4196 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
typedef int errno_t;




typedef unsigned int wint_t;
#line 4227 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 void * memcpy(void *, const void *, size_t);

 int memcmp(const void *, const void *, size_t);
 void * memset(void *, int, size_t);
 void * memmove(void *, const void *, size_t);
 void * memchr(const void *, int, size_t);
 long long int atoll(const char *) ;
 size_t strlen(const char *);
 int strcmp(const char*, const char *);
 int strncmp(const char*, const char *, size_t);
 int _strnicmp(const char *, const char *, size_t);
 char * strcat(char *, const char *);
 char * strncat(char *, const char *, size_t);
 char * strcpy(char *, const char *);
 char * strncpy(char *, const char *, size_t);
 char * strchr(const char *, int);
 char * strrchr(const char *, int);
 char * strpbrk(const char *, const char *);
 char * strstr(const char *, const char *);
 char * PAL_strtok(char *, const char *);
 int atoi(const char *);
 ULONG PAL_strtoul(const char *, char **, int);
 ULONGLONG PAL_strtoull(const char *, char **, int);
 double atof(const char *);
 double strtod(const char *, char **);
 int isprint(int);
 int isspace(int);
 int isalpha(int);
 int isalnum(int);
 int isdigit(int);
 int isxdigit(int);
 int tolower(int);
 int toupper(int);
 int iswalpha(wint_t);
 int iswdigit(wint_t);
 int iswupper(wint_t);
 int iswprint(wint_t);
 int iswspace(wint_t);
 int iswxdigit(wint_t);
 wint_t towupper(wint_t);
 wint_t towlower(wint_t);
#line 4275 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 __attribute__((visibility("default"))) errno_t memcpy_s(void *, size_t, const void *, size_t) ;
 errno_t memmove_s(void *, size_t, const void *, size_t);
 __attribute__((visibility("default"))) int _stricmp(const char *, const char *);
 __attribute__((visibility("default"))) int vsprintf_s(char *, size_t, const char *, va_list);
 char * _gcvt_s(char *, int, double, int);
 int __iscsym(int);
 __attribute__((visibility("default"))) int _wcsicmp(const WCHAR *, const WCHAR*);
 int _wcsnicmp(const WCHAR *, const WCHAR *, size_t);
 int _vsnprintf(char *, size_t, const char *, va_list);
 __attribute__((visibility("default"))) int _vsnprintf_s(char *, size_t, size_t, const char *, va_list);
 __attribute__((visibility("default"))) int _vsnwprintf_s(WCHAR *, size_t, size_t, const WCHAR *, va_list);
 __attribute__((visibility("default"))) int _snwprintf_s(WCHAR *, size_t, size_t, const WCHAR *, ...);
 __attribute__((visibility("default"))) int _snprintf_s(char *, size_t, size_t, const char *, ...);
 __attribute__((visibility("default"))) int sprintf_s(char *, size_t, const char *, ... );
 __attribute__((visibility("default"))) int swprintf_s(WCHAR *, size_t, const WCHAR *, ... );
 int _snwprintf_s(WCHAR *, size_t, size_t, const WCHAR *, ...);
 int vswprintf_s( WCHAR *, size_t, const WCHAR *, va_list);
 __attribute__((visibility("default"))) int sscanf_s(const char *, const char *, ...);
 __attribute__((visibility("default"))) errno_t _itow_s(int, WCHAR *, size_t, int);

 __attribute__((visibility("default"))) size_t PAL_wcslen(const WCHAR *);
 __attribute__((visibility("default"))) int PAL_wcscmp(const WCHAR*, const WCHAR*);
 __attribute__((visibility("default"))) int PAL_wcsncmp(const WCHAR *, const WCHAR *, size_t);
 __attribute__((visibility("default"))) WCHAR * PAL_wcscat(WCHAR *, const WCHAR *);
 WCHAR * PAL_wcscpy(WCHAR *, const WCHAR *);
 WCHAR * PAL_wcsncpy(WCHAR *, const WCHAR *, size_t);
 __attribute__((visibility("default"))) const WCHAR * PAL_wcschr(const WCHAR *, WCHAR);
 __attribute__((visibility("default"))) const WCHAR * PAL_wcsrchr(const WCHAR *, WCHAR);
 WCHAR * PAL_wcspbrk(const WCHAR *, const WCHAR *);
 __attribute__((visibility("default"))) WCHAR * PAL_wcsstr(const WCHAR *, const WCHAR *);
 int PAL_swprintf(WCHAR *, const WCHAR *, ...);
 int PAL_vswprintf(WCHAR *, const WCHAR *, va_list);
 int PAL_swscanf(const WCHAR *, const WCHAR *, ...);
 __attribute__((visibility("default"))) ULONG PAL_wcstoul(const WCHAR *, WCHAR **, int);
 double PAL_wcstod(const WCHAR *, WCHAR **);

 errno_t _wcslwr_s(WCHAR *, size_t sz);
 __attribute__((visibility("default"))) ULONGLONG PAL__wcstoui64(const WCHAR *, WCHAR **, int);
 __attribute__((visibility("default"))) errno_t _i64tow_s(long long, WCHAR *, size_t, int);
 int _wtoi(const WCHAR *);
#line 4346 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
unsigned int _rotl(unsigned int value, int shift)
{
    unsigned int retval = 0;

    shift &= 0x1f;
    retval = (value << shift) | (value >> (sizeof(int) * 8 - shift));
    return retval;
}
#line 4372 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
inline
unsigned int _rotr(unsigned int value, int shift)
{
    unsigned int retval;

    shift &= 0x1f;
    retval = (value >> shift) | (value << (sizeof(int) * 8 - shift));
    return retval;
}



 int abs(int);

 long long llabs(long long);


 int _finite(double);
 int _isnan(double);
 double _copysign(double, double);
 double PAL_acos(double);
 double acosh(double) ;
 double PAL_asin(double);
 double asinh(double) ;
 double atan(double) ;
 double atanh(double) ;
 double PAL_atan2(double, double);
 double cbrt(double) ;
 double ceil(double);
 double cos(double);
 double cosh(double);
 double PAL_exp(double);
 double fabs(double);
 double floor(double);
 double fmod(double, double);
 double fma(double, double, double) ;
 int PAL_ilogb(double);
 double PAL_log(double);
 double log2(double) ;
 double PAL_log10(double);
 double modf(double, double*);
 double PAL_pow(double, double);
 double sin(double);
 void PAL_sincos(double, double*, double*);
 double sinh(double);
 double sqrt(double);
 double tan(double);
 double tanh(double);
 double trunc(double);

 int _finitef(float);
 int _isnanf(float);
 float _copysignf(float, float);
 float PAL_acosf(float);
 float acoshf(float) ;
 float PAL_asinf(float);
 float asinhf(float) ;
 float atanf(float) ;
 float atanhf(float) ;
 float PAL_atan2f(float, float);
 float cbrtf(float) ;
 float ceilf(float);
 float cosf(float);
 float coshf(float);
 float PAL_expf(float);
 float fabsf(float);
 float floorf(float);
 float fmodf(float, float);
 float fmaf(float, float, float) ;
 int PAL_ilogbf(float);
 float PAL_logf(float);
 float log2f(float) ;
 float PAL_log10f(float);
 float modff(float, float*);
 float PAL_powf(float, float);
 float sinf(float);
 void PAL_sincosf(float, float*, float*);
 float sinhf(float);
 float sqrtf(float);
 float tanf(float);
 float tanhf(float);
 float truncf(float);
#line 4468 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 __attribute__((visibility("default"))) void * PAL_malloc(size_t);
 __attribute__((visibility("default"))) void PAL_free(void *);
 __attribute__((visibility("default"))) void * PAL_realloc(void *, size_t);
 char * PAL__strdup(const char *);
#line 4486 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 __attribute__((noreturn)) void PAL_exit(int);



 __attribute__((visibility("default"))) void PAL_qsort(void *, size_t, size_t, int( *)(const void *, const void *));
 __attribute__((visibility("default"))) void * PAL_bsearch(const void *, const void *, size_t, size_t,
    int( *)(const void *, const void *));

 time_t PAL_time(time_t *);



 __attribute__((visibility("default"))) int PAL__open(const char *szPath, int nFlags, ...);
 __attribute__((visibility("default"))) size_t PAL__pread(int fd, void *buf, size_t nbytes, ULONG64 offset);
 __attribute__((visibility("default"))) int PAL__close(int);
 __attribute__((visibility("default"))) int PAL__flushall();
#line 4510 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
struct _FILE;
typedef struct _FILE FILE;
typedef struct _FILE PAL_FILE;
#line 4532 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 int PAL_fclose(PAL_FILE *);
 __attribute__((visibility("default"))) int PAL_fflush(PAL_FILE *);
 size_t PAL_fwrite(const void *, size_t, size_t, PAL_FILE *);
 size_t PAL_fread(void *, size_t, size_t, PAL_FILE *);
 char * PAL_fgets(char *, int, PAL_FILE *);
 int PAL_fputs(const char *, PAL_FILE *);
 __attribute__((visibility("default"))) int PAL_fprintf(PAL_FILE *, const char *, ...);
 int PAL_vfprintf(PAL_FILE *, const char *, va_list);
 int PAL_fseek(PAL_FILE *, LONG, int);
 LONG PAL_ftell(PAL_FILE *);
 int PAL_ferror(PAL_FILE *);
 PAL_FILE * PAL_fopen(const char *, const char *);
 int PAL_setvbuf(PAL_FILE *stream, char *, int, size_t);
 __attribute__((visibility("default"))) int PAL_fwprintf(PAL_FILE *, const WCHAR *, ...);
 int PAL_vfwprintf(PAL_FILE *, const WCHAR *, va_list);
 int PAL_wprintf(const WCHAR*, ...);

 int _getw(PAL_FILE *);
 int _putw(int, PAL_FILE *);
 PAL_FILE * _fdopen(int, const char *);
 PAL_FILE * _wfopen(const WCHAR *, const WCHAR *);
#line 4560 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 int PAL_rand(void);
 void srand(unsigned int);

 __attribute__((visibility("default"))) int PAL_printf(const char *, ...);
 int PAL_vprintf(const char *, va_list);
#line 4572 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 __attribute__((visibility("default"))) PAL_FILE * PAL_get_stdout(int caller);
 PAL_FILE * PAL_get_stdin(int caller);
 __attribute__((visibility("default"))) PAL_FILE * PAL_get_stderr(int caller);
 __attribute__((visibility("default"))) int * PAL_errno(int caller);
#line 4589 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
 __attribute__((visibility("default"))) char * PAL_getenv(const char *);
 __attribute__((visibility("default"))) int _putenv(const char *);



 WCHAR PAL_ToUpperInvariant(WCHAR);
 WCHAR PAL_ToLowerInvariant(WCHAR);



typedef struct _PAL_IOCP_CPU_INFORMATION {
    union {
        FILETIME ftLastRecordedIdleTime;
        FILETIME ftLastRecordedCurrentTime;
    } LastRecordedTime;
    FILETIME ftLastRecordedKernelTime;
    FILETIME ftLastRecordedUserTime;
} PAL_IOCP_CPU_INFORMATION;


INT
__attribute__((visibility("default")))
PAL_GetCPUBusyTime(
      PAL_IOCP_CPU_INFORMATION *lpPrevCPUInfo);
#line 4640 "../../dotnet/runtime/src/coreclr/pal/inc/pal.h"
unsigned int PAL__mm_getcsr(void);


void PAL__mm_setcsr(unsigned int i);
#line 236 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
 const GUID GUID_NULL;

typedef GUID *LPGUID;
typedef const GUID *LPCGUID;
#line 258 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef GUID IID;
#line 269 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef GUID CLSID;
#line 278 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef CLSID *LPCLSID;

typedef UINT_PTR WPARAM;
typedef LONG_PTR LRESULT;

typedef LONG SCODE;


typedef union _ULARGE_INTEGER {
    struct {




        DWORD LowPart;
        DWORD HighPart;

    }

    u

     ;
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;



 __attribute__((visibility("default"))) LPVOID CoTaskMemAlloc(SIZE_T cb);
 __attribute__((visibility("default"))) void CoTaskMemFree(LPVOID pv);

typedef SHORT VARIANT_BOOL;



typedef WCHAR OLECHAR;
typedef OLECHAR* LPOLESTR;
typedef const OLECHAR* LPCOLESTR;

typedef WCHAR *BSTR;

typedef double DATE;

typedef union tagCY {
    struct {




        ULONG   Lo;
        LONG    Hi;

    } u;
    LONGLONG int64;
} CY, *LPCY;

typedef CY CURRENCY;

typedef struct tagDEC {
#line 350 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
    USHORT wReserved;
    union {
        struct {
            BYTE scale;
            BYTE sign;
        } u;
        USHORT signscale;
    } u;

    ULONG Hi32;
    union {
        struct {
            ULONG Lo32;
            ULONG Mid32;
        } v;
        ULONGLONG Lo64;
    } v;
} DECIMAL, *LPDECIMAL;
#line 381 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef struct tagBLOB {
    ULONG cbSize;
    BYTE *pBlobData;
} BLOB, *LPBLOB;

struct IStream;
struct IRecordInfo;

typedef unsigned short VARTYPE;

enum VARENUM {
    VT_EMPTY    = 0,
    VT_NULL = 1,
    VT_I2   = 2,
    VT_I4   = 3,
    VT_R4   = 4,
    VT_R8   = 5,
    VT_CY   = 6,
    VT_DATE = 7,
    VT_BSTR = 8,
    VT_DISPATCH = 9,
    VT_ERROR    = 10,
    VT_BOOL = 11,
    VT_VARIANT  = 12,
    VT_UNKNOWN  = 13,
    VT_DECIMAL  = 14,
    VT_I1   = 16,
    VT_UI1  = 17,
    VT_UI2  = 18,
    VT_UI4  = 19,
    VT_I8   = 20,
    VT_UI8  = 21,
    VT_INT  = 22,
    VT_UINT = 23,
    VT_VOID = 24,
    VT_HRESULT  = 25,
    VT_PTR  = 26,
    VT_SAFEARRAY    = 27,
    VT_CARRAY   = 28,
    VT_USERDEFINED  = 29,
    VT_LPSTR    = 30,
    VT_LPWSTR   = 31,
    VT_RECORD   = 36,
    VT_INT_PTR	= 37,
    VT_UINT_PTR	= 38,

    VT_FILETIME        = 64,
    VT_BLOB            = 65,
    VT_STREAM          = 66,
    VT_STORAGE         = 67,
    VT_STREAMED_OBJECT = 68,
    VT_STORED_OBJECT   = 69,
    VT_BLOB_OBJECT     = 70,
    VT_CF              = 71,
    VT_CLSID           = 72,

    VT_VECTOR   = 0x1000,
    VT_ARRAY    = 0x2000,
    VT_BYREF    = 0x4000,
    VT_TYPEMASK = 0xfff,
};

typedef struct tagVARIANT VARIANT, *LPVARIANT;
typedef struct tagSAFEARRAY SAFEARRAY;

struct tagVARIANT
    {
    union
        {
        struct
            {






            VARTYPE vt;
            WORD wReserved1;

            WORD wReserved2;
            WORD wReserved3;
            union
                {
                LONGLONG llVal;
                LONG lVal;
                BYTE bVal;
                SHORT iVal;
                FLOAT fltVal;
                DOUBLE dblVal;
                VARIANT_BOOL boolVal;
                SCODE scode;
                CY cyVal;
                DATE date;
                BSTR bstrVal;
                struct IUnknown *punkVal;
                struct IDispatch *pdispVal;
                SAFEARRAY *parray;
                BYTE *pbVal;
                SHORT *piVal;
                LONG *plVal;
                LONGLONG *pllVal;
                FLOAT *pfltVal;
                DOUBLE *pdblVal;
                VARIANT_BOOL *pboolVal;
                SCODE *pscode;
                CY *pcyVal;
                DATE *pdate;
                BSTR *pbstrVal;
                struct IUnknown **ppunkVal;
                VARIANT *pvarVal;
                PVOID byref;
                CHAR cVal;
                USHORT uiVal;
                ULONG ulVal;
                ULONGLONG ullVal;
                INT intVal;
                UINT uintVal;
                DECIMAL *pdecVal;
                CHAR *pcVal;
                USHORT *puiVal;
                ULONG *pulVal;
                ULONGLONG *pullVal;
                INT *pintVal;
                UINT *puintVal;
                struct __tagBRECORD
                    {
                    PVOID pvRecord;
                    struct IRecordInfo *pRecInfo;
                    } brecVal;
                } n3;
            } n2;
        DECIMAL decVal;
        } n1;
    };

typedef VARIANT VARIANTARG, *LPVARIANTARG;

 void VariantInit(VARIANT * pvarg);
 HRESULT VariantClear(VARIANT * pvarg);
#line 586 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
 HRESULT CreateStreamOnHGlobal(PVOID hGlobal, BOOL fDeleteOnRelease, struct IStream** ppstm);
#line 607 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
 HRESULT IIDFromString(LPOLESTR lpsz, IID* lpiid);
 int StringFromGUID2(const GUID * rguid, LPOLESTR lpsz, int cchMax);
#line 621 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef unsigned int ALG_ID;
#line 658 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
 LPWSTR StrRChrW(LPCWSTR lpStart, LPCWSTR lpEnd, WCHAR wMatch);
#line 750 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
 BOOL PathIsUNCW(LPCWSTR pszPath);
 BOOL PathCanonicalizeW(LPWSTR lpszDst, LPCWSTR lpszSrc);
#line 783 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef DWORD OLE_COLOR;



typedef VOID ( * WAITORTIMERCALLBACKFUNC) (PVOID, BOOLEAN );

typedef HANDLE HWND;




typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef VOID ( *WAITORTIMERCALLBACK)(PVOID, BOOLEAN);
#line 906 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef struct _JIT_DEBUG_INFO {
    DWORD dwSize;
    DWORD dwProcessorArchitecture;
    DWORD dwThreadID;
    DWORD dwReserved0;
    ULONG64 lpExceptionAddress;
    ULONG64 lpExceptionRecord;
    ULONG64 lpContextRecord;
} JIT_DEBUG_INFO, *LPJIT_DEBUG_INFO;

typedef JIT_DEBUG_INFO JIT_DEBUG_INFO32, *LPJIT_DEBUG_INFO32;
typedef JIT_DEBUG_INFO JIT_DEBUG_INFO64, *LPJIT_DEBUG_INFO64;
#line 929 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
struct IDispatch;
struct ITypeInfo;
struct ITypeLib;
struct IMoniker;

typedef VOID ( *LPOVERLAPPED_COMPLETION_ROUTINE)(
    DWORD dwErrorCode,
    DWORD dwNumberOfBytesTransfered,
    LPOVERLAPPED lpOverlapped);
#line 952 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef struct _EXCEPTION_DEBUG_INFO {
    EXCEPTION_RECORD ExceptionRecord;
    DWORD dwFirstChance;
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

typedef struct _CREATE_THREAD_DEBUG_INFO {
    HANDLE hThread;
    LPVOID lpThreadLocalBase;
    LPTHREAD_START_ROUTINE lpStartAddress;
} CREATE_THREAD_DEBUG_INFO, *LPCREATE_THREAD_DEBUG_INFO;

typedef struct _CREATE_PROCESS_DEBUG_INFO {
    HANDLE hFile;
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID lpBaseOfImage;
    DWORD dwDebugInfoFileOffset;
    DWORD nDebugInfoSize;
    LPVOID lpThreadLocalBase;
    LPTHREAD_START_ROUTINE lpStartAddress;
    LPVOID lpImageName;
    WORD fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;

typedef struct _EXIT_THREAD_DEBUG_INFO {
    DWORD dwExitCode;
} EXIT_THREAD_DEBUG_INFO, *LPEXIT_THREAD_DEBUG_INFO;

typedef struct _EXIT_PROCESS_DEBUG_INFO {
    DWORD dwExitCode;
} EXIT_PROCESS_DEBUG_INFO, *LPEXIT_PROCESS_DEBUG_INFO;

typedef struct _LOAD_DLL_DEBUG_INFO {
    HANDLE hFile;
    LPVOID lpBaseOfDll;
    DWORD dwDebugInfoFileOffset;
    DWORD nDebugInfoSize;
    LPVOID lpImageName;
    WORD fUnicode;
} LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;

typedef struct _UNLOAD_DLL_DEBUG_INFO {
    LPVOID lpBaseOfDll;
} UNLOAD_DLL_DEBUG_INFO, *LPUNLOAD_DLL_DEBUG_INFO;

typedef struct _OUTPUT_DEBUG_STRING_INFO {
    LPSTR lpDebugStringData;
    WORD fUnicode;
    WORD nDebugStringLength;
} OUTPUT_DEBUG_STRING_INFO, *LPOUTPUT_DEBUG_STRING_INFO;

typedef struct _RIP_INFO {
    DWORD dwError;
    DWORD dwType;
} RIP_INFO, *LPRIP_INFO;

typedef struct _DEBUG_EVENT {
    DWORD dwDebugEventCode;
    DWORD dwProcessId;
    DWORD dwThreadId;
    union {
        EXCEPTION_DEBUG_INFO Exception;
        CREATE_THREAD_DEBUG_INFO CreateThread;
        CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
        EXIT_THREAD_DEBUG_INFO ExitThread;
        EXIT_PROCESS_DEBUG_INFO ExitProcess;
        LOAD_DLL_DEBUG_INFO LoadDll;
        UNLOAD_DLL_DEBUG_INFO UnloadDll;
        OUTPUT_DEBUG_STRING_INFO DebugString;
        RIP_INFO RipInfo;
    } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;
#line 1029 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef
PRUNTIME_FUNCTION
GET_RUNTIME_FUNCTION_CALLBACK (
    DWORD64 ControlPc,
    PVOID Context
    );
typedef GET_RUNTIME_FUNCTION_CALLBACK *PGET_RUNTIME_FUNCTION_CALLBACK;

typedef
DWORD
OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK (
    HANDLE Process,
    PVOID TableAddress,
    PDWORD Entries,
    PRUNTIME_FUNCTION* Functions
    );
typedef OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK *POUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK;




typedef
EXCEPTION_DISPOSITION
(*PEXCEPTION_ROUTINE) (
    PEXCEPTION_RECORD ExceptionRecord,
    ULONG64 EstablisherFrame,
    PCONTEXT ContextRecord,
    PVOID DispatcherContext
    );
#line 1097 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef struct _DISPATCHER_CONTEXT {
    ULONG64 ControlPc;
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 EstablisherFrame;
    ULONG64 TargetIp;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    PVOID HistoryTable;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;
#line 1167 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef DISPATCHER_CONTEXT *PDISPATCHER_CONTEXT;





typedef struct _EXCEPTION_REGISTRATION_RECORD EXCEPTION_REGISTRATION_RECORD;
typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;

typedef LPVOID HKEY;
typedef LPVOID PACL;
typedef LPVOID LPBC;
typedef LPVOID PSECURITY_DESCRIPTOR;

typedef struct _EXCEPTION_RECORD64 {
    DWORD ExceptionCode;
    ULONG ExceptionFlags;
    ULONG64 ExceptionRecord;
    ULONG64 ExceptionAddress;
    ULONG NumberParameters;
    ULONG __unusedAlignment;
    ULONG64 ExceptionInformation[15];
} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;

typedef LONG ( *PTOP_LEVEL_EXCEPTION_FILTER)(
     struct _EXCEPTION_POINTERS *ExceptionInfo
    );
typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;
#line 1204 "../../dotnet/runtime/src/coreclr/pal/inc/rt/palrt.h"
typedef struct LIST_ENTRY32 {
    ULONG Flink;
    ULONG Blink;
} LIST_ENTRY32;
typedef LIST_ENTRY32 *PLIST_ENTRY32;

typedef struct LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} LIST_ENTRY64;
typedef LIST_ENTRY64 *PLIST_ENTRY64;



typedef struct _HSATELLITE *HSATELLITE;

 HSATELLITE __attribute__((visibility("default"))) PAL_LoadSatelliteResourceW(LPCWSTR SatelliteResourceFileName);
 HSATELLITE __attribute__((visibility("default"))) PAL_LoadSatelliteResourceA(LPCSTR SatelliteResourceFileName);
 BOOL __attribute__((visibility("default"))) PAL_FreeSatelliteResource(HSATELLITE SatelliteResource);
 UINT __attribute__((visibility("default"))) PAL_LoadSatelliteStringW(HSATELLITE SatelliteResource,
             UINT uID,
             LPWSTR lpBuffer,
             UINT nBufferMax);
 UINT __attribute__((visibility("default"))) PAL_LoadSatelliteStringA(HSATELLITE SatelliteResource,
             UINT uID,
             LPSTR lpBuffer,
             UINT nBufferMax);

 HRESULT __attribute__((visibility("default"))) PAL_CoCreateInstance(const CLSID *   rclsid,
                             const IID *     riid,
                             void     **ppv);





 HRESULT
CoCreateGuid( GUID * pguid);
#line 35 "../../dotnet/runtime/src/coreclr/pal/inc/rt/pshpack4.h"
#pragma pack(4)
#line 34 "../../dotnet/runtime/src/coreclr/pal/inc/rt/pshpack2.h"
#pragma pack(2)
#line 69 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {
    USHORT ne_magic;
    CHAR   ne_ver;
    CHAR   ne_rev;
    USHORT ne_enttab;
    USHORT ne_cbenttab;
    LONG   ne_crc;
    USHORT ne_flags;
    USHORT ne_autodata;
    USHORT ne_heap;
    USHORT ne_stack;
    LONG   ne_csip;
    LONG   ne_sssp;
    USHORT ne_cseg;
    USHORT ne_cmod;
    USHORT ne_cbnrestab;
    USHORT ne_segtab;
    USHORT ne_rsrctab;
    USHORT ne_restab;
    USHORT ne_modtab;
    USHORT ne_imptab;
    LONG   ne_nrestab;
    USHORT ne_cmovent;
    USHORT ne_align;
    USHORT ne_cres;
    UCHAR  ne_exetyp;
    UCHAR  ne_flagsothers;
    USHORT ne_pretthunks;
    USHORT ne_psegrefbytes;
    USHORT ne_swaparea;
    USHORT ne_expver;
  } IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {
    USHORT e32_magic;
    UCHAR  e32_border;
    UCHAR  e32_worder;
    ULONG  e32_level;
    USHORT e32_cpu;
    USHORT e32_os;
    ULONG  e32_ver;
    ULONG  e32_mflags;
    ULONG  e32_mpages;
    ULONG  e32_startobj;
    ULONG  e32_eip;
    ULONG  e32_stackobj;
    ULONG  e32_esp;
    ULONG  e32_pagesize;
    ULONG  e32_lastpagesize;
    ULONG  e32_fixupsize;
    ULONG  e32_fixupsum;
    ULONG  e32_ldrsize;
    ULONG  e32_ldrsum;
    ULONG  e32_objtab;
    ULONG  e32_objcnt;
    ULONG  e32_objmap;
    ULONG  e32_itermap;
    ULONG  e32_rsrctab;
    ULONG  e32_rsrccnt;
    ULONG  e32_restab;
    ULONG  e32_enttab;
    ULONG  e32_dirtab;
    ULONG  e32_dircnt;
    ULONG  e32_fpagetab;
    ULONG  e32_frectab;
    ULONG  e32_impmod;
    ULONG  e32_impmodcnt;
    ULONG  e32_impproc;
    ULONG  e32_pagesum;
    ULONG  e32_datapage;
    ULONG  e32_preload;
    ULONG  e32_nrestab;
    ULONG  e32_cbnrestab;
    ULONG  e32_nressum;
    ULONG  e32_autodata;
    ULONG  e32_debuginfo;
    ULONG  e32_debuglen;
    ULONG  e32_instpreload;
    ULONG  e32_instdemand;
    ULONG  e32_heapsize;
    UCHAR  e32_res3[12];
    ULONG  e32_winresoff;
    ULONG  e32_winreslen;
    USHORT e32_devid;
    USHORT e32_ddkver;
  } IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;
#line 36 "../../dotnet/runtime/src/coreclr/pal/inc/rt/poppack.h"
#pragma pack()
#line 186 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
#line 254 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#line 267 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_OPTIONAL_HEADER {
#line 272 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;
#line 286 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   SizeOfStackReserve;
    ULONG   SizeOfStackCommit;
    ULONG   SizeOfHeapReserve;
    ULONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONG  BaseOfData;
    ULONG  BaseOfBss;
    ULONG  GprMask;
    ULONG  CprMask[4];
    ULONG  GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;
    ULONG       SizeOfInitializedData;
    ULONG       SizeOfUninitializedData;
    ULONG       AddressOfEntryPoint;
    ULONG       BaseOfCode;
    ULONGLONG   ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    USHORT      MajorOperatingSystemVersion;
    USHORT      MinorOperatingSystemVersion;
    USHORT      MajorImageVersion;
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       CheckSum;
    USHORT      Subsystem;
    USHORT      DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
#line 374 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;




typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_ROM_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;





typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#line 499 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_SECTION_HEADER {
    UCHAR   Name[8];
    union {
            ULONG   PhysicalAddress;
            ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
#line 34 "../../dotnet/runtime/src/coreclr/pal/inc/rt/pshpack2.h"
#pragma pack(2)
#line 586 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_SYMBOL {
    union {
        UCHAR   ShortName[8];
        struct {
            ULONG   Short;
            ULONG   Long;
        } Name;
        ULONG   LongName[2];
    } N;
    ULONG   Value;
    SHORT   SectionNumber;
    USHORT  Type;
    UCHAR   StorageClass;
    UCHAR   NumberOfAuxSymbols;
} IMAGE_SYMBOL;
typedef IMAGE_SYMBOL *PIMAGE_SYMBOL;
#line 729 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef union _IMAGE_AUX_SYMBOL {
    struct {
        ULONG    TagIndex;
        union {
            struct {
                USHORT  Linenumber;
                USHORT  Size;
            } LnSz;
           ULONG    TotalSize;
        } Misc;
        union {
            struct {
                ULONG    PointerToLinenumber;
                ULONG    PointerToNextFunction;
            } Function;
            struct {
                USHORT   Dimension[4];
            } Array;
        } FcnAry;
        USHORT  TvIndex;
    } Sym;
    struct {
        UCHAR   Name[18];
    } File;
    struct {
        ULONG   Length;
        USHORT  NumberOfRelocations;
        USHORT  NumberOfLinenumbers;
        ULONG   CheckSum;
        SHORT   Number;
        UCHAR   Selection;
    } Section;
} IMAGE_AUX_SYMBOL;
typedef IMAGE_AUX_SYMBOL *PIMAGE_AUX_SYMBOL;



typedef enum IMAGE_AUX_SYMBOL_TYPE {
    IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1,
} IMAGE_AUX_SYMBOL_TYPE;
#line 34 "../../dotnet/runtime/src/coreclr/pal/inc/rt/pshpack2.h"
#pragma pack(2)
#line 772 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
    UCHAR bAuxType;
    UCHAR bReserved;
    ULONG SymbolTableIndex;
    UCHAR rgbReserved[12];
} IMAGE_AUX_SYMBOL_TOKEN_DEF;

typedef IMAGE_AUX_SYMBOL_TOKEN_DEF *PIMAGE_AUX_SYMBOL_TOKEN_DEF;
#line 36 "../../dotnet/runtime/src/coreclr/pal/inc/rt/poppack.h"
#pragma pack()
#line 803 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_RELOCATION {
    union {
        ULONG   VirtualAddress;
        ULONG   RelocCount;
    };
    ULONG   SymbolTableIndex;
    USHORT  Type;
} IMAGE_RELOCATION;
typedef IMAGE_RELOCATION *PIMAGE_RELOCATION;
#line 1131 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_LINENUMBER {
    union {
        ULONG   SymbolTableIndex;
        ULONG   VirtualAddress;
    } Type;
    USHORT  Linenumber;
} IMAGE_LINENUMBER;
typedef IMAGE_LINENUMBER *PIMAGE_LINENUMBER;
#line 36 "../../dotnet/runtime/src/coreclr/pal/inc/rt/poppack.h"
#pragma pack()
#line 1150 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_BASE_RELOCATION {
    ULONG   VirtualAddress;
    ULONG   SizeOfBlock;

} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION * PIMAGE_BASE_RELOCATION;
#line 1198 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
    UCHAR    Name[16];
    UCHAR    Date[12];
    UCHAR    UserID[6];
    UCHAR    GroupID[6];
    UCHAR    Mode[8];
    UCHAR    Size[10];
    UCHAR    EndHeader[2];
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;
#line 1218 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;
    ULONG   AddressOfNames;
    ULONG   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
#line 1236 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_IMPORT_BY_NAME {
    USHORT  Hint;
    UCHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
#line 35 "../../dotnet/runtime/src/coreclr/pal/inc/rt/pshpack8.h"
#pragma pack(8)
#line 1243 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
#line 36 "../../dotnet/runtime/src/coreclr/pal/inc/rt/poppack.h"
#pragma pack()
#line 1255 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        ULONG ForwarderString;
        ULONG Function;
        ULONG Ordinal;
        ULONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
#line 1285 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG   StartAddressOfRawData;
    ULONGLONG   EndAddressOfRawData;
    ULONGLONG   AddressOfIndex;
    ULONGLONG   AddressOfCallBacks;
    ULONG   SizeOfZeroFill;
    ULONG   Characteristics;
} IMAGE_TLS_DIRECTORY64;
typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
    ULONG   StartAddressOfRawData;
    ULONG   EndAddressOfRawData;
    ULONG   AddressOfIndex;
    ULONG   AddressOfCallBacks;
    ULONG   SizeOfZeroFill;
    ULONG   Characteristics;
} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;
#line 1316 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA;

typedef IMAGE_TLS_DIRECTORY32           IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY32          PIMAGE_TLS_DIRECTORY;


typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;
        ULONG   OriginalFirstThunk;
    } u;
    ULONG   TimeDateStamp;
#line 1333 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
    ULONG   ForwarderChain;
    ULONG   Name;
    ULONG   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR *PIMAGE_IMPORT_DESCRIPTOR;
#line 1343 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    ULONG   TimeDateStamp;
    USHORT  OffsetModuleName;
    USHORT  NumberOfModuleForwarderRefs;

} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
    ULONG   TimeDateStamp;
    USHORT  OffsetModuleName;
    USHORT  Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;
#line 1374 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    USHORT  NumberOfNamedEntries;
    USHORT  NumberOfIdEntries;

} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
#line 1401 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            ULONG NameOffset:31;
            ULONG NameIsString:1;
        };
        ULONG   Name;
        USHORT  Id;
    };
    union {
        ULONG   OffsetToData;
        struct {
            ULONG   OffsetToDirectory:31;
            ULONG   DataIsDirectory:1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
#line 1428 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
    USHORT  Length;
    CHAR    NameString[ 1 ];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;


typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    USHORT  Length;
    WCHAR   NameString[ 1 ];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;
#line 1449 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    ULONG   OffsetToData;
    ULONG   Size;
    ULONG   CodePage;
    ULONG   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
#line 1460 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   GlobalFlagsClear;
    ULONG   GlobalFlagsSet;
    ULONG   CriticalSectionDefaultTimeout;
    ULONG   DeCommitFreeBlockThreshold;
    ULONG   DeCommitTotalFreeThreshold;
    ULONG   LockPrefixTable;
    ULONG   MaximumAllocationSize;
    ULONG   VirtualMemoryThreshold;
    ULONG   ProcessHeapFlags;
    ULONG   ProcessAffinityMask;
    USHORT  CSDVersion;
    USHORT  Reserved1;
    ULONG   EditList;
    ULONG   Reserved[ 1 ];
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   GlobalFlagsClear;
    ULONG   GlobalFlagsSet;
    ULONG   CriticalSectionDefaultTimeout;
    ULONGLONG  DeCommitFreeBlockThreshold;
    ULONGLONG  DeCommitTotalFreeThreshold;
    ULONGLONG  LockPrefixTable;
    ULONGLONG  MaximumAllocationSize;
    ULONGLONG  VirtualMemoryThreshold;
    ULONGLONG  ProcessAffinityMask;
    ULONG   ProcessHeapFlags;
    USHORT  CSDVersion;
    USHORT  Reserved1;
    ULONGLONG  EditList;
    ULONG   Reserved[ 2 ];
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;





typedef IMAGE_LOAD_CONFIG_DIRECTORY32   IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY32  PIMAGE_LOAD_CONFIG_DIRECTORY;
#line 1519 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY {
    ULONG FuncStart;
    ULONG PrologLen : 8;
    ULONG FuncLen : 22;
    ULONG ThirtyTwoBit : 1;
    ULONG ExceptionFlag : 1;
} IMAGE_CE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY {
    ULONGLONG BeginAddress;
    ULONGLONG EndAddress;
    ULONGLONG ExceptionHandler;
    ULONGLONG HandlerData;
    ULONGLONG PrologEndAddress;
} IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG ExceptionHandler;
    ULONG HandlerData;
    ULONG PrologEndAddress;
} IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindInfoAddress;
} _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef  _IMAGE_RUNTIME_FUNCTION_ENTRY  IMAGE_IA64_RUNTIME_FUNCTION_ENTRY;
typedef _PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY;
#line 1566 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef  _IMAGE_RUNTIME_FUNCTION_ENTRY  IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef _PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;
#line 1575 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_DEBUG_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Type;
    ULONG   SizeOfData;
    ULONG   AddressOfRawData;
    ULONG   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
#line 1605 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
    ULONG   NumberOfSymbols;
    ULONG   LvaToFirstSymbol;
    ULONG   NumberOfLinenumbers;
    ULONG   LvaToFirstLinenumber;
    ULONG   RvaToFirstByteOfCode;
    ULONG   RvaToLastByteOfCode;
    ULONG   RvaToFirstByteOfData;
    ULONG   RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;






typedef struct _FPO_DATA {
    ULONG       ulOffStart;
    ULONG       cbProcSize;
    ULONG       cdwLocals;
    USHORT      cdwParams;
    USHORT      cbProlog : 8;
    USHORT      cbRegs   : 3;
    USHORT      fHasSEH  : 1;
    USHORT      fUseBP   : 1;
    USHORT      reserved : 1;
    USHORT      cbFrame  : 2;
} FPO_DATA, *PFPO_DATA;





typedef struct _IMAGE_DEBUG_MISC {
    ULONG       DataType;
    ULONG       Length;

    BOOLEAN     Unicode;
    UCHAR       Reserved[ 3 ];
    UCHAR       Data[ 1 ];
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;
#line 1654 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_FUNCTION_ENTRY {
    ULONG   StartingAddress;
    ULONG   EndingAddress;
    ULONG   EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64 {
    ULONGLONG   StartingAddress;
    ULONGLONG   EndingAddress;
    union {
        ULONGLONG   EndOfPrologue;
        ULONGLONG   UnwindInfoAddress;
    } u;
} IMAGE_FUNCTION_ENTRY64, *PIMAGE_FUNCTION_ENTRY64;
#line 1689 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
    USHORT      Signature;
    USHORT      Flags;
    USHORT      Machine;
    USHORT      Characteristics;
    ULONG       TimeDateStamp;
    ULONG       CheckSum;
    ULONG       ImageBase;
    ULONG       SizeOfImage;
    ULONG       NumberOfSections;
    ULONG       ExportedNamesSize;
    ULONG       DebugDirectorySize;
    ULONG       SectionAlignment;
    ULONG       Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _NON_PAGED_DEBUG_INFO {
    USHORT      Signature;
    USHORT      Flags;
    ULONG       Size;
    USHORT      Machine;
    USHORT      Characteristics;
    ULONG       TimeDateStamp;
    ULONG       CheckSum;
    ULONG       SizeOfImage;
    ULONGLONG   ImageBase;


} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;
#line 1739 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct _ImageArchitectureHeader {
    unsigned int AmaskValue: 1;

    int :7;
    unsigned int AmaskShift: 8;
    int :16;
    ULONG FirstEntryRVA;
} IMAGE_ARCHITECTURE_HEADER, *PIMAGE_ARCHITECTURE_HEADER;

typedef struct _ImageArchitectureEntry {
    ULONG FixupInstRVA;
    ULONG NewInst;
} IMAGE_ARCHITECTURE_ENTRY, *PIMAGE_ARCHITECTURE_ENTRY;
#line 36 "../../dotnet/runtime/src/coreclr/pal/inc/rt/poppack.h"
#pragma pack()
#line 1762 "../../dotnet/runtime/src/coreclr/pal/inc/rt/ntimage.h"
typedef struct IMPORT_OBJECT_HEADER {
    USHORT  Sig1;
    USHORT  Sig2;
    USHORT  Version;
    USHORT  Machine;
    ULONG   TimeDateStamp;
    ULONG   SizeOfData;

    union {
        USHORT  Ordinal;
        USHORT  Hint;
    } u;

    USHORT  Type : 2;
    USHORT  NameType : 3;
    USHORT  Reserved : 11;
} IMPORT_OBJECT_HEADER;

typedef enum IMPORT_OBJECT_TYPE
{
    IMPORT_OBJECT_CODE = 0,
    IMPORT_OBJECT_DATA = 1,
    IMPORT_OBJECT_CONST = 2,
} IMPORT_OBJECT_TYPE;

typedef enum IMPORT_OBJECT_NAME_TYPE
{
    IMPORT_OBJECT_ORDINAL = 0,
    IMPORT_OBJECT_NAME = 1,
    IMPORT_OBJECT_NAME_NO_PREFIX = 2,
    IMPORT_OBJECT_NAME_UNDECORATE = 3,

} IMPORT_OBJECT_NAME_TYPE;
#line 30 "../../dotnet/runtime/src/coreclr/pal/inc/rt/rpc.h"
struct IRpcStubBuffer;
struct IRpcChannelBuffer;

typedef void* PRPC_MESSAGE;
typedef void* RPC_IF_HANDLE;
#line 18 "../../dotnet/runtime/src/coreclr/pal/inc/rt/unknwn.h"
typedef struct IUnknown IUnknown;

typedef IUnknown *LPUNKNOWN;


 const IID IID_IUnknown;

struct
IUnknown
{
    virtual HRESULT QueryInterface(
        const IID * riid,
        void **ppvObject) = 0;

    virtual ULONG AddRef( void) = 0;

    virtual ULONG Release( void) = 0;
};
#line 43 "../../dotnet/runtime/src/coreclr/pal/inc/rt/unknwn.h"
 const IID IID_IClassFactory;

struct
IClassFactory : public IUnknown
{
    virtual HRESULT CreateInstance(
        IUnknown *pUnkOuter,
        const IID * riid,
        void **ppvObject) = 0;

    virtual HRESULT LockServer(
        BOOL fLock) = 0;
};
#line 21 "../../dotnet/runtime/src/coreclr/pal/inc/rt/objidl.h"
 const IID IID_IEnumUnknown;

struct IEnumUnknown : public IUnknown
{
public:
    virtual HRESULT Next(

        _In_  ULONG celt,

        _Out_writes_to_(celt,*pceltFetched)  IUnknown **rgelt,

        _Out_opt_  ULONG *pceltFetched) = 0;

    virtual HRESULT Skip(
          ULONG celt) = 0;

    virtual HRESULT Reset( void) = 0;

    virtual HRESULT Clone(
           IEnumUnknown **ppenum) = 0;

};
#line 50 "../../dotnet/runtime/src/coreclr/pal/inc/rt/objidl.h"
 const IID IID_ISequentialStream;

struct ISequentialStream : public IUnknown
{
public:
    virtual HRESULT Read(
          void *pv,
          ULONG cb,
          ULONG *pcbRead) = 0;

    virtual HRESULT Write(
          const void *pv,
          ULONG cb,
          ULONG *pcbWritten) = 0;

};
#line 73 "../../dotnet/runtime/src/coreclr/pal/inc/rt/objidl.h"
typedef struct tagSTATSTG
    {
    LPOLESTR pwcsName;
    DWORD type;
    ULARGE_INTEGER cbSize;
    FILETIME mtime;
    FILETIME ctime;
    FILETIME atime;
    DWORD grfMode;
    DWORD grfLocksSupported;
    CLSID clsid;
    DWORD grfStateBits;
    DWORD reserved;
    } 	STATSTG;

typedef
enum tagSTGTY
    {	STGTY_STORAGE	= 1,
	STGTY_STREAM	= 2,
	STGTY_LOCKBYTES	= 3,
	STGTY_PROPERTY	= 4
    } 	STGTY;

typedef
enum tagSTREAM_SEEK
    {	STREAM_SEEK_SET	= 0,
	STREAM_SEEK_CUR	= 1,
	STREAM_SEEK_END	= 2
    } 	STREAM_SEEK;

typedef
enum tagSTATFLAG
    {	STATFLAG_DEFAULT	= 0,
	STATFLAG_NONAME	= 1,
	STATFLAG_NOOPEN	= 2
    } 	STATFLAG;


 const IID IID_IStream;

struct
IStream : public ISequentialStream
{
public:
    virtual HRESULT Seek(
          LARGE_INTEGER dlibMove,
          DWORD dwOrigin,
          ULARGE_INTEGER *plibNewPosition) = 0;

    virtual HRESULT SetSize(
          ULARGE_INTEGER libNewSize) = 0;

    virtual HRESULT CopyTo(
          IStream *pstm,
          ULARGE_INTEGER cb,
          ULARGE_INTEGER *pcbRead,
          ULARGE_INTEGER *pcbWritten) = 0;

    virtual HRESULT Commit(
          DWORD grfCommitFlags) = 0;

    virtual HRESULT Revert( void) = 0;

    virtual HRESULT LockRegion(
          ULARGE_INTEGER libOffset,
          ULARGE_INTEGER cb,
          DWORD dwLockType) = 0;

    virtual HRESULT UnlockRegion(
          ULARGE_INTEGER libOffset,
          ULARGE_INTEGER cb,
          DWORD dwLockType) = 0;

    virtual HRESULT Stat(
          STATSTG *pstatstg,
          DWORD grfStatFlag) = 0;

    virtual HRESULT Clone(
          IStream **ppstm) = 0;

};
#line 161 "../../dotnet/runtime/src/coreclr/pal/inc/rt/objidl.h"
typedef OLECHAR **SNB;

struct IEnumSTATSTG;



struct IStorage : public IUnknown
{
public:
    virtual HRESULT CreateStream(
          const OLECHAR *pwcsName,
          DWORD grfMode,
          DWORD reserved1,
          DWORD reserved2,
          IStream **ppstm) = 0;

    virtual HRESULT OpenStream(
          const OLECHAR *pwcsName,
          void *reserved1,
          DWORD grfMode,
          DWORD reserved2,
          IStream **ppstm) = 0;

    virtual HRESULT CreateStorage(
          const OLECHAR *pwcsName,
          DWORD grfMode,
          DWORD reserved1,
          DWORD reserved2,
          IStorage **ppstg) = 0;

    virtual HRESULT OpenStorage(
          const OLECHAR *pwcsName,
          IStorage *pstgPriority,
          DWORD grfMode,
          SNB snbExclude,
          DWORD reserved,
          IStorage **ppstg) = 0;

    virtual HRESULT CopyTo(
          DWORD ciidExclude,
          const IID *rgiidExclude,
          SNB snbExclude,
          IStorage *pstgDest) = 0;

    virtual HRESULT MoveElementTo(
          const OLECHAR *pwcsName,
          IStorage *pstgDest,
          const OLECHAR *pwcsNewName,
          DWORD grfFlags) = 0;

    virtual HRESULT Commit(
          DWORD grfCommitFlags) = 0;

    virtual HRESULT Revert( void) = 0;

    virtual HRESULT EnumElements(
          DWORD reserved1,
          void *reserved2,
          DWORD reserved3,
          IEnumSTATSTG **ppenum) = 0;

    virtual HRESULT DestroyElement(
          const OLECHAR *pwcsName) = 0;

    virtual HRESULT RenameElement(
          const OLECHAR *pwcsOldName,
          const OLECHAR *pwcsNewName) = 0;

    virtual HRESULT SetElementTimes(
          const OLECHAR *pwcsName,
          const FILETIME *pctime,
          const FILETIME *patime,
          const FILETIME *pmtime) = 0;

    virtual HRESULT SetClass(
          const CLSID * clsid) = 0;

    virtual HRESULT SetStateBits(
          DWORD grfStateBits,
          DWORD grfMask) = 0;

    virtual HRESULT Stat(
          STATSTG *pstatstg,
          DWORD grfStatFlag) = 0;

};
#line 258 "../../dotnet/runtime/src/coreclr/pal/inc/rt/objidl.h"
 const IID IID_IMalloc;

struct IMalloc : public IUnknown
{
public:
    virtual void * Alloc(
          SIZE_T cb) = 0;

    virtual void * Realloc(
          void *pv,
          SIZE_T cb) = 0;

    virtual void Free(
          void *pv) = 0;

    virtual SIZE_T GetSize(
          void *pv) = 0;

    virtual int DidAlloc(
        void *pv) = 0;

    virtual void HeapMinimize( void) = 0;

};

typedef IMalloc *LPMALLOC;
#line 21 "../../dotnet/runtime/src/coreclr/pal/inc/rt/servprov.h"
 const IID IID_IServiceProvider;

struct IServiceProvider : public IUnknown
{
    virtual HRESULT QueryService(
          const GUID * guidService,
          const IID * riid,
          void **ppvObject) = 0;
};
#line 19 "../../dotnet/runtime/src/coreclr/pal/inc/rt/oaidl.h"
typedef struct tagEXCEPINFO {
    WORD wCode;
    WORD wReserved;
    BSTR bstrSource;
    BSTR bstrDescription;
    BSTR bstrHelpFile;
    DWORD dwHelpContext;
    PVOID pvReserved;
    HRESULT ( *pfnDeferredFillIn)(struct tagEXCEPINFO *);
    SCODE scode;
} EXCEPINFO, * LPEXCEPINFO;

typedef struct IErrorInfo IErrorInfo;
typedef IErrorInfo *LPERRORINFO;

 const IID IID_IErrorInfo;

    struct
    IErrorInfo : public IUnknown
    {
    public:
        virtual HRESULT GetGUID(
              GUID *pGUID) = 0;

        virtual HRESULT GetSource(
              BSTR *pBstrSource) = 0;

        virtual HRESULT GetDescription(
              BSTR *pBstrDescription) = 0;

        virtual HRESULT GetHelpFile(
              BSTR *pBstrHelpFile) = 0;

        virtual HRESULT GetHelpContext(
              DWORD *pdwHelpContext) = 0;

    };

typedef struct ICreateErrorInfo ICreateErrorInfo;

 const IID IID_ICreateErrorInfo;

typedef ICreateErrorInfo *LPCREATEERRORINFO;

    struct
    ICreateErrorInfo : public IUnknown
    {
    public:
        virtual HRESULT SetGUID(
              const GUID * rguid) = 0;

        virtual HRESULT SetSource(
              LPOLESTR szSource) = 0;

        virtual HRESULT SetDescription(
              LPOLESTR szDescription) = 0;

        virtual HRESULT SetHelpFile(
              LPOLESTR szHelpFile) = 0;

        virtual HRESULT SetHelpContext(
              DWORD dwHelpContext) = 0;

    };

 HRESULT
SetErrorInfo(ULONG dwReserved, IErrorInfo * perrinfo);

 HRESULT
GetErrorInfo(ULONG dwReserved, IErrorInfo * * pperrinfo);

 HRESULT
CreateErrorInfo(ICreateErrorInfo * * pperrinfo);


typedef struct ISupportErrorInfo ISupportErrorInfo;

typedef ISupportErrorInfo *LPSUPPORTERRORINFO;

 const IID IID_ISupportErrorInfo;


    struct
    ISupportErrorInfo : public IUnknown
    {
    public:
        virtual HRESULT InterfaceSupportsErrorInfo(
              const IID * riid) = 0;

    };
#line 27
constexpr IID LIBID_ComPlusRuntime = {0xbed7f4ea,0x1a96,0x11d2,{0x8f,0x8,0x0,0xa0,0xc9,0xa6,0x18,0x6d}};


constexpr IID GUID_ExportedFromComPlus = {0x90883f05,0x3d28,0x11d2,{0x8f,0x17,0x0,0xa0,0xc9,0xa6,0x18,0x6d}};


constexpr IID GUID_ManagedName = {0xf21f359,0xab84,0x41e8,{0x9a,0x78,0x36,0xd1,0x10,0xe6,0xd2,0xf9}};


constexpr IID GUID_Function2Getter = {0x54fc8f55,0x38de,0x4703,{0x9c,0x4e,0x25,0x3,0x51,0x30,0x2b,0x1c}};
#line 41
constexpr IID CLSID_CorMetaDataDispenserRuntime = {0x1ec2de53,0x75cc,0x11d2,{0x97,0x75,0x0,0xa0,0xc9,0xb4,0xd5,0xc}};


constexpr IID GUID_DispIdOverride = {0xcd2bc5c9,0xf452,0x4326,{0xb7,0x14,0xf9,0xc5,0x39,0xd4,0xda,0x58}};


constexpr IID GUID_ForceIEnumerable = {0xb64784eb,0xd8d4,0x4d9b,{0x9a,0xcd,0x0e,0x30,0x80,0x64,0x26,0xf7}};


constexpr IID GUID_PropGetCA = {0x2941ff83,0x88d8,0x4f73,{0xb6,0xa9,0xbd,0xf8,0x71,0x2d,0x00,0x0d}};


constexpr IID GUID_PropPutCA = {0x29533527,0x3683,0x4364,{0xab,0xc0,0xdb,0x1a,0xdd,0x82,0x2f,0xa2}};



constexpr IID CLSID_CLR_v1_MetaData = {0x005023ca,0x72b1,0x11d3,{0x9f,0xc4,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};


constexpr IID CLSID_CLR_v2_MetaData = {0xefea471a,0x44fd,0x4862,{0x92,0x92,0xc,0x58,0xd4,0x6e,0x1f,0x3a}};
#line 69
constexpr IID MetaDataCheckDuplicatesFor = {0x30fe7be8,0xd7d9,0x11d2,{0x9f,0x80,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};


constexpr IID MetaDataRefToDefCheck = {0xde3856f8,0xd7d9,0x11d2,{0x9f,0x80,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};


constexpr IID MetaDataNotificationForTokenMovement = {0xe5d71a4c,0xd7da,0x11d2,{0x9f,0x80,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};


constexpr IID MetaDataSetUpdate = {0x2eee315c,0xd7db,0x11d2,{0x9f,0x80,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};
#line 85
constexpr IID MetaDataImportOption = {0x79700f36,0x4aac,0x11d3,{0x84,0xc3,0x0,0x90,0x27,0x86,0x8c,0xb1}};
#line 90
constexpr IID MetaDataThreadSafetyOptions = {0xf7559806,0xf266,0x42ea,{0x8c,0x63,0xa,0xdb,0x45,0xe8,0xb2,0x34}};



constexpr IID MetaDataErrorIfEmitOutOfOrder = {0x1547872d,0xdc03,0x11d2,{0x94,0x20,0x0,0x0,0xf8,0x8,0x34,0x60}};
#line 99
constexpr IID MetaDataGenerateTCEAdapters = {0xdcc9de90,0x4151,0x11d3,{0x88,0xd6,0x0,0x90,0x27,0x54,0xc4,0x3a}};



constexpr IID MetaDataTypeLibImportNamespace = {0xf17ff889,0x5a63,0x11d3,{0x9f,0xf2,0x0,0xc0,0x4f,0xf7,0x43,0x1a}};



constexpr IID MetaDataLinkerOptions = {0x47e099b6,0xae7c,0x4797,{0x83,0x17,0xb4,0x8a,0xa6,0x45,0xb8,0xf9}};



constexpr IID MetaDataRuntimeVersion = {0x47e099b7,0xae7c,0x4797,{0x83,0x17,0xb4,0x8a,0xa6,0x45,0xb8,0xf9}};



constexpr IID MetaDataMergerOptions = {0x132d3a6e,0xb35d,0x464e,{0x95,0x1a,0x42,0xef,0xb9,0xfb,0x66,0x1}};



constexpr IID MetaDataPreserveLocalRefs = {0xa55c0354,0xe91b,0x468b,{0x86,0x48,0x7c,0xc3,0x10,0x35,0xd5,0x33}};

struct IMetaDataImport;
struct IMetaDataAssemblyEmit;
struct IMetaDataAssemblyImport;
struct IMetaDataEmit;

typedef void const *UVCP_CONSTANT;
#line 24 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef void*  mdScope;
typedef uint32_t mdToken;
#line 31 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef mdToken mdModule;
typedef mdToken mdTypeRef;
typedef mdToken mdTypeDef;
typedef mdToken mdFieldDef;
typedef mdToken mdMethodDef;
typedef mdToken mdParamDef;
typedef mdToken mdInterfaceImpl;

typedef mdToken mdMemberRef;
typedef mdToken mdCustomAttribute;
typedef mdToken mdPermission;

typedef mdToken mdSignature;
typedef mdToken mdEvent;
typedef mdToken mdProperty;

typedef mdToken mdModuleRef;


typedef mdToken mdAssembly;
typedef mdToken mdAssemblyRef;
typedef mdToken mdFile;
typedef mdToken mdExportedType;
typedef mdToken mdManifestResource;

typedef mdToken mdTypeSpec;

typedef mdToken mdGenericParam;
typedef mdToken mdMethodSpec;
typedef mdToken mdGenericParamConstraint;


typedef mdToken mdString;

typedef mdToken mdCPToken;


typedef uint32_t RID;




typedef enum ReplacesGeneralNumericDefines
{


    IMAGE_DIRECTORY_ENTRY_COMHEADER     =14,

} ReplacesGeneralNumericDefines;
#line 126 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum ReplacesCorHdrNumericDefines
{

    COMIMAGE_FLAGS_ILONLY               =0x00000001,
    COMIMAGE_FLAGS_32BITREQUIRED        =0x00000002,
    COMIMAGE_FLAGS_IL_LIBRARY           =0x00000004,
    COMIMAGE_FLAGS_STRONGNAMESIGNED     =0x00000008,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT    =0x00000010,
    COMIMAGE_FLAGS_TRACKDEBUGDATA       =0x00010000,
    COMIMAGE_FLAGS_32BITPREFERRED       =0x00020000,



    COR_VERSION_MAJOR_V2                =2,
    COR_VERSION_MAJOR                   =COR_VERSION_MAJOR_V2,
    COR_VERSION_MINOR                   =5,
    COR_DELETED_NAME_LENGTH             =8,
    COR_VTABLEGAP_NAME_LENGTH           =8,


    NATIVE_TYPE_MAX_CB                  =1,
    COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE=0xFF,


    COR_VTABLE_32BIT                    =0x01,
    COR_VTABLE_64BIT                    =0x02,
    COR_VTABLE_FROM_UNMANAGED           =0x04,
    COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN=0x08,
    COR_VTABLE_CALL_MOST_DERIVED        =0x10,


    IMAGE_COR_EATJ_THUNK_SIZE           = 32,



    MAX_CLASS_NAME                      =1024,
    MAX_PACKAGE_NAME                    =1024,
} ReplacesCorHdrNumericDefines;
#line 209 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef struct IMAGE_COR20_HEADER
{

    uint32_t                cb;
    uint16_t                MajorRuntimeVersion;
    uint16_t                MinorRuntimeVersion;


    IMAGE_DATA_DIRECTORY    MetaData;
    uint32_t                Flags;
#line 224 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
    union {
        uint32_t            EntryPointToken;
        uint32_t            EntryPointRVA;
    };
#line 233 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
    IMAGE_DATA_DIRECTORY    Resources;


    IMAGE_DATA_DIRECTORY    StrongNameSignature;

    IMAGE_DATA_DIRECTORY    CodeManagerTable;

    IMAGE_DATA_DIRECTORY    VTableFixups;
    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;



    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;

} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;
#line 281 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorTypeAttr
{

    tdVisibilityMask        =   0x00000007,
    tdNotPublic             =   0x00000000,
    tdPublic                =   0x00000001,
    tdNestedPublic          =   0x00000002,
    tdNestedPrivate         =   0x00000003,
    tdNestedFamily          =   0x00000004,
    tdNestedAssembly        =   0x00000005,
    tdNestedFamANDAssem     =   0x00000006,
    tdNestedFamORAssem      =   0x00000007,


    tdLayoutMask            =   0x00000018,
    tdAutoLayout            =   0x00000000,
    tdSequentialLayout      =   0x00000008,
    tdExplicitLayout        =   0x00000010,



    tdClassSemanticsMask    =   0x00000020,
    tdClass                 =   0x00000000,
    tdInterface             =   0x00000020,



    tdAbstract              =   0x00000080,
    tdSealed                =   0x00000100,
    tdSpecialName           =   0x00000400,


    tdImport                =   0x00001000,
    tdSerializable          =   0x00002000,
    tdWindowsRuntime        =   0x00004000,


    tdStringFormatMask      =   0x00030000,
    tdAnsiClass             =   0x00000000,
    tdUnicodeClass          =   0x00010000,
    tdAutoClass             =   0x00020000,
    tdCustomFormatClass     =   0x00030000,
    tdCustomFormatMask      =   0x00C00000,



    tdBeforeFieldInit       =   0x00100000,
    tdForwarder             =   0x00200000,


    tdReservedMask          =   0x00040800,
    tdRTSpecialName         =   0x00000800,
    tdHasSecurity           =   0x00040000,
} CorTypeAttr;
#line 374 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorMethodAttr
{

    mdMemberAccessMask          =   0x0007,
    mdPrivateScope              =   0x0000,
    mdPrivate                   =   0x0001,
    mdFamANDAssem               =   0x0002,
    mdAssem                     =   0x0003,
    mdFamily                    =   0x0004,
    mdFamORAssem                =   0x0005,
    mdPublic                    =   0x0006,



    mdStatic                    =   0x0010,
    mdFinal                     =   0x0020,
    mdVirtual                   =   0x0040,
    mdHideBySig                 =   0x0080,


    mdVtableLayoutMask          =   0x0100,
    mdReuseSlot                 =   0x0000,
    mdNewSlot                   =   0x0100,



    mdCheckAccessOnOverride     =   0x0200,
    mdAbstract                  =   0x0400,
    mdSpecialName               =   0x0800,


    mdPinvokeImpl               =   0x2000,
    mdUnmanagedExport           =   0x0008,


    mdReservedMask              =   0xd000,
    mdRTSpecialName             =   0x1000,
    mdHasSecurity               =   0x4000,
    mdRequireSecObject          =   0x8000,

} CorMethodAttr;
#line 449 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorFieldAttr
{

    fdFieldAccessMask           =   0x0007,
    fdPrivateScope              =   0x0000,
    fdPrivate                   =   0x0001,
    fdFamANDAssem               =   0x0002,
    fdAssembly                  =   0x0003,
    fdFamily                    =   0x0004,
    fdFamORAssem                =   0x0005,
    fdPublic                    =   0x0006,



    fdStatic                    =   0x0010,
    fdInitOnly                  =   0x0020,
    fdLiteral                   =   0x0040,
    fdNotSerialized             =   0x0080,

    fdSpecialName               =   0x0200,


    fdPinvokeImpl               =   0x2000,


    fdReservedMask              =   0x9500,
    fdRTSpecialName             =   0x0400,
    fdHasFieldMarshal           =   0x1000,
    fdHasDefault                =   0x8000,
    fdHasFieldRVA               =   0x0100,
} CorFieldAttr;
#line 504 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorParamAttr
{
    pdIn                        =   0x0001,
    pdOut                       =   0x0002,
    pdOptional                  =   0x0010,


    pdReservedMask              =   0xf000,
    pdHasDefault                =   0x1000,
    pdHasFieldMarshal           =   0x2000,

    pdUnused                    =   0xcfe0,
} CorParamAttr;
#line 528 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorPropertyAttr
{
    prSpecialName           =   0x0200,


    prReservedMask          =   0xf400,
    prRTSpecialName         =   0x0400,
    prHasDefault            =   0x1000,

    prUnused                =   0xe9ff,
} CorPropertyAttr;
#line 547 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorEventAttr
{
    evSpecialName           =   0x0200,


    evReservedMask          =   0x0400,
    evRTSpecialName         =   0x0400,
} CorEventAttr;
#line 563 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorMethodSemanticsAttr
{
    msSetter    =   0x0001,
    msGetter    =   0x0002,
    msOther     =   0x0004,
    msAddOn     =   0x0008,
    msRemoveOn  =   0x0010,
    msFire      =   0x0020,
} CorMethodSemanticsAttr;
#line 583 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorDeclSecurity
{
    dclActionMask               =   0x001f,
    dclActionNil                =   0x0000,
    dclRequest                  =   0x0001,
    dclDemand                   =   0x0002,
    dclAssert                   =   0x0003,
    dclDeny                     =   0x0004,
    dclPermitOnly               =   0x0005,
    dclLinktimeCheck            =   0x0006,
    dclInheritanceCheck         =   0x0007,
    dclRequestMinimum           =   0x0008,
    dclRequestOptional          =   0x0009,
    dclRequestRefuse            =   0x000a,
    dclPrejitGrant              =   0x000b,
    dclPrejitDenied             =   0x000c,
    dclNonCasDemand             =   0x000d,
    dclNonCasLinkDemand         =   0x000e,
    dclNonCasInheritance        =   0x000f,
    dclMaximumValue             =   0x000f,
} CorDeclSecurity;
#line 623 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorMethodImpl
{

    miCodeTypeMask       =   0x0003,
    miIL                 =   0x0000,
    miNative             =   0x0001,
    miOPTIL              =   0x0002,
    miRuntime            =   0x0003,



    miManagedMask        =   0x0004,
    miUnmanaged          =   0x0004,
    miManaged            =   0x0000,



    miForwardRef         =   0x0010,
    miPreserveSig        =   0x0080,

    miInternalCall       =   0x1000,

    miSynchronized       =   0x0020,
    miNoInlining         =   0x0008,
    miAggressiveInlining =   0x0100,
    miNoOptimization     =   0x0040,
    miAggressiveOptimization = 0x0200,
#line 654 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
    miUserMask           =   miManagedMask | miForwardRef | miPreserveSig |
                             miInternalCall | miSynchronized |
                             miNoInlining | miAggressiveInlining |
                             miNoOptimization | miAggressiveOptimization,

    miMaxMethodImplVal   =   0xffff,
} CorMethodImpl;
#line 683 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum  CorPinvokeMap
{
    pmNoMangle          = 0x0001,


    pmCharSetMask       = 0x0006,
    pmCharSetNotSpec    = 0x0000,
    pmCharSetAnsi       = 0x0002,
    pmCharSetUnicode    = 0x0004,
    pmCharSetAuto       = 0x0006,


    pmBestFitUseAssem   = 0x0000,
    pmBestFitEnabled    = 0x0010,
    pmBestFitDisabled   = 0x0020,
    pmBestFitMask       = 0x0030,

    pmThrowOnUnmappableCharUseAssem   = 0x0000,
    pmThrowOnUnmappableCharEnabled    = 0x1000,
    pmThrowOnUnmappableCharDisabled   = 0x2000,
    pmThrowOnUnmappableCharMask       = 0x3000,

    pmSupportsLastError = 0x0040,


    pmCallConvMask      = 0x0700,
    pmCallConvWinapi    = 0x0100,
    pmCallConvCdecl     = 0x0200,
    pmCallConvStdcall   = 0x0300,
    pmCallConvThiscall  = 0x0400,
    pmCallConvFastcall  = 0x0500,

    pmMaxValue          = 0xFFFF,
} CorPinvokeMap;
#line 743 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorAssemblyFlags
{
    afPublicKey             =   0x0001,

    afPA_None               =   0x0000,
    afPA_MSIL               =   0x0010,
    afPA_x86                =   0x0020,
    afPA_IA64               =   0x0030,
    afPA_AMD64              =   0x0040,
    afPA_ARM                =   0x0050,
    afPA_ARM64              =   0x0060,
    afPA_NoPlatform         =   0x0070,
    afPA_Specified          =   0x0080,
    afPA_Mask               =   0x0070,
    afPA_FullMask           =   0x00F0,
    afPA_Shift              =   0x0004,

    afEnableJITcompileTracking   =  0x8000,
    afDisableJITcompileOptimizer =  0x4000,
    afDebuggableAttributeMask    =  0xc000,

    afRetargetable          =   0x0100,


    afContentType_Default         = 0x0000,
    afContentType_WindowsRuntime  = 0x0200,
    afContentType_Mask            = 0x0E00,
} CorAssemblyFlags;
#line 799 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorManifestResourceFlags
{
    mrVisibilityMask        =   0x0007,
    mrPublic                =   0x0001,
    mrPrivate               =   0x0002,
} CorManifestResourceFlags;
#line 812 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorFileFlags
{
    ffContainsMetaData      =   0x0000,
    ffContainsNoMetaData    =   0x0001,
} CorFileFlags;






typedef enum CorPEKind
{
    peNot       = 0x00000000,
    peILonly    = 0x00000001,
    pe32BitRequired=0x00000002,
    pe32Plus    = 0x00000004,
    pe32Unmanaged=0x00000008,
    pe32BitPreferred=0x00000010
} CorPEKind;



typedef enum CorGenericParamAttr
{


    gpVarianceMask          =   0x0003,
    gpNonVariant            =   0x0000,
    gpCovariant             =   0x0001,
    gpContravariant         =   0x0002,


    gpSpecialConstraintMask =  0x003C,
    gpNoSpecialConstraint   =   0x0000,
    gpReferenceTypeConstraint = 0x0004,
    gpNotNullableValueTypeConstraint   =   0x0008,
    gpDefaultConstructorConstraint = 0x0010,
    gpAcceptByRefLike = 0x0020,
} CorGenericParamAttr;


typedef uint8_t COR_SIGNATURE;

typedef COR_SIGNATURE* PCOR_SIGNATURE;

typedef const COR_SIGNATURE* PCCOR_SIGNATURE;


typedef const char * MDUTF8CSTR;
typedef char * MDUTF8STR;
#line 870 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorElementType
{
    ELEMENT_TYPE_END            = 0x00,
    ELEMENT_TYPE_VOID           = 0x01,
    ELEMENT_TYPE_BOOLEAN        = 0x02,
    ELEMENT_TYPE_CHAR           = 0x03,
    ELEMENT_TYPE_I1             = 0x04,
    ELEMENT_TYPE_U1             = 0x05,
    ELEMENT_TYPE_I2             = 0x06,
    ELEMENT_TYPE_U2             = 0x07,
    ELEMENT_TYPE_I4             = 0x08,
    ELEMENT_TYPE_U4             = 0x09,
    ELEMENT_TYPE_I8             = 0x0a,
    ELEMENT_TYPE_U8             = 0x0b,
    ELEMENT_TYPE_R4             = 0x0c,
    ELEMENT_TYPE_R8             = 0x0d,
    ELEMENT_TYPE_STRING         = 0x0e,


    ELEMENT_TYPE_PTR            = 0x0f,
    ELEMENT_TYPE_BYREF          = 0x10,


    ELEMENT_TYPE_VALUETYPE      = 0x11,
    ELEMENT_TYPE_CLASS          = 0x12,
    ELEMENT_TYPE_VAR            = 0x13,
    ELEMENT_TYPE_ARRAY          = 0x14,
    ELEMENT_TYPE_GENERICINST    = 0x15,
    ELEMENT_TYPE_TYPEDBYREF     = 0x16,

    ELEMENT_TYPE_I              = 0x18,
    ELEMENT_TYPE_U              = 0x19,
    ELEMENT_TYPE_FNPTR          = 0x1b,
    ELEMENT_TYPE_OBJECT         = 0x1c,
    ELEMENT_TYPE_SZARRAY        = 0x1d,

    ELEMENT_TYPE_MVAR           = 0x1e,


    ELEMENT_TYPE_CMOD_REQD      = 0x1f,
    ELEMENT_TYPE_CMOD_OPT       = 0x20,


    ELEMENT_TYPE_INTERNAL       = 0x21,


    ELEMENT_TYPE_MAX            = 0x22,


    ELEMENT_TYPE_MODIFIER       = 0x40,
    ELEMENT_TYPE_SENTINEL       = 0x01 | ELEMENT_TYPE_MODIFIER,
    ELEMENT_TYPE_PINNED         = 0x05 | ELEMENT_TYPE_MODIFIER,

} CorElementType;
#line 932 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorSerializationType
{
    SERIALIZATION_TYPE_UNDEFINED    = 0,
    SERIALIZATION_TYPE_BOOLEAN      = ELEMENT_TYPE_BOOLEAN,
    SERIALIZATION_TYPE_CHAR         = ELEMENT_TYPE_CHAR,
    SERIALIZATION_TYPE_I1           = ELEMENT_TYPE_I1,
    SERIALIZATION_TYPE_U1           = ELEMENT_TYPE_U1,
    SERIALIZATION_TYPE_I2           = ELEMENT_TYPE_I2,
    SERIALIZATION_TYPE_U2           = ELEMENT_TYPE_U2,
    SERIALIZATION_TYPE_I4           = ELEMENT_TYPE_I4,
    SERIALIZATION_TYPE_U4           = ELEMENT_TYPE_U4,
    SERIALIZATION_TYPE_I8           = ELEMENT_TYPE_I8,
    SERIALIZATION_TYPE_U8           = ELEMENT_TYPE_U8,
    SERIALIZATION_TYPE_R4           = ELEMENT_TYPE_R4,
    SERIALIZATION_TYPE_R8           = ELEMENT_TYPE_R8,
    SERIALIZATION_TYPE_STRING       = ELEMENT_TYPE_STRING,
    SERIALIZATION_TYPE_SZARRAY      = ELEMENT_TYPE_SZARRAY,
    SERIALIZATION_TYPE_TYPE         = 0x50,
    SERIALIZATION_TYPE_TAGGED_OBJECT= 0x51,
    SERIALIZATION_TYPE_FIELD        = 0x53,
    SERIALIZATION_TYPE_PROPERTY     = 0x54,
    SERIALIZATION_TYPE_ENUM         = 0x55
} CorSerializationType;
#line 960 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorUnmanagedCallingConvention
{
    IMAGE_CEE_UNMANAGED_CALLCONV_C         = 0x1,
    IMAGE_CEE_UNMANAGED_CALLCONV_STDCALL   = 0x2,
    IMAGE_CEE_UNMANAGED_CALLCONV_THISCALL  = 0x3,
    IMAGE_CEE_UNMANAGED_CALLCONV_FASTCALL  = 0x4,
} CorUnmanagedCallingConvention;

typedef enum CorCallingConvention
{
    IMAGE_CEE_CS_CALLCONV_DEFAULT       = 0x0,
    IMAGE_CEE_CS_CALLCONV_C         = IMAGE_CEE_UNMANAGED_CALLCONV_C,
    IMAGE_CEE_CS_CALLCONV_STDCALL   = IMAGE_CEE_UNMANAGED_CALLCONV_STDCALL,
    IMAGE_CEE_CS_CALLCONV_THISCALL  = IMAGE_CEE_UNMANAGED_CALLCONV_THISCALL,
    IMAGE_CEE_CS_CALLCONV_FASTCALL  = IMAGE_CEE_UNMANAGED_CALLCONV_FASTCALL,
    IMAGE_CEE_CS_CALLCONV_VARARG        = 0x5,
    IMAGE_CEE_CS_CALLCONV_FIELD         = 0x6,
    IMAGE_CEE_CS_CALLCONV_LOCAL_SIG     = 0x7,
    IMAGE_CEE_CS_CALLCONV_PROPERTY      = 0x8,
    IMAGE_CEE_CS_CALLCONV_UNMANAGED     = 0x9,
    IMAGE_CEE_CS_CALLCONV_GENERICINST   = 0xa,
    IMAGE_CEE_CS_CALLCONV_NATIVEVARARG  = 0xb,
    IMAGE_CEE_CS_CALLCONV_MAX           = 0xc,



    IMAGE_CEE_CS_CALLCONV_MASK      = 0x0f,
    IMAGE_CEE_CS_CALLCONV_HASTHIS   = 0x20,
    IMAGE_CEE_CS_CALLCONV_EXPLICITTHIS = 0x40,
    IMAGE_CEE_CS_CALLCONV_GENERIC   = 0x10,

} CorCallingConvention;




typedef enum CorArgType
{
    IMAGE_CEE_CS_END        = 0x0,
    IMAGE_CEE_CS_VOID       = 0x1,
    IMAGE_CEE_CS_I4         = 0x2,
    IMAGE_CEE_CS_I8         = 0x3,
    IMAGE_CEE_CS_R4         = 0x4,
    IMAGE_CEE_CS_R8         = 0x5,
    IMAGE_CEE_CS_PTR        = 0x6,
    IMAGE_CEE_CS_OBJECT     = 0x7,
    IMAGE_CEE_CS_STRUCT4    = 0x8,
    IMAGE_CEE_CS_STRUCT32   = 0x9,
    IMAGE_CEE_CS_BYVALUE    = 0xA,
} CorArgType;
#line 1018 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorNativeType
{



    NATIVE_TYPE_END         = 0x0,
    NATIVE_TYPE_VOID        = 0x1,
    NATIVE_TYPE_BOOLEAN     = 0x2,
    NATIVE_TYPE_I1          = 0x3,
    NATIVE_TYPE_U1          = 0x4,
    NATIVE_TYPE_I2          = 0x5,
    NATIVE_TYPE_U2          = 0x6,
    NATIVE_TYPE_I4          = 0x7,
    NATIVE_TYPE_U4          = 0x8,
    NATIVE_TYPE_I8          = 0x9,
    NATIVE_TYPE_U8          = 0xa,
    NATIVE_TYPE_R4          = 0xb,
    NATIVE_TYPE_R8          = 0xc,
    NATIVE_TYPE_SYSCHAR     = 0xd,
    NATIVE_TYPE_VARIANT     = 0xe,
    NATIVE_TYPE_CURRENCY    = 0xf,
    NATIVE_TYPE_PTR         = 0x10,

    NATIVE_TYPE_DECIMAL     = 0x11,
    NATIVE_TYPE_DATE        = 0x12,
    NATIVE_TYPE_BSTR        = 0x13,
    NATIVE_TYPE_LPSTR       = 0x14,
    NATIVE_TYPE_LPWSTR      = 0x15,
    NATIVE_TYPE_LPTSTR      = 0x16,
    NATIVE_TYPE_FIXEDSYSSTRING  = 0x17,
    NATIVE_TYPE_OBJECTREF   = 0x18,
    NATIVE_TYPE_IUNKNOWN    = 0x19,
    NATIVE_TYPE_IDISPATCH   = 0x1a,
    NATIVE_TYPE_STRUCT      = 0x1b,
    NATIVE_TYPE_INTF        = 0x1c,
    NATIVE_TYPE_SAFEARRAY   = 0x1d,
    NATIVE_TYPE_FIXEDARRAY  = 0x1e,
    NATIVE_TYPE_INT         = 0x1f,
    NATIVE_TYPE_UINT        = 0x20,

    NATIVE_TYPE_NESTEDSTRUCT  = 0x21,

    NATIVE_TYPE_BYVALSTR    = 0x22,

    NATIVE_TYPE_ANSIBSTR    = 0x23,

    NATIVE_TYPE_TBSTR       = 0x24,


    NATIVE_TYPE_VARIANTBOOL = 0x25,

    NATIVE_TYPE_FUNC        = 0x26,

    NATIVE_TYPE_ASANY       = 0x28,

    NATIVE_TYPE_ARRAY       = 0x2a,
    NATIVE_TYPE_LPSTRUCT    = 0x2b,

    NATIVE_TYPE_CUSTOMMARSHALER = 0x2c,
#line 1082 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
    NATIVE_TYPE_ERROR       = 0x2d,


    NATIVE_TYPE_IINSPECTABLE = 0x2e,
    NATIVE_TYPE_HSTRING     = 0x2f,
    NATIVE_TYPE_LPUTF8STR   = 0x30,
    NATIVE_TYPE_MAX         = 0x50,
} CorNativeType;


enum
{
    DESCR_GROUP_METHODDEF = 0,
    DESCR_GROUP_METHODIMPL,
};
#line 1105 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorILMethodSect
{
    CorILMethod_Sect_Reserved    = 0,
    CorILMethod_Sect_EHTable     = 1,
    CorILMethod_Sect_OptILTable  = 2,

    CorILMethod_Sect_KindMask    = 0x3F,
    CorILMethod_Sect_FatFormat   = 0x40,
    CorILMethod_Sect_MoreSects   = 0x80,
} CorILMethodSect;




typedef struct IMAGE_COR_ILMETHOD_SECT_SMALL
{
    uint8_t Kind;
    uint8_t DataSize;

} IMAGE_COR_ILMETHOD_SECT_SMALL;





typedef struct IMAGE_COR_ILMETHOD_SECT_FAT
{
    unsigned Kind : 8;
    unsigned DataSize : 24;

} IMAGE_COR_ILMETHOD_SECT_FAT;
#line 1143 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorExceptionFlag
{
    COR_ILEXCEPTION_CLAUSE_NONE,
    COR_ILEXCEPTION_CLAUSE_OFFSETLEN = 0x0000,
    COR_ILEXCEPTION_CLAUSE_DEPRECATED = 0x0000,
    COR_ILEXCEPTION_CLAUSE_FILTER  = 0x0001,
    COR_ILEXCEPTION_CLAUSE_FINALLY = 0x0002,
    COR_ILEXCEPTION_CLAUSE_FAULT = 0x0004,
    COR_ILEXCEPTION_CLAUSE_DUPLICATED = 0x0008,
} CorExceptionFlag;


typedef struct IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT
{
    CorExceptionFlag    Flags;
    uint32_t            TryOffset;
    uint32_t            TryLength;
    uint32_t            HandlerOffset;
    uint32_t            HandlerLength;
    union {
        uint32_t        ClassToken;
        uint32_t        FilterOffset;
    };
} IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT;

typedef struct IMAGE_COR_ILMETHOD_SECT_EH_FAT
{
    IMAGE_COR_ILMETHOD_SECT_FAT   SectFat;
    IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_FAT Clauses[1];
} IMAGE_COR_ILMETHOD_SECT_EH_FAT;


typedef struct IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL
{



    CorExceptionFlag    Flags         : 16;

    unsigned            TryOffset     : 16;
    unsigned            TryLength     : 8;
    unsigned            HandlerOffset : 16;
    unsigned            HandlerLength : 8;
    union {
        uint32_t        ClassToken;
        uint32_t        FilterOffset;
    };
} IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL;


typedef struct IMAGE_COR_ILMETHOD_SECT_EH_SMALL
{
    IMAGE_COR_ILMETHOD_SECT_SMALL SectSmall;
    uint16_t Reserved;
    IMAGE_COR_ILMETHOD_SECT_EH_CLAUSE_SMALL Clauses[1];
} IMAGE_COR_ILMETHOD_SECT_EH_SMALL;



typedef union IMAGE_COR_ILMETHOD_SECT_EH
{
    IMAGE_COR_ILMETHOD_SECT_EH_SMALL Small;
    IMAGE_COR_ILMETHOD_SECT_EH_FAT Fat;
} IMAGE_COR_ILMETHOD_SECT_EH;
#line 1215 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorILMethodFlags
{
    CorILMethod_InitLocals      = 0x0010,
    CorILMethod_MoreSects       = 0x0008,

    CorILMethod_CompressedIL    = 0x0040,


    CorILMethod_FormatShift     = 3,
    CorILMethod_FormatMask      = ((1 << CorILMethod_FormatShift) - 1),
    CorILMethod_TinyFormat      = 0x0002,
    CorILMethod_SmallFormat     = 0x0000,
    CorILMethod_FatFormat       = 0x0003,
    CorILMethod_TinyFormat1     = 0x0006,
} CorILMethodFlags;



typedef struct IMAGE_COR_ILMETHOD_TINY
{
    uint8_t Flags_CodeSize;
} IMAGE_COR_ILMETHOD_TINY;




typedef struct IMAGE_COR_ILMETHOD_FAT
{
    unsigned Flags    : 12;
    unsigned Size     :  4;
    unsigned MaxStack : 16;
    uint32_t CodeSize;
    mdSignature   LocalVarSigTok;

} IMAGE_COR_ILMETHOD_FAT;
#line 1255 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef union IMAGE_COR_ILMETHOD
{
    IMAGE_COR_ILMETHOD_TINY       Tiny;
    IMAGE_COR_ILMETHOD_FAT        Fat;
} IMAGE_COR_ILMETHOD;
#line 1270 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef struct IMAGE_COR_VTABLEFIXUP
{
    uint32_t       RVA;
    uint16_t       Count;
    uint16_t       Type;
} IMAGE_COR_VTABLEFIXUP;
#line 1296 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorCheckDuplicatesFor
{
    MDDupAll                    = 0xffffffff,
    MDDupENC                    = MDDupAll,
    MDNoDupChecks               = 0x00000000,
    MDDupTypeDef                = 0x00000001,
    MDDupInterfaceImpl          = 0x00000002,
    MDDupMethodDef              = 0x00000004,
    MDDupTypeRef                = 0x00000008,
    MDDupMemberRef              = 0x00000010,
    MDDupCustomAttribute        = 0x00000020,
    MDDupParamDef               = 0x00000040,
    MDDupPermission             = 0x00000080,
    MDDupProperty               = 0x00000100,
    MDDupEvent                  = 0x00000200,
    MDDupFieldDef               = 0x00000400,
    MDDupSignature              = 0x00000800,
    MDDupModuleRef              = 0x00001000,
    MDDupTypeSpec               = 0x00002000,
    MDDupImplMap                = 0x00004000,
    MDDupAssemblyRef            = 0x00008000,
    MDDupFile                   = 0x00010000,
    MDDupExportedType           = 0x00020000,
    MDDupManifestResource       = 0x00040000,
    MDDupGenericParam           = 0x00080000,
    MDDupMethodSpec             = 0x00100000,
    MDDupGenericParamConstraint = 0x00200000,

    MDDupAssembly               = 0x10000000,


    MDDupDefault = MDNoDupChecks | MDDupTypeRef | MDDupMemberRef | MDDupSignature | MDDupTypeSpec | MDDupMethodSpec,
} CorCheckDuplicatesFor;


typedef enum CorRefToDefCheck
{

    MDRefToDefDefault           = 0x00000003,
    MDRefToDefAll               = 0xffffffff,
    MDRefToDefNone              = 0x00000000,
    MDTypeRefToDef              = 0x00000001,
    MDMemberRefToDef            = 0x00000002
} CorRefToDefCheck;



typedef enum CorNotificationForTokenMovement
{

    MDNotifyDefault             = 0x0000000f,
    MDNotifyAll                 = 0xffffffff,
    MDNotifyNone                = 0x00000000,
    MDNotifyMethodDef           = 0x00000001,
    MDNotifyMemberRef           = 0x00000002,
    MDNotifyFieldDef            = 0x00000004,
    MDNotifyTypeRef             = 0x00000008,

    MDNotifyTypeDef             = 0x00000010,
    MDNotifyParamDef            = 0x00000020,
    MDNotifyInterfaceImpl       = 0x00000040,
    MDNotifyProperty            = 0x00000080,
    MDNotifyEvent               = 0x00000100,
    MDNotifySignature           = 0x00000200,
    MDNotifyTypeSpec            = 0x00000400,
    MDNotifyCustomAttribute     = 0x00000800,
    MDNotifySecurityValue       = 0x00001000,
    MDNotifyPermission          = 0x00002000,
    MDNotifyModuleRef           = 0x00004000,

    MDNotifyNameSpace           = 0x00008000,

    MDNotifyAssemblyRef         = 0x01000000,
    MDNotifyFile                = 0x02000000,
    MDNotifyExportedType        = 0x04000000,
    MDNotifyResource            = 0x08000000,
} CorNotificationForTokenMovement;


typedef enum CorSetENC
{
    MDSetENCOn                  = 0x00000001,
    MDSetENCOff                 = 0x00000002,

    MDUpdateENC                 = 0x00000001,
    MDUpdateFull                = 0x00000002,
    MDUpdateExtension           = 0x00000003,
    MDUpdateIncremental         = 0x00000004,
    MDUpdateDelta               = 0x00000005,
    MDUpdateMask                = 0x00000007,


} CorSetENC;




typedef enum CorErrorIfEmitOutOfOrder
{
    MDErrorOutOfOrderDefault    = 0x00000000,
    MDErrorOutOfOrderNone       = 0x00000000,
    MDErrorOutOfOrderAll        = 0xffffffff,
    MDMethodOutOfOrder          = 0x00000001,
    MDFieldOutOfOrder           = 0x00000002,
    MDParamOutOfOrder           = 0x00000004,
    MDPropertyOutOfOrder        = 0x00000008,
    MDEventOutOfOrder           = 0x00000010,
} CorErrorIfEmitOutOfOrder;



typedef enum CorImportOptions
{
    MDImportOptionDefault       = 0x00000000,
    MDImportOptionAll           = 0xFFFFFFFF,
    MDImportOptionAllTypeDefs   = 0x00000001,
    MDImportOptionAllMethodDefs = 0x00000002,
    MDImportOptionAllFieldDefs  = 0x00000004,
    MDImportOptionAllProperties = 0x00000008,
    MDImportOptionAllEvents     = 0x00000010,
    MDImportOptionAllCustomAttributes = 0x00000020,
    MDImportOptionAllExportedTypes  = 0x00000040,

} CorImportOptions;



typedef enum CorThreadSafetyOptions
{


    MDThreadSafetyDefault       = 0x00000000,
    MDThreadSafetyOff           = 0x00000000,
    MDThreadSafetyOn            = 0x00000001,
} CorThreadSafetyOptions;



typedef enum CorLinkerOptions
{

    MDAssembly          = 0x00000000,
    MDNetModule         = 0x00000001,
} CorLinkerOptions;


typedef enum MergeFlags
{
    MergeFlagsNone      =   0,
    MergeManifest       =   0x00000001,
    DropMemberRefCAs    =   0x00000002,
    NoDupCheck          =   0x00000004,
    MergeExportedTypes  =   0x00000008
} MergeFlags;


typedef enum CorLocalRefPreservation
{
    MDPreserveLocalRefsNone     = 0x00000000,
    MDPreserveLocalTypeRef      = 0x00000001,
    MDPreserveLocalMemberRef    = 0x00000002
} CorLocalRefPreservation;
#line 1467 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef struct COR_FIELD_OFFSET
{
    mdFieldDef  ridOfField;
    uint32_t       ulOffset;
} COR_FIELD_OFFSET;
#line 1479 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorTokenType
{
    mdtModule               = 0x00000000,
    mdtTypeRef              = 0x01000000,
    mdtTypeDef              = 0x02000000,
    mdtFieldDef             = 0x04000000,
    mdtMethodDef            = 0x06000000,
    mdtParamDef             = 0x08000000,
    mdtInterfaceImpl        = 0x09000000,
    mdtMemberRef            = 0x0a000000,
    mdtCustomAttribute      = 0x0c000000,
    mdtPermission           = 0x0e000000,
    mdtSignature            = 0x11000000,
    mdtEvent                = 0x14000000,
    mdtProperty             = 0x17000000,
    mdtMethodImpl           = 0x19000000,
    mdtModuleRef            = 0x1a000000,
    mdtTypeSpec             = 0x1b000000,
    mdtAssembly             = 0x20000000,
    mdtAssemblyRef          = 0x23000000,
    mdtFile                 = 0x26000000,
    mdtExportedType         = 0x27000000,
    mdtManifestResource     = 0x28000000,
    mdtNestedClass          = 0x29000000,
    mdtGenericParam         = 0x2a000000,
    mdtMethodSpec           = 0x2b000000,
    mdtGenericParamConstraint = 0x2c000000,

    mdtString               = 0x70000000,
    mdtName                 = 0x71000000,
    mdtBaseType             = 0x72000000,
} CorTokenType;
#line 1555 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorOpenFlags
{
    ofRead              =   0x00000000,
    ofWrite             =   0x00000001,
    ofReadWriteMask     =   0x00000001,

    ofCopyMemory        =   0x00000002,

    ofReadOnly          =   0x00000010,
    ofTakeOwnership     =   0x00000020,
#line 1569 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
    ofNoTypeLib         =   0x00000080,
    ofNoTransform       =   0x00001000,


    ofReserved1         =   0x00000100,
    ofReserved2         =   0x00000200,
    ofReserved3         =   0x00000400,
    ofReserved          =   0xffffef40

} CorOpenFlags;
#line 1593 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorFileMapping
{
    fmFlat            = 0,

    fmExecutableImage = 1,

} CorFileMapping;


typedef CorTypeAttr CorRegTypeAttr;
#line 1607 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef void *HCORENUM;



typedef enum CorAttributeTargets
{
    catAssembly      = 0x0001,
    catModule        = 0x0002,
    catClass         = 0x0004,
    catStruct        = 0x0008,
    catEnum          = 0x0010,
    catConstructor   = 0x0020,
    catMethod        = 0x0040,
    catProperty      = 0x0080,
    catField         = 0x0100,
    catEvent         = 0x0200,
    catInterface     = 0x0400,
    catParameter     = 0x0800,
    catDelegate      = 0x1000,
    catGenericParameter = 0x4000,

    catAll           = catAssembly | catModule | catClass | catStruct | catEnum | catConstructor |
                    catMethod | catProperty | catField | catEvent | catInterface | catParameter | catDelegate | catGenericParameter,
    catClassMembers  = catClass | catStruct | catEnum | catConstructor | catMethod | catProperty | catField | catEvent | catDelegate | catInterface,

} CorAttributeTargets;
#line 1694 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum NGenHintEnum
{
    NGenDefault             = 0x0000,

    NGenEager               = 0x0001,
    NGenLazy                = 0x0002,
    NGenNever               = 0x0003
} NGenHintEnum;

typedef enum LoadHintEnum
{
    LoadDefault             = 0x0000,

    LoadAlways              = 0x0001,
    LoadSometimes           = 0x0002,
    LoadNever               = 0x0003
} LoadHintEnum;
#line 1728 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorSaveSize
{
    cssAccurate             = 0x0000,
    cssQuick                = 0x0001,
    cssDiscardTransientCAs  = 0x0002,
} CorSaveSize;
#line 1744 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum NativeTypeArrayFlags
{
    ntaSizeParamIndexSpecified = 0x0001,
    ntaReserved                = 0xfffe
} NativeTypeArrayFlags;
#line 1753 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef enum CorInfoHFAElemType : unsigned {
    CORINFO_HFA_ELEM_NONE,
    CORINFO_HFA_ELEM_FLOAT,
    CORINFO_HFA_ELEM_DOUBLE,
    CORINFO_HFA_ELEM_VECTOR64,
    CORINFO_HFA_ELEM_VECTOR128,
} CorInfoHFAElemType;
#line 1764 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef void  *  PSECURITY_PROPS ;
typedef void  *  PSECURITY_VALUE ;
typedef void ** PPSECURITY_PROPS ;
typedef void ** PPSECURITY_VALUE ;
#line 1774 "../../dotnet/runtime/src/coreclr/inc/corhdr.h"
typedef struct COR_SECATTR {
    mdMemberRef     tkCtor;
    const void     *pCustomAttribute;
    uint32_t        cbCustomAttribute;
} COR_SECATTR;
#line 162
constexpr IID CLSID_Cor = {0xbee00010,0xee77,0x11d0,{0xa0,0x15,0x00,0xc0,0x4f,0xbb,0xb8,0x84}};
#line 167
constexpr IID CLSID_CorMetaDataDispenser = {0xe5cb7a31,0x7512,0x11d2,{0x89,0xce,0x0,0x80,0xc7,0x92,0xe5,0xd8}};
#line 173
constexpr IID CLSID_CorMetaDataDispenserReg = {0x435755ff,0x7397,0x11d2,{0x97,0x71,0x0,0xa0,0xc9,0xb4,0xd5,0xc}};




constexpr IID CLSID_CorMetaDataReg = {0x87f3a1f5,0x7397,0x11d2,{0x97,0x71,0x0,0xa0,0xc9,0xb4,0xd5,0xc}};


struct IMetaDataDispenser;
#line 187
constexpr IID IID_IMetaDataError = {0xb81ff171,0x20f3,0x11d2,{0x8d,0xcc,0x0,0xa0,0xc9,0xb0,0x9c,0x19}};




struct IMetaDataError : public IUnknown
{
    virtual HRESULT OnError(HRESULT hrError, mdToken token) = 0;
};
#line 201
constexpr IID IID_IMapToken = {0x6a3ea8b,0x225,0x11d1,{0xbf,0x72,0x0,0xc0,0x4f,0xc3,0x1e,0x12}};




struct IMapToken : public IUnknown
{
    virtual HRESULT Map(mdToken tkImp, mdToken tkEmit) = 0;
};
#line 215
constexpr IID IID_IMetaDataDispenser = {0x809c652e,0x7396,0x11d2,{0x97,0x71,0x00,0xa0,0xc9,0xb4,0xd5,0x0c}};




struct IMetaDataDispenser : public IUnknown
{
    virtual HRESULT DefineScope(
        const CLSID *    rclsid,
        DWORD       dwCreateFlags,
        const IID *      riid,
        IUnknown    **ppIUnk) = 0;

    virtual HRESULT OpenScope(
        LPCWSTR     szScope,
        DWORD       dwOpenFlags,
        const IID *      riid,
        IUnknown    **ppIUnk) = 0;

    virtual HRESULT OpenScopeOnMemory(
        LPCVOID     pData,
        ULONG       cbData,
        DWORD       dwOpenFlags,
        const IID *      riid,
        IUnknown    **ppIUnk) = 0;
};
#line 246
constexpr IID IID_IMetaDataEmit = {0xba3fee4c,0xecb9,0x4e41,{0x83,0xb7,0x18,0x3f,0xa4,0x1c,0xd8,0x59}};




struct IMetaDataEmit : public IUnknown
{
    virtual HRESULT SetModuleProps(
        LPCWSTR     szName) = 0;

    virtual HRESULT Save(
        LPCWSTR     szFile,
        DWORD       dwSaveFlags) = 0;

    virtual HRESULT SaveToStream(
        IStream     *pIStream,
        DWORD       dwSaveFlags) = 0;

    virtual HRESULT GetSaveSize(
        CorSaveSize fSave,
        DWORD       *pdwSaveSize) = 0;

    virtual HRESULT DefineTypeDef(
        LPCWSTR     szTypeDef,
        DWORD       dwTypeDefFlags,
        mdToken     tkExtends,
        mdToken     rtkImplements[],
        mdTypeDef   *ptd) = 0;

    virtual HRESULT DefineNestedType(
        LPCWSTR     szTypeDef,
        DWORD       dwTypeDefFlags,
        mdToken     tkExtends,
        mdToken     rtkImplements[],
        mdTypeDef   tdEncloser,
        mdTypeDef   *ptd) = 0;

    virtual HRESULT SetHandler(
        IUnknown    *pUnk) = 0;

    virtual HRESULT DefineMethod(
        mdTypeDef   td,
        LPCWSTR     szName,
        DWORD       dwMethodFlags,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        ULONG       ulCodeRVA,
        DWORD       dwImplFlags,
        mdMethodDef *pmd) = 0;

    virtual HRESULT DefineMethodImpl(
        mdTypeDef   td,
        mdToken     tkBody,
        mdToken     tkDecl) = 0;

    virtual HRESULT DefineTypeRefByName(
        mdToken     tkResolutionScope,
        LPCWSTR     szName,
        mdTypeRef   *ptr) = 0;

    virtual HRESULT DefineImportType(
        IMetaDataAssemblyImport *pAssemImport,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        IMetaDataImport *pImport,
        mdTypeDef   tdImport,
        IMetaDataAssemblyEmit *pAssemEmit,
        mdTypeRef   *ptr) = 0;

    virtual HRESULT DefineMemberRef(
        mdToken     tkImport,
        LPCWSTR     szName,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        mdMemberRef *pmr) = 0;

    virtual HRESULT DefineImportMember(
        IMetaDataAssemblyImport *pAssemImport,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        IMetaDataImport *pImport,
        mdToken     mbMember,
        IMetaDataAssemblyEmit *pAssemEmit,
        mdToken     tkParent,
        mdMemberRef *pmr) = 0;

    virtual HRESULT DefineEvent (
        mdTypeDef   td,
        LPCWSTR     szEvent,
        DWORD       dwEventFlags,
        mdToken     tkEventType,
        mdMethodDef mdAddOn,
        mdMethodDef mdRemoveOn,
        mdMethodDef mdFire,
        mdMethodDef rmdOtherMethods[],
        mdEvent     *pmdEvent) = 0;

    virtual HRESULT SetClassLayout (
        mdTypeDef   td,
        DWORD       dwPackSize,
        COR_FIELD_OFFSET rFieldOffsets[],
        ULONG       ulClassSize) = 0;

    virtual HRESULT DeleteClassLayout (
        mdTypeDef   td) = 0;

    virtual HRESULT SetFieldMarshal (
        mdToken     tk,
        PCCOR_SIGNATURE pvNativeType,
        ULONG       cbNativeType) = 0;

    virtual HRESULT DeleteFieldMarshal (
        mdToken     tk) = 0;

    virtual HRESULT DefinePermissionSet (
        mdToken     tk,
        DWORD       dwAction,
        void const  *pvPermission,
        ULONG       cbPermission,
        mdPermission *ppm) = 0;

    virtual HRESULT SetRVA(
        mdMethodDef md,
        ULONG       ulRVA) = 0;

    virtual HRESULT GetTokenFromSig(
        PCCOR_SIGNATURE pvSig,
        ULONG       cbSig,
        mdSignature *pmsig) = 0;

    virtual HRESULT DefineModuleRef(
        LPCWSTR     szName,
        mdModuleRef *pmur) = 0;


    virtual HRESULT SetParent(
        mdMemberRef mr,
        mdToken     tk) = 0;

    virtual HRESULT GetTokenFromTypeSpec(
        PCCOR_SIGNATURE pvSig,
        ULONG       cbSig,
        mdTypeSpec *ptypespec) = 0;

    virtual HRESULT SaveToMemory(
        void        *pbData,
        ULONG       cbData) = 0;

    virtual HRESULT DefineUserString(
        LPCWSTR szString,
        ULONG       cchString,
        mdString    *pstk) = 0;

    virtual HRESULT DeleteToken(
        mdToken     tkObj) = 0;

    virtual HRESULT SetMethodProps(
        mdMethodDef md,
        DWORD       dwMethodFlags,
        ULONG       ulCodeRVA,
        DWORD       dwImplFlags) = 0;

    virtual HRESULT SetTypeDefProps(
        mdTypeDef   td,
        DWORD       dwTypeDefFlags,
        mdToken     tkExtends,
        mdToken     rtkImplements[]) = 0;

    virtual HRESULT SetEventProps(
        mdEvent     ev,
        DWORD       dwEventFlags,
        mdToken     tkEventType,
        mdMethodDef mdAddOn,
        mdMethodDef mdRemoveOn,
        mdMethodDef mdFire,
        mdMethodDef rmdOtherMethods[]) = 0;

    virtual HRESULT SetPermissionSetProps(
        mdToken     tk,
        DWORD       dwAction,
        void const  *pvPermission,
        ULONG       cbPermission,
        mdPermission *ppm) = 0;

    virtual HRESULT DefinePinvokeMap(
        mdToken     tk,
        DWORD       dwMappingFlags,
        LPCWSTR     szImportName,
        mdModuleRef mrImportDLL) = 0;

    virtual HRESULT SetPinvokeMap(
        mdToken     tk,
        DWORD       dwMappingFlags,
        LPCWSTR     szImportName,
        mdModuleRef mrImportDLL) = 0;

    virtual HRESULT DeletePinvokeMap(
        mdToken     tk) = 0;


    virtual HRESULT DefineCustomAttribute(
        mdToken     tkOwner,
        mdToken     tkCtor,
        void const  *pCustomAttribute,
        ULONG       cbCustomAttribute,
        mdCustomAttribute *pcv) = 0;

    virtual HRESULT SetCustomAttributeValue(
        mdCustomAttribute pcv,
        void const  *pCustomAttribute,
        ULONG       cbCustomAttribute) = 0;

    virtual HRESULT DefineField(
        mdTypeDef   td,
        LPCWSTR     szName,
        DWORD       dwFieldFlags,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        DWORD       dwCPlusTypeFlag,
        void const  *pValue,
        ULONG       cchValue,
        mdFieldDef  *pmd) = 0;

    virtual HRESULT DefineProperty(
        mdTypeDef   td,
        LPCWSTR     szProperty,
        DWORD       dwPropFlags,
        PCCOR_SIGNATURE pvSig,
        ULONG       cbSig,
        DWORD       dwCPlusTypeFlag,
        void const  *pValue,
        ULONG       cchValue,
        mdMethodDef mdSetter,
        mdMethodDef mdGetter,
        mdMethodDef rmdOtherMethods[],
        mdProperty  *pmdProp) = 0;

    virtual HRESULT DefineParam(
        mdMethodDef md,
        ULONG       ulParamSeq,
        LPCWSTR     szName,
        DWORD       dwParamFlags,
        DWORD       dwCPlusTypeFlag,
        void const  *pValue,
        ULONG       cchValue,
        mdParamDef  *ppd) = 0;

    virtual HRESULT SetFieldProps(
        mdFieldDef  fd,
        DWORD       dwFieldFlags,
        DWORD       dwCPlusTypeFlag,
        void const  *pValue,
        ULONG       cchValue) = 0;

    virtual HRESULT SetPropertyProps(
        mdProperty  pr,
        DWORD       dwPropFlags,
        DWORD       dwCPlusTypeFlag,
        void const  *pValue,
        ULONG       cchValue,
        mdMethodDef mdSetter,
        mdMethodDef mdGetter,
        mdMethodDef rmdOtherMethods[]) = 0;

    virtual HRESULT SetParamProps(
        mdParamDef  pd,
        LPCWSTR     szName,
        DWORD       dwParamFlags,
        DWORD       dwCPlusTypeFlag,
        void const  *pValue,
        ULONG       cchValue) = 0;


    virtual HRESULT DefineSecurityAttributeSet(
        mdToken     tkObj,
        COR_SECATTR rSecAttrs[],
        ULONG       cSecAttrs,
        ULONG       *pulErrorAttr) = 0;

    virtual HRESULT ApplyEditAndContinue(
        IUnknown    *pImport) = 0;

    virtual HRESULT TranslateSigWithScope(
        IMetaDataAssemblyImport *pAssemImport,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        IMetaDataImport *import,
        PCCOR_SIGNATURE pbSigBlob,
        ULONG       cbSigBlob,
        IMetaDataAssemblyEmit *pAssemEmit,
        IMetaDataEmit *emit,
        PCOR_SIGNATURE pvTranslatedSig,
        ULONG       cbTranslatedSigMax,
        ULONG       *pcbTranslatedSig) = 0;

    virtual HRESULT SetMethodImplFlags(
        mdMethodDef md,
        DWORD       dwImplFlags) = 0;

    virtual HRESULT SetFieldRVA(
        mdFieldDef  fd,
        ULONG       ulRVA) = 0;

    virtual HRESULT Merge(
        IMetaDataImport *pImport,
        IMapToken   *pHostMapToken,
        IUnknown    *pHandler) = 0;

    virtual HRESULT MergeEnd() = 0;



};
#line 564
constexpr IID IID_IMetaDataEmit2 = {0xf5dd9950,0xf693,0x42e6,{0x83,0xe,0x7b,0x83,0x3e,0x81,0x46,0xa9}};




struct IMetaDataEmit2 : public IMetaDataEmit
{
    virtual HRESULT DefineMethodSpec(
        mdToken     tkParent,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        mdMethodSpec *pmi) = 0;

    virtual HRESULT GetDeltaSaveSize(
        CorSaveSize fSave,
        DWORD       *pdwSaveSize) = 0;

    virtual HRESULT SaveDelta(
        LPCWSTR     szFile,
        DWORD       dwSaveFlags) = 0;

    virtual HRESULT SaveDeltaToStream(
        IStream     *pIStream,
        DWORD       dwSaveFlags) = 0;

    virtual HRESULT SaveDeltaToMemory(
        void        *pbData,
        ULONG       cbData) = 0;

    virtual HRESULT DefineGenericParam(
        mdToken      tk,
        ULONG        ulParamSeq,
        DWORD        dwParamFlags,
        LPCWSTR      szname,
        DWORD        reserved,
        mdToken      rtkConstraints[],
        mdGenericParam *pgp) = 0;

    virtual HRESULT SetGenericParamProps(
        mdGenericParam gp,
        DWORD        dwParamFlags,
        LPCWSTR      szName,
        DWORD        reserved,
        mdToken      rtkConstraints[]) = 0;

    virtual HRESULT ResetENCLog() = 0;

};
#line 617
constexpr IID IID_IMetaDataImport = {0x7dac8207,0xd3ae,0x4c75,{0x9b,0x67,0x92,0x80,0x1a,0x49,0x7d,0x44}};




struct IMetaDataImport : public IUnknown
{
    virtual void CloseEnum(HCORENUM hEnum) = 0;
    virtual HRESULT CountEnum(HCORENUM hEnum, ULONG *pulCount) = 0;
    virtual HRESULT ResetEnum(HCORENUM hEnum, ULONG ulPos) = 0;
    virtual HRESULT EnumTypeDefs(HCORENUM *phEnum, mdTypeDef rTypeDefs[],
                            ULONG cMax, ULONG *pcTypeDefs) = 0;
    virtual HRESULT EnumInterfaceImpls(HCORENUM *phEnum, mdTypeDef td,
                            mdInterfaceImpl rImpls[], ULONG cMax,
                            ULONG* pcImpls) = 0;
    virtual HRESULT EnumTypeRefs(HCORENUM *phEnum, mdTypeRef rTypeRefs[],
                            ULONG cMax, ULONG* pcTypeRefs) = 0;

    virtual HRESULT FindTypeDefByName(
        LPCWSTR     szTypeDef,
        mdToken     tkEnclosingClass,
        mdTypeDef   *ptd) = 0;

    virtual HRESULT GetScopeProps(

        LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName,
        GUID        *pmvid) = 0;

    virtual HRESULT GetModuleFromScope(
        mdModule    *pmd) = 0;

    virtual HRESULT GetTypeDefProps(
        mdTypeDef   td,

        LPWSTR      szTypeDef,
        ULONG       cchTypeDef,
        ULONG       *pchTypeDef,
        DWORD       *pdwTypeDefFlags,
        mdToken     *ptkExtends) = 0;

    virtual HRESULT GetInterfaceImplProps(
        mdInterfaceImpl iiImpl,
        mdTypeDef   *pClass,
        mdToken     *ptkIface) = 0;

    virtual HRESULT GetTypeRefProps(
        mdTypeRef   tr,
        mdToken     *ptkResolutionScope,

        LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName) = 0;

    virtual HRESULT ResolveTypeRef(mdTypeRef tr, const IID * riid, IUnknown **ppIScope, mdTypeDef *ptd) = 0;

    virtual HRESULT EnumMembers(
        HCORENUM    *phEnum,
        mdTypeDef   cl,
        mdToken     rMembers[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumMembersWithName(
        HCORENUM    *phEnum,
        mdTypeDef   cl,
        LPCWSTR     szName,
        mdToken     rMembers[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumMethods(
        HCORENUM    *phEnum,
        mdTypeDef   cl,
        mdMethodDef rMethods[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumMethodsWithName(
        HCORENUM    *phEnum,
        mdTypeDef   cl,
        LPCWSTR     szName,
        mdMethodDef rMethods[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumFields(
        HCORENUM    *phEnum,
        mdTypeDef   cl,
        mdFieldDef  rFields[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumFieldsWithName(
        HCORENUM    *phEnum,
        mdTypeDef   cl,
        LPCWSTR     szName,
        mdFieldDef  rFields[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;


    virtual HRESULT EnumParams(
        HCORENUM    *phEnum,
        mdMethodDef mb,
        mdParamDef  rParams[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumMemberRefs(
        HCORENUM    *phEnum,
        mdToken     tkParent,
        mdMemberRef rMemberRefs[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumMethodImpls(
        HCORENUM    *phEnum,
        mdTypeDef   td,
        mdToken     rMethodBody[],
        mdToken     rMethodDecl[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumPermissionSets(
        HCORENUM    *phEnum,
        mdToken     tk,
        DWORD       dwActions,
        mdPermission rPermission[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT FindMember(
        mdTypeDef   td,
        LPCWSTR     szName,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        mdToken     *pmb) = 0;

    virtual HRESULT FindMethod(
        mdTypeDef   td,
        LPCWSTR     szName,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        mdMethodDef *pmb) = 0;

    virtual HRESULT FindField(
        mdTypeDef   td,
        LPCWSTR     szName,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        mdFieldDef  *pmb) = 0;

    virtual HRESULT FindMemberRef(
        mdTypeRef   td,
        LPCWSTR     szName,
        PCCOR_SIGNATURE pvSigBlob,
        ULONG       cbSigBlob,
        mdMemberRef *pmr) = 0;

    virtual HRESULT GetMethodProps(
        mdMethodDef mb,
        mdTypeDef   *pClass,

        LPWSTR      szMethod,
        ULONG       cchMethod,
        ULONG       *pchMethod,
        DWORD       *pdwAttr,
        PCCOR_SIGNATURE *ppvSigBlob,
        ULONG       *pcbSigBlob,
        ULONG       *pulCodeRVA,
        DWORD       *pdwImplFlags) = 0;

    virtual HRESULT GetMemberRefProps(
        mdMemberRef mr,
        mdToken     *ptk,

        LPWSTR      szMember,
        ULONG       cchMember,
        ULONG       *pchMember,
        PCCOR_SIGNATURE *ppvSigBlob,
        ULONG       *pbSig) = 0;

    virtual HRESULT EnumProperties(
        HCORENUM    *phEnum,
        mdTypeDef   td,
        mdProperty  rProperties[],
        ULONG       cMax,
        ULONG       *pcProperties) = 0;

    virtual HRESULT EnumEvents(
        HCORENUM    *phEnum,
        mdTypeDef   td,
        mdEvent     rEvents[],
        ULONG       cMax,
        ULONG       *pcEvents) = 0;

    virtual HRESULT GetEventProps(
        mdEvent     ev,
        mdTypeDef   *pClass,
        LPCWSTR     szEvent,
        ULONG       cchEvent,
        ULONG       *pchEvent,
        DWORD       *pdwEventFlags,
        mdToken     *ptkEventType,
        mdMethodDef *pmdAddOn,
        mdMethodDef *pmdRemoveOn,
        mdMethodDef *pmdFire,
        mdMethodDef rmdOtherMethod[],
        ULONG       cMax,
        ULONG       *pcOtherMethod) = 0;

    virtual HRESULT EnumMethodSemantics(
        HCORENUM    *phEnum,
        mdMethodDef mb,
        mdToken     rEventProp[],
        ULONG       cMax,
        ULONG       *pcEventProp) = 0;

    virtual HRESULT GetMethodSemantics(
        mdMethodDef mb,
        mdToken     tkEventProp,
        DWORD       *pdwSemanticsFlags) = 0;

    virtual HRESULT GetClassLayout (
        mdTypeDef   td,
        DWORD       *pdwPackSize,
        COR_FIELD_OFFSET rFieldOffset[],
        ULONG       cMax,
        ULONG       *pcFieldOffset,
        ULONG       *pulClassSize) = 0;

    virtual HRESULT GetFieldMarshal (
        mdToken     tk,
        PCCOR_SIGNATURE *ppvNativeType,
        ULONG       *pcbNativeType) = 0;

    virtual HRESULT GetRVA(
        mdToken     tk,
        ULONG       *pulCodeRVA,
        DWORD       *pdwImplFlags) = 0;

    virtual HRESULT GetPermissionSetProps (
        mdPermission pm,
        DWORD       *pdwAction,
        void const  **ppvPermission,
        ULONG       *pcbPermission) = 0;

    virtual HRESULT GetSigFromToken(
        mdSignature mdSig,
        PCCOR_SIGNATURE *ppvSig,
        ULONG       *pcbSig) = 0;

    virtual HRESULT GetModuleRefProps(
        mdModuleRef mur,

        LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName) = 0;

    virtual HRESULT EnumModuleRefs(
        HCORENUM    *phEnum,
        mdModuleRef rModuleRefs[],
        ULONG       cmax,
        ULONG       *pcModuleRefs) = 0;

    virtual HRESULT GetTypeSpecFromToken(
        mdTypeSpec typespec,
        PCCOR_SIGNATURE *ppvSig,
        ULONG       *pcbSig) = 0;

    virtual HRESULT GetNameFromToken(
        mdToken     tk,
        MDUTF8CSTR  *pszUtf8NamePtr) = 0;

    virtual HRESULT EnumUnresolvedMethods(
        HCORENUM    *phEnum,
        mdToken     rMethods[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT GetUserString(
        mdString    stk,

        LPWSTR      szString,
        ULONG       cchString,
        ULONG       *pchString) = 0;

    virtual HRESULT GetPinvokeMap(
        mdToken     tk,
        DWORD       *pdwMappingFlags,

        LPWSTR      szImportName,
        ULONG       cchImportName,
        ULONG       *pchImportName,
        mdModuleRef *pmrImportDLL) = 0;

    virtual HRESULT EnumSignatures(
        HCORENUM    *phEnum,
        mdSignature rSignatures[],
        ULONG       cmax,
        ULONG       *pcSignatures) = 0;

    virtual HRESULT EnumTypeSpecs(
        HCORENUM    *phEnum,
        mdTypeSpec  rTypeSpecs[],
        ULONG       cmax,
        ULONG       *pcTypeSpecs) = 0;

    virtual HRESULT EnumUserStrings(
        HCORENUM    *phEnum,
        mdString    rStrings[],
        ULONG       cmax,
        ULONG       *pcStrings) = 0;

    virtual HRESULT GetParamForMethodIndex(
        mdMethodDef md,
        ULONG       ulParamSeq,
        mdParamDef  *ppd) = 0;

    virtual HRESULT EnumCustomAttributes(
        HCORENUM    *phEnum,
        mdToken     tk,
        mdToken     tkType,
        mdCustomAttribute rCustomAttributes[],
        ULONG       cMax,
        ULONG       *pcCustomAttributes) = 0;

    virtual HRESULT GetCustomAttributeProps(
        mdCustomAttribute cv,
        mdToken     *ptkObj,
        mdToken     *ptkType,
        void const  **ppBlob,
        ULONG       *pcbSize) = 0;

    virtual HRESULT FindTypeRef(
        mdToken     tkResolutionScope,
        LPCWSTR     szName,
        mdTypeRef   *ptr) = 0;

    virtual HRESULT GetMemberProps(
        mdToken     mb,
        mdTypeDef   *pClass,

        LPWSTR      szMember,
        ULONG       cchMember,
        ULONG       *pchMember,
        DWORD       *pdwAttr,
        PCCOR_SIGNATURE *ppvSigBlob,
        ULONG       *pcbSigBlob,
        ULONG       *pulCodeRVA,
        DWORD       *pdwImplFlags,
        DWORD       *pdwCPlusTypeFlag,
        UVCP_CONSTANT *ppValue,
        ULONG       *pcchValue) = 0;

    virtual HRESULT GetFieldProps(
        mdFieldDef  mb,
        mdTypeDef   *pClass,

        LPWSTR      szField,
        ULONG       cchField,
        ULONG       *pchField,
        DWORD       *pdwAttr,
        PCCOR_SIGNATURE *ppvSigBlob,
        ULONG       *pcbSigBlob,
        DWORD       *pdwCPlusTypeFlag,
        UVCP_CONSTANT *ppValue,
        ULONG       *pcchValue) = 0;

    virtual HRESULT GetPropertyProps(
        mdProperty  prop,
        mdTypeDef   *pClass,
        LPCWSTR     szProperty,
        ULONG       cchProperty,
        ULONG       *pchProperty,
        DWORD       *pdwPropFlags,
        PCCOR_SIGNATURE *ppvSig,
        ULONG       *pbSig,
        DWORD       *pdwCPlusTypeFlag,
        UVCP_CONSTANT *ppDefaultValue,
        ULONG       *pcchDefaultValue,
        mdMethodDef *pmdSetter,
        mdMethodDef *pmdGetter,
        mdMethodDef rmdOtherMethod[],
        ULONG       cMax,
        ULONG       *pcOtherMethod) = 0;

    virtual HRESULT GetParamProps(
        mdParamDef  tk,
        mdMethodDef *pmd,
        ULONG       *pulSequence,

        LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName,
        DWORD       *pdwAttr,
        DWORD       *pdwCPlusTypeFlag,
        UVCP_CONSTANT *ppValue,
        ULONG       *pcchValue) = 0;

    virtual HRESULT GetCustomAttributeByName(
        mdToken     tkObj,
        LPCWSTR     szName,
        const void  **ppData,
        ULONG       *pcbData) = 0;

    virtual BOOL IsValidToken(
        mdToken     tk) = 0;

    virtual HRESULT GetNestedClassProps(
        mdTypeDef   tdNestedClass,
        mdTypeDef   *ptdEnclosingClass) = 0;

    virtual HRESULT GetNativeCallConvFromSig(
        void const  *pvSig,
        ULONG       cbSig,
        ULONG       *pCallConv) = 0;

    virtual HRESULT IsGlobal(
        mdToken     pd,
        int         *pbGlobal) = 0;



};
#line 1049
constexpr IID IID_IMetaDataImport2 = {0xfce5efa0,0x8bba,0x4f8e,{0xa0,0x36,0x8f,0x20,0x22,0xb0,0x84,0x66}};




struct IMetaDataImport2 : public IMetaDataImport
{
    virtual HRESULT EnumGenericParams(
        HCORENUM    *phEnum,
        mdToken      tk,
        mdGenericParam rGenericParams[],
        ULONG       cMax,
        ULONG       *pcGenericParams) = 0;

    virtual HRESULT GetGenericParamProps(
        mdGenericParam gp,
        ULONG        *pulParamSeq,
        DWORD        *pdwParamFlags,
        mdToken      *ptOwner,
        DWORD       *reserved,

        LPWSTR       wzname,
        ULONG        cchName,
        ULONG        *pchName) = 0;

    virtual HRESULT GetMethodSpecProps(
        mdMethodSpec mi,
        mdToken *tkParent,
        PCCOR_SIGNATURE *ppvSigBlob,
        ULONG       *pcbSigBlob) = 0;

    virtual HRESULT EnumGenericParamConstraints(
        HCORENUM    *phEnum,
        mdGenericParam tk,
        mdGenericParamConstraint rGenericParamConstraints[],
        ULONG       cMax,
        ULONG       *pcGenericParamConstraints) = 0;

    virtual HRESULT GetGenericParamConstraintProps(
        mdGenericParamConstraint gpc,
        mdGenericParam *ptGenericParam,
        mdToken      *ptkConstraintType) = 0;

    virtual HRESULT GetPEKind(
        DWORD* pdwPEKind,
        DWORD* pdwMAchine) = 0;

    virtual HRESULT GetVersionString(

        LPWSTR      pwzBuf,
        DWORD       ccBufSize,
        DWORD       *pccBufSize) = 0;

    virtual HRESULT EnumMethodSpecs(
        HCORENUM    *phEnum,
        mdToken      tk,
        mdMethodSpec rMethodSpecs[],
        ULONG       cMax,
        ULONG       *pcMethodSpecs) = 0;

};
#line 1115
constexpr IID IID_IMetaDataFilter = {0xd0e80dd1,0x12d4,0x11d3,{0xb3,0x9d,0x0,0xc0,0x4f,0xf8,0x17,0x95}};




struct IMetaDataFilter : public IUnknown
{
    virtual HRESULT UnmarkAll() = 0;
    virtual HRESULT MarkToken(mdToken tk) = 0;
    virtual HRESULT IsTokenMarked(mdToken tk, BOOL *pIsMarked) = 0;
};
#line 1132
constexpr IID IID_IHostFilter = {0xd0e80dd3,0x12d4,0x11d3,{0xb3,0x9d,0x0,0xc0,0x4f,0xf8,0x17,0x95}};




struct IHostFilter : public IUnknown
{
    virtual HRESULT MarkToken(mdToken tk) = 0;
};
#line 1147
typedef struct
{
    DWORD       dwOSPlatformId;
    DWORD       dwOSMajorVersion;
    DWORD       dwOSMinorVersion;
} OSINFO;


typedef struct
{
    USHORT      usMajorVersion;
    USHORT      usMinorVersion;
    USHORT      usBuildNumber;
    USHORT      usRevisionNumber;
    LPWSTR      szLocale;
    ULONG       cbLocale;
    DWORD       *rProcessor;
    ULONG       ulProcessor;
    OSINFO      *rOS;
    ULONG       ulOS;
} ASSEMBLYMETADATA;



constexpr IID IID_IMetaDataAssemblyEmit = {0x211ef15b,0x5317,0x4438,{0xb1,0x96,0xde,0xc8,0x7b,0x88,0x76,0x93}};




struct IMetaDataAssemblyEmit : public IUnknown
{
    virtual HRESULT DefineAssembly(
        const void  *pbPublicKey,
        ULONG       cbPublicKey,
        ULONG       ulHashAlgId,
        LPCWSTR     szName,
        const ASSEMBLYMETADATA *pMetaData,
        DWORD       dwAssemblyFlags,
        mdAssembly  *pma) = 0;

    virtual HRESULT DefineAssemblyRef(
        const void  *pbPublicKeyOrToken,
        ULONG       cbPublicKeyOrToken,
        LPCWSTR     szName,
        const ASSEMBLYMETADATA *pMetaData,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        DWORD       dwAssemblyRefFlags,
        mdAssemblyRef *pmdar) = 0;

    virtual HRESULT DefineFile(
        LPCWSTR     szName,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        DWORD       dwFileFlags,
        mdFile      *pmdf) = 0;

    virtual HRESULT DefineExportedType(
        LPCWSTR     szName,
        mdToken     tkImplementation,
        mdTypeDef   tkTypeDef,
        DWORD       dwExportedTypeFlags,
        mdExportedType   *pmdct) = 0;

    virtual HRESULT DefineManifestResource(
        LPCWSTR     szName,
        mdToken     tkImplementation,
        DWORD       dwOffset,
        DWORD       dwResourceFlags,
        mdManifestResource  *pmdmr) = 0;

    virtual HRESULT SetAssemblyProps(
        mdAssembly  pma,
        const void  *pbPublicKey,
        ULONG       cbPublicKey,
        ULONG       ulHashAlgId,
        LPCWSTR     szName,
        const ASSEMBLYMETADATA *pMetaData,
        DWORD       dwAssemblyFlags) = 0;

    virtual HRESULT SetAssemblyRefProps(
        mdAssemblyRef ar,
        const void  *pbPublicKeyOrToken,
        ULONG       cbPublicKeyOrToken,
        LPCWSTR     szName,
        const ASSEMBLYMETADATA *pMetaData,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        DWORD       dwAssemblyRefFlags) = 0;

    virtual HRESULT SetFileProps(
        mdFile      file,
        const void  *pbHashValue,
        ULONG       cbHashValue,
        DWORD       dwFileFlags) = 0;

    virtual HRESULT SetExportedTypeProps(
        mdExportedType   ct,
        mdToken     tkImplementation,
        mdTypeDef   tkTypeDef,
        DWORD       dwExportedTypeFlags) = 0;

    virtual HRESULT SetManifestResourceProps(
        mdManifestResource  mr,
        mdToken     tkImplementation,
        DWORD       dwOffset,
        DWORD       dwResourceFlags) = 0;

};



constexpr IID IID_IMetaDataAssemblyImport = {0xee62470b,0xe94b,0x424e,{0x9b,0x7c,0x2f,0x0,0xc9,0x24,0x9f,0x93}};




struct IMetaDataAssemblyImport : public IUnknown
{
    virtual HRESULT GetAssemblyProps(
        mdAssembly  mda,
        const void  **ppbPublicKey,
        ULONG       *pcbPublicKey,
        ULONG       *pulHashAlgId,
         LPWSTR  szName,
        ULONG       cchName,
        ULONG       *pchName,
        ASSEMBLYMETADATA *pMetaData,
        DWORD       *pdwAssemblyFlags) = 0;

    virtual HRESULT GetAssemblyRefProps(
        mdAssemblyRef mdar,
        const void  **ppbPublicKeyOrToken,
        ULONG       *pcbPublicKeyOrToken,
         LPWSTR szName,
        ULONG       cchName,
        ULONG       *pchName,
        ASSEMBLYMETADATA *pMetaData,
        const void  **ppbHashValue,
        ULONG       *pcbHashValue,
        DWORD       *pdwAssemblyRefFlags) = 0;

    virtual HRESULT GetFileProps(
        mdFile      mdf,
         LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName,
        const void  **ppbHashValue,
        ULONG       *pcbHashValue,
        DWORD       *pdwFileFlags) = 0;

    virtual HRESULT GetExportedTypeProps(
        mdExportedType   mdct,
         LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName,
        mdToken     *ptkImplementation,
        mdTypeDef   *ptkTypeDef,
        DWORD       *pdwExportedTypeFlags) = 0;

    virtual HRESULT GetManifestResourceProps(
        mdManifestResource  mdmr,
         LPWSTR      szName,
        ULONG       cchName,
        ULONG       *pchName,
        mdToken     *ptkImplementation,
        DWORD       *pdwOffset,
        DWORD       *pdwResourceFlags) = 0;

    virtual HRESULT EnumAssemblyRefs(
        HCORENUM    *phEnum,
        mdAssemblyRef rAssemblyRefs[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumFiles(
        HCORENUM    *phEnum,
        mdFile      rFiles[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumExportedTypes(
        HCORENUM    *phEnum,
        mdExportedType   rExportedTypes[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT EnumManifestResources(
        HCORENUM    *phEnum,
        mdManifestResource  rManifestResources[],
        ULONG       cMax,
        ULONG       *pcTokens) = 0;

    virtual HRESULT GetAssemblyFromScope(
        mdAssembly  *ptkAssembly) = 0;

    virtual HRESULT FindExportedTypeByName(
        LPCWSTR     szName,
        mdToken     mdtExportedType,
        mdExportedType   *ptkExportedType) = 0;

    virtual HRESULT FindManifestResourceByName(
        LPCWSTR     szName,
        mdManifestResource *ptkManifestResource) = 0;

    virtual void CloseEnum(
        HCORENUM hEnum) = 0;

    virtual HRESULT FindAssembliesByName(
        LPCWSTR  szAppBase,
        LPCWSTR  szPrivateBin,
        LPCWSTR  szAssemblyName,
        IUnknown *ppIUnk[],
        ULONG    cMax,
        ULONG    *pcAssemblies) = 0;
};
#line 1374
typedef enum
{
    ValidatorModuleTypeInvalid      = 0x0,
    ValidatorModuleTypeMin          = 0x00000001,
    ValidatorModuleTypePE           = 0x00000001,
    ValidatorModuleTypeObj          = 0x00000002,
    ValidatorModuleTypeEnc          = 0x00000003,
    ValidatorModuleTypeIncr         = 0x00000004,
    ValidatorModuleTypeMax          = 0x00000004,
} CorValidatorModuleType;



constexpr IID IID_IMetaDataValidate = {0x4709c9c6,0x81ff,0x11d3,{0x9f,0xc7,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};




struct IMetaDataValidate : public IUnknown
{
    virtual HRESULT ValidatorInit(
        DWORD       dwModuleType,
        IUnknown    *pUnk) = 0;

    virtual HRESULT ValidateMetaData(
        ) = 0;
};
#line 1411
constexpr IID IID_IMetaDataDispenserEx = {0x31bcfce2,0xdafb,0x11d2,{0x9f,0x81,0x0,0xc0,0x4f,0x79,0xa0,0xa3}};



struct IMetaDataDispenserEx : public IMetaDataDispenser
{
    virtual HRESULT SetOption(
        const GUID *     optionid,
        const VARIANT *value) = 0;

    virtual HRESULT GetOption(
        const GUID *     optionid,
        VARIANT *pvalue) = 0;

    virtual HRESULT OpenScopeOnITypeInfo(
        ITypeInfo   *pITI,
        DWORD       dwOpenFlags,
        const IID *      riid,
        IUnknown    **ppIUnk) = 0;

    virtual HRESULT GetCORSystemDirectory(

         LPWSTR      szBuffer,
         DWORD       cchBuffer,
         DWORD*      pchBuffer) = 0;

    virtual HRESULT FindAssembly(
        LPCWSTR  szAppBase,
        LPCWSTR  szPrivateBin,
        LPCWSTR  szGlobalBin,
        LPCWSTR  szAssemblyName,
        LPCWSTR  szName,
        ULONG    cchName,
        ULONG    *pcName) = 0;

    virtual HRESULT FindAssemblyModule(
        LPCWSTR  szAppBase,
        LPCWSTR  szPrivateBin,
        LPCWSTR  szGlobalBin,
        LPCWSTR  szAssemblyName,
        LPCWSTR  szModuleName,

        LPWSTR   szName,
        ULONG    cchName,
        ULONG    *pcName) = 0;

};
#line 1466
constexpr IID IID_IMetaDataTables = {0xd8f579ab,0x402d,0x4b8e,{0x82,0xd9,0x5d,0x63,0xb1,0x6,0x5c,0x68}};

struct IMetaDataTables : public IUnknown
{
    virtual HRESULT GetStringHeapSize (
        ULONG   *pcbStrings) = 0;

    virtual HRESULT GetBlobHeapSize (
        ULONG   *pcbBlobs) = 0;

    virtual HRESULT GetGuidHeapSize (
        ULONG   *pcbGuids) = 0;

    virtual HRESULT GetUserStringHeapSize (
        ULONG   *pcbBlobs) = 0;

    virtual HRESULT GetNumTables (
        ULONG   *pcTables) = 0;

    virtual HRESULT GetTableIndex (
        ULONG   token,
        ULONG   *pixTbl) = 0;

    virtual HRESULT GetTableInfo (
        ULONG   ixTbl,
        ULONG   *pcbRow,
        ULONG   *pcRows,
        ULONG   *pcCols,
        ULONG   *piKey,
        const char **ppName) = 0;

    virtual HRESULT GetColumnInfo (
        ULONG   ixTbl,
        ULONG   ixCol,
        ULONG   *poCol,
        ULONG   *pcbCol,
        ULONG   *pType,
        const char **ppName) = 0;

    virtual HRESULT GetCodedTokenInfo (
        ULONG   ixCdTkn,
        ULONG   *pcTokens,
        ULONG   **ppTokens,
        const char **ppName) = 0;

    virtual HRESULT GetRow (
        ULONG   ixTbl,
        ULONG   rid,
        void    **ppRow) = 0;

    virtual HRESULT GetColumn (
        ULONG   ixTbl,
        ULONG   ixCol,
        ULONG   rid,
        ULONG   *pVal) = 0;

    virtual HRESULT GetString (
        ULONG   ixString,
        const char **ppString) = 0;

    virtual HRESULT GetBlob (
        ULONG   ixBlob,
        ULONG   *pcbData,
        const void **ppData) = 0;

    virtual HRESULT GetGuid (
        ULONG   ixGuid,
        const GUID **ppGUID) = 0;

    virtual HRESULT GetUserString (
        ULONG   ixUserString,
        ULONG   *pcbData,
        const void **ppData) = 0;

    virtual HRESULT GetNextString (
        ULONG   ixString,
        ULONG   *pNext) = 0;

    virtual HRESULT GetNextBlob (
        ULONG   ixBlob,
        ULONG   *pNext) = 0;

    virtual HRESULT GetNextGuid (
        ULONG   ixGuid,
        ULONG   *pNext) = 0;

    virtual HRESULT GetNextUserString (
        ULONG   ixUserString,
        ULONG   *pNext) = 0;



};



constexpr IID IID_IMetaDataTables2 = {0xbadb5f70,0x58da,0x43a9,{0xa1,0xc6,0xd7,0x48,0x19,0xf1,0x9b,0x15}};

struct IMetaDataTables2 : public IMetaDataTables
{
    virtual HRESULT GetMetaDataStorage (
        const void **ppvMd,
        ULONG   *pcbMd) = 0;

    virtual HRESULT GetMetaDataStreamInfo (
        ULONG   ix,
        const char **ppchName,
        const void **ppv,
        ULONG   *pcb) = 0;

};
#line 1609
constexpr IID IID_IMetaDataInfo = {0x7998EA64,0x7F95,0x48B8,{0x86,0xFC,0x17,0xCA,0xF4,0x8B,0xF5,0xCB}};




struct IMetaDataInfo : public IUnknown
{
#line 1621
   virtual HRESULT GetFileMapping(
        const void ** ppvData,
        ULONGLONG *   pcbData,
        DWORD *       pdwMappingType) = 0;
};
#line 35 "../../dotnet/runtime/src/coreclr/pal/inc/rt/pshpack1.h"
#pragma pack(1)
#line 1638
typedef struct
{
    BYTE        m_linkType;
    BYTE        m_flags;
    mdMemberRef m_entryPoint;
} COR_NATIVE_LINK;
#line 36 "../../dotnet/runtime/src/coreclr/pal/inc/rt/poppack.h"
#pragma pack()
#line 1646
typedef enum
{
    nltNone         = 1,
    nltAnsi         = 2,
    nltUnicode      = 3,
    nltAuto         = 4,
    nltMaxValue     = 7,
} CorNativeLinkType;

typedef enum
{
    nlfNone         = 0x00,
    nlfLastError    = 0x01,
    nlfNoMangle     = 0x02,
    nlfMaxValue     = 0x03,
} CorNativeLinkFlags;
