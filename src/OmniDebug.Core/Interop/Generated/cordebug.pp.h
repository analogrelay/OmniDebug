#line 18
#pragma warning( disable: 4049 )
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
#line 49
typedef struct ICorDebugDataTarget ICorDebugDataTarget;






typedef struct ICorDebugStaticFieldSymbol ICorDebugStaticFieldSymbol;






typedef struct ICorDebugInstanceFieldSymbol ICorDebugInstanceFieldSymbol;






typedef struct ICorDebugVariableSymbol ICorDebugVariableSymbol;






typedef struct ICorDebugMemoryBuffer ICorDebugMemoryBuffer;






typedef struct ICorDebugMergedAssemblyRecord ICorDebugMergedAssemblyRecord;






typedef struct ICorDebugSymbolProvider ICorDebugSymbolProvider;






typedef struct ICorDebugSymbolProvider2 ICorDebugSymbolProvider2;






typedef struct ICorDebugVirtualUnwinder ICorDebugVirtualUnwinder;






typedef struct ICorDebugDataTarget2 ICorDebugDataTarget2;






typedef struct ICorDebugLoadedModule ICorDebugLoadedModule;






typedef struct ICorDebugDataTarget3 ICorDebugDataTarget3;






typedef struct ICorDebugDataTarget4 ICorDebugDataTarget4;






typedef struct ICorDebugMutableDataTarget ICorDebugMutableDataTarget;






typedef struct ICorDebugMetaDataLocator ICorDebugMetaDataLocator;






typedef struct ICorDebugManagedCallback ICorDebugManagedCallback;






typedef struct ICorDebugManagedCallback3 ICorDebugManagedCallback3;






typedef struct ICorDebugManagedCallback4 ICorDebugManagedCallback4;






typedef struct ICorDebugManagedCallback2 ICorDebugManagedCallback2;






typedef struct ICorDebugUnmanagedCallback ICorDebugUnmanagedCallback;






typedef struct ICorDebug ICorDebug;






typedef struct ICorDebugRemoteTarget ICorDebugRemoteTarget;






typedef struct ICorDebugRemote ICorDebugRemote;






typedef struct ICorDebug2 ICorDebug2;






typedef struct ICorDebugController ICorDebugController;






typedef struct ICorDebugAppDomain ICorDebugAppDomain;






typedef struct ICorDebugAppDomain2 ICorDebugAppDomain2;






typedef struct ICorDebugEnum ICorDebugEnum;






typedef struct ICorDebugGuidToTypeEnum ICorDebugGuidToTypeEnum;






typedef struct ICorDebugAppDomain3 ICorDebugAppDomain3;






typedef struct ICorDebugAppDomain4 ICorDebugAppDomain4;






typedef struct ICorDebugAssembly ICorDebugAssembly;






typedef struct ICorDebugAssembly2 ICorDebugAssembly2;






typedef struct ICorDebugAssembly3 ICorDebugAssembly3;






typedef struct ICorDebugHeapEnum ICorDebugHeapEnum;






typedef struct ICorDebugHeapSegmentEnum ICorDebugHeapSegmentEnum;






typedef struct ICorDebugGCReferenceEnum ICorDebugGCReferenceEnum;






typedef struct ICorDebugProcess ICorDebugProcess;






typedef struct ICorDebugProcess2 ICorDebugProcess2;






typedef struct ICorDebugProcess3 ICorDebugProcess3;






typedef struct ICorDebugProcess5 ICorDebugProcess5;






typedef struct ICorDebugDebugEvent ICorDebugDebugEvent;






typedef struct ICorDebugProcess6 ICorDebugProcess6;






typedef struct ICorDebugProcess7 ICorDebugProcess7;






typedef struct ICorDebugProcess8 ICorDebugProcess8;






typedef struct ICorDebugProcess10 ICorDebugProcess10;






typedef struct ICorDebugMemoryRangeEnum ICorDebugMemoryRangeEnum;






typedef struct ICorDebugProcess11 ICorDebugProcess11;






typedef struct ICorDebugModuleDebugEvent ICorDebugModuleDebugEvent;






typedef struct ICorDebugExceptionDebugEvent ICorDebugExceptionDebugEvent;






typedef struct ICorDebugBreakpoint ICorDebugBreakpoint;






typedef struct ICorDebugFunctionBreakpoint ICorDebugFunctionBreakpoint;






typedef struct ICorDebugModuleBreakpoint ICorDebugModuleBreakpoint;






typedef struct ICorDebugValueBreakpoint ICorDebugValueBreakpoint;






typedef struct ICorDebugStepper ICorDebugStepper;






typedef struct ICorDebugStepper2 ICorDebugStepper2;






typedef struct ICorDebugRegisterSet ICorDebugRegisterSet;






typedef struct ICorDebugRegisterSet2 ICorDebugRegisterSet2;






typedef struct ICorDebugThread ICorDebugThread;






typedef struct ICorDebugThread2 ICorDebugThread2;






typedef struct ICorDebugThread3 ICorDebugThread3;






typedef struct ICorDebugThread4 ICorDebugThread4;






typedef struct ICorDebugThread5 ICorDebugThread5;






typedef struct ICorDebugStackWalk ICorDebugStackWalk;






typedef struct ICorDebugChain ICorDebugChain;






typedef struct ICorDebugFrame ICorDebugFrame;






typedef struct ICorDebugInternalFrame ICorDebugInternalFrame;






typedef struct ICorDebugInternalFrame2 ICorDebugInternalFrame2;






typedef struct ICorDebugILFrame ICorDebugILFrame;






typedef struct ICorDebugILFrame2 ICorDebugILFrame2;






typedef struct ICorDebugILFrame3 ICorDebugILFrame3;






typedef struct ICorDebugILFrame4 ICorDebugILFrame4;






typedef struct ICorDebugNativeFrame ICorDebugNativeFrame;






typedef struct ICorDebugNativeFrame2 ICorDebugNativeFrame2;






typedef struct ICorDebugModule3 ICorDebugModule3;






typedef struct ICorDebugModule4 ICorDebugModule4;






typedef struct ICorDebugRuntimeUnwindableFrame ICorDebugRuntimeUnwindableFrame;






typedef struct ICorDebugModule ICorDebugModule;






typedef struct ICorDebugModule2 ICorDebugModule2;






typedef struct ICorDebugFunction ICorDebugFunction;






typedef struct ICorDebugFunction2 ICorDebugFunction2;






typedef struct ICorDebugFunction3 ICorDebugFunction3;






typedef struct ICorDebugFunction4 ICorDebugFunction4;






typedef struct ICorDebugCode ICorDebugCode;






typedef struct ICorDebugCode2 ICorDebugCode2;






typedef struct ICorDebugCode3 ICorDebugCode3;






typedef struct ICorDebugCode4 ICorDebugCode4;






typedef struct ICorDebugILCode ICorDebugILCode;






typedef struct ICorDebugILCode2 ICorDebugILCode2;






typedef struct ICorDebugClass ICorDebugClass;






typedef struct ICorDebugClass2 ICorDebugClass2;






typedef struct ICorDebugEval ICorDebugEval;






typedef struct ICorDebugEval2 ICorDebugEval2;






typedef struct ICorDebugValue ICorDebugValue;






typedef struct ICorDebugValue2 ICorDebugValue2;






typedef struct ICorDebugValue3 ICorDebugValue3;






typedef struct ICorDebugGenericValue ICorDebugGenericValue;






typedef struct ICorDebugReferenceValue ICorDebugReferenceValue;






typedef struct ICorDebugHeapValue ICorDebugHeapValue;






typedef struct ICorDebugHeapValue2 ICorDebugHeapValue2;






typedef struct ICorDebugHeapValue3 ICorDebugHeapValue3;






typedef struct ICorDebugHeapValue4 ICorDebugHeapValue4;






typedef struct ICorDebugObjectValue ICorDebugObjectValue;






typedef struct ICorDebugObjectValue2 ICorDebugObjectValue2;






typedef struct ICorDebugDelegateObjectValue ICorDebugDelegateObjectValue;






typedef struct ICorDebugBoxValue ICorDebugBoxValue;






typedef struct ICorDebugStringValue ICorDebugStringValue;






typedef struct ICorDebugArrayValue ICorDebugArrayValue;






typedef struct ICorDebugVariableHome ICorDebugVariableHome;






typedef struct ICorDebugHandleValue ICorDebugHandleValue;






typedef struct ICorDebugContext ICorDebugContext;






typedef struct ICorDebugComObjectValue ICorDebugComObjectValue;






typedef struct ICorDebugObjectEnum ICorDebugObjectEnum;






typedef struct ICorDebugBreakpointEnum ICorDebugBreakpointEnum;






typedef struct ICorDebugStepperEnum ICorDebugStepperEnum;






typedef struct ICorDebugProcessEnum ICorDebugProcessEnum;






typedef struct ICorDebugThreadEnum ICorDebugThreadEnum;






typedef struct ICorDebugFrameEnum ICorDebugFrameEnum;






typedef struct ICorDebugChainEnum ICorDebugChainEnum;






typedef struct ICorDebugModuleEnum ICorDebugModuleEnum;






typedef struct ICorDebugValueEnum ICorDebugValueEnum;






typedef struct ICorDebugVariableHomeEnum ICorDebugVariableHomeEnum;






typedef struct ICorDebugCodeEnum ICorDebugCodeEnum;






typedef struct ICorDebugTypeEnum ICorDebugTypeEnum;






typedef struct ICorDebugType ICorDebugType;






typedef struct ICorDebugType2 ICorDebugType2;






typedef struct ICorDebugErrorInfoEnum ICorDebugErrorInfoEnum;






typedef struct ICorDebugAppDomainEnum ICorDebugAppDomainEnum;






typedef struct ICorDebugAssemblyEnum ICorDebugAssemblyEnum;






typedef struct ICorDebugBlockingObjectEnum ICorDebugBlockingObjectEnum;






typedef struct ICorDebugMDA ICorDebugMDA;






typedef struct ICorDebugEditAndContinueErrorInfo ICorDebugEditAndContinueErrorInfo;






typedef struct ICorDebugEditAndContinueSnapshot ICorDebugEditAndContinueSnapshot;






typedef struct ICorDebugExceptionObjectCallStackEnum ICorDebugExceptionObjectCallStackEnum;






typedef struct ICorDebugExceptionObjectValue ICorDebugExceptionObjectValue;
#line 998
typedef struct CorDebug CorDebug;
#line 1010
typedef struct EmbeddedCLRCorDebug EmbeddedCLRCorDebug;
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
#line 1291
typedef void *HPROCESS;

typedef void *HTHREAD;

typedef UINT64 TASKID;

typedef DWORD CONNID;



typedef struct
    {
    ULONG32 oldOffset;
    ULONG32 newOffset;
    BOOL fAccurate;
    } 	COR_IL_MAP;




typedef
enum CorDebugIlToNativeMappingTypes
    {
        NO_MAPPING	= -1,
        PROLOG	= -2,
        EPILOG	= -3
    } 	CorDebugIlToNativeMappingTypes;

typedef struct COR_DEBUG_IL_TO_NATIVE_MAP
    {
    ULONG32 ilOffset;
    ULONG32 nativeStartOffset;
    ULONG32 nativeEndOffset;
    } 	COR_DEBUG_IL_TO_NATIVE_MAP;



typedef
enum CorDebugJITCompilerFlags
    {
        CORDEBUG_JIT_DEFAULT	= 0x1,
        CORDEBUG_JIT_DISABLE_OPTIMIZATION	= 0x3,
        CORDEBUG_JIT_ENABLE_ENC	= 0x7
    } 	CorDebugJITCompilerFlags;

typedef
enum CorDebugJITCompilerFlagsDecprecated
    {
        CORDEBUG_JIT_TRACK_DEBUG_INFO	= 0x1
    } 	CorDebugJITCompilerFlagsDeprecated;

typedef
enum CorDebugNGENPolicy
    {
        DISABLE_LOCAL_NIC	= 1
    } 	CorDebugNGENPolicy;

#pragma warning(push)
#pragma warning(disable:28718)
#line 1417
#pragma warning(pop)
typedef ULONG64 CORDB_ADDRESS;

typedef ULONG64 CORDB_REGISTER;

typedef DWORD CORDB_CONTINUE_STATUS;

typedef
enum CorDebugBlockingReason
    {
        BLOCKING_NONE	= 0,
        BLOCKING_MONITOR_CRITICAL_SECTION	= 0x1,
        BLOCKING_MONITOR_EVENT	= 0x2
    } 	CorDebugBlockingReason;

typedef struct CorDebugBlockingObject
    {
    ICorDebugValue *pBlockingObject;
    DWORD dwTimeout;
    CorDebugBlockingReason blockingReason;
    } 	CorDebugBlockingObject;

typedef struct CorDebugExceptionObjectStackFrame
    {
    ICorDebugModule *pModule;
    CORDB_ADDRESS ip;
    mdMethodDef methodDef;
    BOOL isLastForeignExceptionFrame;
    } 	CorDebugExceptionObjectStackFrame;

typedef struct CorDebugGuidToTypeMapping
    {
    GUID iid;
    ICorDebugType *pType;
    } 	CorDebugGuidToTypeMapping;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0000_v0_0_s_ifspec;
#line 1464
typedef
enum CorDebugPlatform
    {
        CORDB_PLATFORM_WINDOWS_X86	= 0,
        CORDB_PLATFORM_WINDOWS_AMD64	= ( CORDB_PLATFORM_WINDOWS_X86 + 1 ) ,
        CORDB_PLATFORM_WINDOWS_IA64	= ( CORDB_PLATFORM_WINDOWS_AMD64 + 1 ) ,
        CORDB_PLATFORM_MAC_PPC	= ( CORDB_PLATFORM_WINDOWS_IA64 + 1 ) ,
        CORDB_PLATFORM_MAC_X86	= ( CORDB_PLATFORM_MAC_PPC + 1 ) ,
        CORDB_PLATFORM_WINDOWS_ARM	= ( CORDB_PLATFORM_MAC_X86 + 1 ) ,
        CORDB_PLATFORM_MAC_AMD64	= ( CORDB_PLATFORM_WINDOWS_ARM + 1 ) ,
        CORDB_PLATFORM_WINDOWS_ARM64	= ( CORDB_PLATFORM_MAC_AMD64 + 1 ) ,
        CORDB_PLATFORM_POSIX_AMD64	= ( CORDB_PLATFORM_WINDOWS_ARM64 + 1 ) ,
        CORDB_PLATFORM_POSIX_X86	= ( CORDB_PLATFORM_POSIX_AMD64 + 1 ) ,
        CORDB_PLATFORM_POSIX_ARM	= ( CORDB_PLATFORM_POSIX_X86 + 1 ) ,
        CORDB_PLATFORM_POSIX_ARM64	= ( CORDB_PLATFORM_POSIX_ARM + 1 ) ,
        CORDB_PLATFORM_POSIX_LOONGARCH64	= ( CORDB_PLATFORM_POSIX_ARM64 + 1 )
    } 	CorDebugPlatform;


 const IID IID_ICorDebugDataTarget;
#line 1511
    typedef struct ICorDebugDataTargetVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugDataTarget * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugDataTarget * This);

        ULONG ( *Release )(
            ICorDebugDataTarget * This);

        HRESULT ( *GetPlatform )(
            ICorDebugDataTarget * This,
              CorDebugPlatform *pTargetPlatform);

        HRESULT ( *ReadVirtual )(
            ICorDebugDataTarget * This,
              CORDB_ADDRESS address,
              BYTE *pBuffer,
              ULONG32 bytesRequested,
              ULONG32 *pBytesRead);

        HRESULT ( *GetThreadContext )(
            ICorDebugDataTarget * This,
              DWORD dwThreadID,
              ULONG32 contextFlags,
              ULONG32 contextSize,
              BYTE *pContext);


    } ICorDebugDataTargetVtbl;

    struct ICorDebugDataTarget
    {
        CONST_VTBL struct ICorDebugDataTargetVtbl *lpVtbl;
    };
#line 1595
 const IID IID_ICorDebugStaticFieldSymbol;
#line 1619
    typedef struct ICorDebugStaticFieldSymbolVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugStaticFieldSymbol * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugStaticFieldSymbol * This);

        ULONG ( *Release )(
            ICorDebugStaticFieldSymbol * This);

        HRESULT ( *GetName )(
            ICorDebugStaticFieldSymbol * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetSize )(
            ICorDebugStaticFieldSymbol * This,
              ULONG32 *pcbSize);

        HRESULT ( *GetAddress )(
            ICorDebugStaticFieldSymbol * This,
              CORDB_ADDRESS *pRVA);


    } ICorDebugStaticFieldSymbolVtbl;

    struct ICorDebugStaticFieldSymbol
    {
        CONST_VTBL struct ICorDebugStaticFieldSymbolVtbl *lpVtbl;
    };
#line 1699
 const IID IID_ICorDebugInstanceFieldSymbol;
#line 1723
    typedef struct ICorDebugInstanceFieldSymbolVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugInstanceFieldSymbol * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugInstanceFieldSymbol * This);

        ULONG ( *Release )(
            ICorDebugInstanceFieldSymbol * This);

        HRESULT ( *GetName )(
            ICorDebugInstanceFieldSymbol * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetSize )(
            ICorDebugInstanceFieldSymbol * This,
              ULONG32 *pcbSize);

        HRESULT ( *GetOffset )(
            ICorDebugInstanceFieldSymbol * This,
              ULONG32 *pcbOffset);


    } ICorDebugInstanceFieldSymbolVtbl;

    struct ICorDebugInstanceFieldSymbol
    {
        CONST_VTBL struct ICorDebugInstanceFieldSymbolVtbl *lpVtbl;
    };
#line 1803
 const IID IID_ICorDebugVariableSymbol;
#line 1843
    typedef struct ICorDebugVariableSymbolVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugVariableSymbol * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugVariableSymbol * This);

        ULONG ( *Release )(
            ICorDebugVariableSymbol * This);

        HRESULT ( *GetName )(
            ICorDebugVariableSymbol * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetSize )(
            ICorDebugVariableSymbol * This,
              ULONG32 *pcbValue);

        HRESULT ( *GetValue )(
            ICorDebugVariableSymbol * This,
              ULONG32 offset,
              ULONG32 cbContext,
              BYTE context[  ],
              ULONG32 cbValue,
              ULONG32 *pcbValue,
              BYTE pValue[  ]);

        HRESULT ( *SetValue )(
            ICorDebugVariableSymbol * This,
              ULONG32 offset,
              DWORD threadID,
              ULONG32 cbContext,
              BYTE context[  ],
              ULONG32 cbValue,
              BYTE pValue[  ]);

        HRESULT ( *GetSlotIndex )(
            ICorDebugVariableSymbol * This,
              ULONG32 *pSlotIndex);


    } ICorDebugVariableSymbolVtbl;

    struct ICorDebugVariableSymbol
    {
        CONST_VTBL struct ICorDebugVariableSymbolVtbl *lpVtbl;
    };
#line 1947
 const IID IID_ICorDebugMemoryBuffer;
#line 1966
    typedef struct ICorDebugMemoryBufferVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugMemoryBuffer * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugMemoryBuffer * This);

        ULONG ( *Release )(
            ICorDebugMemoryBuffer * This);

        HRESULT ( *GetStartAddress )(
            ICorDebugMemoryBuffer * This,
              LPCVOID *address);

        HRESULT ( *GetSize )(
            ICorDebugMemoryBuffer * This,
              ULONG32 *pcbBufferLength);


    } ICorDebugMemoryBufferVtbl;

    struct ICorDebugMemoryBuffer
    {
        CONST_VTBL struct ICorDebugMemoryBufferVtbl *lpVtbl;
    };
#line 2037
 const IID IID_ICorDebugMergedAssemblyRecord;
#line 2079
    typedef struct ICorDebugMergedAssemblyRecordVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugMergedAssemblyRecord * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugMergedAssemblyRecord * This);

        ULONG ( *Release )(
            ICorDebugMergedAssemblyRecord * This);

        HRESULT ( *GetSimpleName )(
            ICorDebugMergedAssemblyRecord * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetVersion )(
            ICorDebugMergedAssemblyRecord * This,
              USHORT *pMajor,
              USHORT *pMinor,
              USHORT *pBuild,
              USHORT *pRevision);

        HRESULT ( *GetCulture )(
            ICorDebugMergedAssemblyRecord * This,
              ULONG32 cchCulture,
              ULONG32 *pcchCulture,
              WCHAR szCulture[  ]);

        HRESULT ( *GetPublicKey )(
            ICorDebugMergedAssemblyRecord * This,
              ULONG32 cbPublicKey,
              ULONG32 *pcbPublicKey,
              BYTE pbPublicKey[  ]);

        HRESULT ( *GetPublicKeyToken )(
            ICorDebugMergedAssemblyRecord * This,
              ULONG32 cbPublicKeyToken,
              ULONG32 *pcbPublicKeyToken,
              BYTE pbPublicKeyToken[  ]);

        HRESULT ( *GetIndex )(
            ICorDebugMergedAssemblyRecord * This,
              ULONG32 *pIndex);


    } ICorDebugMergedAssemblyRecordVtbl;

    struct ICorDebugMergedAssemblyRecord
    {
        CONST_VTBL struct ICorDebugMergedAssemblyRecordVtbl *lpVtbl;
    };
#line 2189
 const IID IID_ICorDebugSymbolProvider;
#line 2265
    typedef struct ICorDebugSymbolProviderVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugSymbolProvider * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugSymbolProvider * This);

        ULONG ( *Release )(
            ICorDebugSymbolProvider * This);

        HRESULT ( *GetStaticFieldSymbols )(
            ICorDebugSymbolProvider * This,
              ULONG32 cbSignature,
              BYTE typeSig[  ],
              ULONG32 cRequestedSymbols,
              ULONG32 *pcFetchedSymbols,
              ICorDebugStaticFieldSymbol *pSymbols[  ]);

        HRESULT ( *GetInstanceFieldSymbols )(
            ICorDebugSymbolProvider * This,
              ULONG32 cbSignature,
              BYTE typeSig[  ],
              ULONG32 cRequestedSymbols,
              ULONG32 *pcFetchedSymbols,
              ICorDebugInstanceFieldSymbol *pSymbols[  ]);

        HRESULT ( *GetMethodLocalSymbols )(
            ICorDebugSymbolProvider * This,
              ULONG32 nativeRVA,
              ULONG32 cRequestedSymbols,
              ULONG32 *pcFetchedSymbols,
              ICorDebugVariableSymbol *pSymbols[  ]);

        HRESULT ( *GetMethodParameterSymbols )(
            ICorDebugSymbolProvider * This,
              ULONG32 nativeRVA,
              ULONG32 cRequestedSymbols,
              ULONG32 *pcFetchedSymbols,
              ICorDebugVariableSymbol *pSymbols[  ]);

        HRESULT ( *GetMergedAssemblyRecords )(
            ICorDebugSymbolProvider * This,
              ULONG32 cRequestedRecords,
              ULONG32 *pcFetchedRecords,
              ICorDebugMergedAssemblyRecord *pRecords[  ]);

        HRESULT ( *GetMethodProps )(
            ICorDebugSymbolProvider * This,
              ULONG32 codeRva,
              mdToken *pMethodToken,
              ULONG32 *pcGenericParams,
              ULONG32 cbSignature,
              ULONG32 *pcbSignature,
              BYTE signature[  ]);

        HRESULT ( *GetTypeProps )(
            ICorDebugSymbolProvider * This,
              ULONG32 vtableRva,
              ULONG32 cbSignature,
              ULONG32 *pcbSignature,
              BYTE signature[  ]);

        HRESULT ( *GetCodeRange )(
            ICorDebugSymbolProvider * This,
              ULONG32 codeRva,
              ULONG32 *pCodeStartAddress,
            ULONG32 *pCodeSize);

        HRESULT ( *GetAssemblyImageBytes )(
            ICorDebugSymbolProvider * This,
              CORDB_ADDRESS rva,
              ULONG32 length,
              ICorDebugMemoryBuffer **ppMemoryBuffer);

        HRESULT ( *GetObjectSize )(
            ICorDebugSymbolProvider * This,
              ULONG32 cbSignature,
              BYTE typeSig[  ],
              ULONG32 *pObjectSize);

        HRESULT ( *GetAssemblyImageMetadata )(
            ICorDebugSymbolProvider * This,
              ICorDebugMemoryBuffer **ppMemoryBuffer);


    } ICorDebugSymbolProviderVtbl;

    struct ICorDebugSymbolProvider
    {
        CONST_VTBL struct ICorDebugSymbolProviderVtbl *lpVtbl;
    };
#line 2429
 const IID IID_ICorDebugSymbolProvider2;
#line 2450
    typedef struct ICorDebugSymbolProvider2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugSymbolProvider2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugSymbolProvider2 * This);

        ULONG ( *Release )(
            ICorDebugSymbolProvider2 * This);

        HRESULT ( *GetGenericDictionaryInfo )(
            ICorDebugSymbolProvider2 * This,
              ICorDebugMemoryBuffer **ppMemoryBuffer);

        HRESULT ( *GetFrameProps )(
            ICorDebugSymbolProvider2 * This,
              ULONG32 codeRva,
              ULONG32 *pCodeStartRva,
              ULONG32 *pParentFrameStartRva);


    } ICorDebugSymbolProvider2Vtbl;

    struct ICorDebugSymbolProvider2
    {
        CONST_VTBL struct ICorDebugSymbolProvider2Vtbl *lpVtbl;
    };
#line 2523
 const IID IID_ICorDebugVirtualUnwinder;
#line 2544
    typedef struct ICorDebugVirtualUnwinderVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugVirtualUnwinder * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugVirtualUnwinder * This);

        ULONG ( *Release )(
            ICorDebugVirtualUnwinder * This);

        HRESULT ( *GetContext )(
            ICorDebugVirtualUnwinder * This,
              ULONG32 contextFlags,
              ULONG32 cbContextBuf,
              ULONG32 *contextSize,
              BYTE contextBuf[  ]);

        HRESULT ( *Next )(
            ICorDebugVirtualUnwinder * This);


    } ICorDebugVirtualUnwinderVtbl;

    struct ICorDebugVirtualUnwinder
    {
        CONST_VTBL struct ICorDebugVirtualUnwinderVtbl *lpVtbl;
    };
#line 2617
 const IID IID_ICorDebugDataTarget2;
#line 2657
    typedef struct ICorDebugDataTarget2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugDataTarget2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugDataTarget2 * This);

        ULONG ( *Release )(
            ICorDebugDataTarget2 * This);

        HRESULT ( *GetImageFromPointer )(
            ICorDebugDataTarget2 * This,
              CORDB_ADDRESS addr,
              CORDB_ADDRESS *pImageBase,
              ULONG32 *pSize);

        HRESULT ( *GetImageLocation )(
            ICorDebugDataTarget2 * This,
              CORDB_ADDRESS baseAddress,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetSymbolProviderForImage )(
            ICorDebugDataTarget2 * This,
              CORDB_ADDRESS imageBaseAddress,
              ICorDebugSymbolProvider **ppSymProvider);

        HRESULT ( *EnumerateThreadIDs )(
            ICorDebugDataTarget2 * This,
              ULONG32 cThreadIds,
              ULONG32 *pcThreadIds,
              ULONG32 pThreadIds[  ]);

        HRESULT ( *CreateVirtualUnwinder )(
            ICorDebugDataTarget2 * This,
              DWORD nativeThreadID,
              ULONG32 contextFlags,
              ULONG32 cbContext,
              BYTE initialContext[  ],
              ICorDebugVirtualUnwinder **ppUnwinder);


    } ICorDebugDataTarget2Vtbl;

    struct ICorDebugDataTarget2
    {
        CONST_VTBL struct ICorDebugDataTarget2Vtbl *lpVtbl;
    };
#line 2761
 const IID IID_ICorDebugLoadedModule;
#line 2785
    typedef struct ICorDebugLoadedModuleVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugLoadedModule * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugLoadedModule * This);

        ULONG ( *Release )(
            ICorDebugLoadedModule * This);

        HRESULT ( *GetBaseAddress )(
            ICorDebugLoadedModule * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *GetName )(
            ICorDebugLoadedModule * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetSize )(
            ICorDebugLoadedModule * This,
              ULONG32 *pcBytes);


    } ICorDebugLoadedModuleVtbl;

    struct ICorDebugLoadedModule
    {
        CONST_VTBL struct ICorDebugLoadedModuleVtbl *lpVtbl;
    };
#line 2865
 const IID IID_ICorDebugDataTarget3;
#line 2883
    typedef struct ICorDebugDataTarget3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugDataTarget3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugDataTarget3 * This);

        ULONG ( *Release )(
            ICorDebugDataTarget3 * This);

        HRESULT ( *GetLoadedModules )(
            ICorDebugDataTarget3 * This,
              ULONG32 cRequestedModules,
              ULONG32 *pcFetchedModules,
              ICorDebugLoadedModule *pLoadedModules[  ]);


    } ICorDebugDataTarget3Vtbl;

    struct ICorDebugDataTarget3
    {
        CONST_VTBL struct ICorDebugDataTarget3Vtbl *lpVtbl;
    };
#line 2949
 const IID IID_ICorDebugDataTarget4;
#line 2967
    typedef struct ICorDebugDataTarget4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugDataTarget4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugDataTarget4 * This);

        ULONG ( *Release )(
            ICorDebugDataTarget4 * This);

        HRESULT ( *VirtualUnwind )(
            ICorDebugDataTarget4 * This,
              DWORD threadId,
              ULONG32 contextSize,
              BYTE *context);


    } ICorDebugDataTarget4Vtbl;

    struct ICorDebugDataTarget4
    {
        CONST_VTBL struct ICorDebugDataTarget4Vtbl *lpVtbl;
    };
#line 3033
 const IID IID_ICorDebugMutableDataTarget;
#line 3060
    typedef struct ICorDebugMutableDataTargetVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugMutableDataTarget * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugMutableDataTarget * This);

        ULONG ( *Release )(
            ICorDebugMutableDataTarget * This);

        HRESULT ( *GetPlatform )(
            ICorDebugMutableDataTarget * This,
              CorDebugPlatform *pTargetPlatform);

        HRESULT ( *ReadVirtual )(
            ICorDebugMutableDataTarget * This,
              CORDB_ADDRESS address,
              BYTE *pBuffer,
              ULONG32 bytesRequested,
              ULONG32 *pBytesRead);

        HRESULT ( *GetThreadContext )(
            ICorDebugMutableDataTarget * This,
              DWORD dwThreadID,
              ULONG32 contextFlags,
              ULONG32 contextSize,
              BYTE *pContext);

        HRESULT ( *WriteVirtual )(
            ICorDebugMutableDataTarget * This,
              CORDB_ADDRESS address,
              const BYTE *pBuffer,
              ULONG32 bytesRequested);

        HRESULT ( *SetThreadContext )(
            ICorDebugMutableDataTarget * This,
              DWORD dwThreadID,
              ULONG32 contextSize,
              const BYTE *pContext);

        HRESULT ( *ContinueStatusChanged )(
            ICorDebugMutableDataTarget * This,
              DWORD dwThreadId,
              CORDB_CONTINUE_STATUS continueStatus);


    } ICorDebugMutableDataTargetVtbl;

    struct ICorDebugMutableDataTarget
    {
        CONST_VTBL struct ICorDebugMutableDataTargetVtbl *lpVtbl;
    };
#line 3171
 const IID IID_ICorDebugMetaDataLocator;
#line 3194
    typedef struct ICorDebugMetaDataLocatorVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugMetaDataLocator * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugMetaDataLocator * This);

        ULONG ( *Release )(
            ICorDebugMetaDataLocator * This);

        HRESULT ( *GetMetaData )(
            ICorDebugMetaDataLocator * This,
              LPCWSTR wszImagePath,
              DWORD dwImageTimeStamp,
              DWORD dwImageSize,
              ULONG32 cchPathBuffer,

            _Out_  ULONG32 *pcchPathBuffer,

            _Out_writes_to_(cchPathBuffer, *pcchPathBuffer)   WCHAR wszPathBuffer[  ]);


    } ICorDebugMetaDataLocatorVtbl;

    struct ICorDebugMetaDataLocator
    {
        CONST_VTBL struct ICorDebugMetaDataLocatorVtbl *lpVtbl;
    };
#line 3261
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0015_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0015_v0_0_s_ifspec;
#line 3274
typedef
enum CorDebugStepReason
    {
        STEP_NORMAL	= 0,
        STEP_RETURN	= ( STEP_NORMAL + 1 ) ,
        STEP_CALL	= ( STEP_RETURN + 1 ) ,
        STEP_EXCEPTION_FILTER	= ( STEP_CALL + 1 ) ,
        STEP_EXCEPTION_HANDLER	= ( STEP_EXCEPTION_FILTER + 1 ) ,
        STEP_INTERCEPT	= ( STEP_EXCEPTION_HANDLER + 1 ) ,
        STEP_EXIT	= ( STEP_INTERCEPT + 1 )
    } 	CorDebugStepReason;

typedef
enum LoggingLevelEnum
    {
        LTraceLevel0	= 0,
        LTraceLevel1	= ( LTraceLevel0 + 1 ) ,
        LTraceLevel2	= ( LTraceLevel1 + 1 ) ,
        LTraceLevel3	= ( LTraceLevel2 + 1 ) ,
        LTraceLevel4	= ( LTraceLevel3 + 1 ) ,
        LStatusLevel0	= 20,
        LStatusLevel1	= ( LStatusLevel0 + 1 ) ,
        LStatusLevel2	= ( LStatusLevel1 + 1 ) ,
        LStatusLevel3	= ( LStatusLevel2 + 1 ) ,
        LStatusLevel4	= ( LStatusLevel3 + 1 ) ,
        LWarningLevel	= 40,
        LErrorLevel	= 50,
        LPanicLevel	= 100
    } 	LoggingLevelEnum;

typedef
enum LogSwitchCallReason
    {
        SWITCH_CREATE	= 0,
        SWITCH_MODIFY	= ( SWITCH_CREATE + 1 ) ,
        SWITCH_DELETE	= ( SWITCH_MODIFY + 1 )
    } 	LogSwitchCallReason;


 const IID IID_ICorDebugManagedCallback;
#line 3446
    typedef struct ICorDebugManagedCallbackVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugManagedCallback * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugManagedCallback * This);

        ULONG ( *Release )(
            ICorDebugManagedCallback * This);

        HRESULT ( *Breakpoint )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugBreakpoint *pBreakpoint);

        HRESULT ( *StepComplete )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugStepper *pStepper,
              CorDebugStepReason reason);

        HRESULT ( *Break )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *thread);

        HRESULT ( *Exception )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              BOOL unhandled);

        HRESULT ( *EvalComplete )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugEval *pEval);

        HRESULT ( *EvalException )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugEval *pEval);

        HRESULT ( *CreateProcessW )(
            ICorDebugManagedCallback * This,
              ICorDebugProcess *pProcess);

        HRESULT ( *ExitProcess )(
            ICorDebugManagedCallback * This,
              ICorDebugProcess *pProcess);

        HRESULT ( *CreateThread )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *thread);

        HRESULT ( *ExitThread )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *thread);

        HRESULT ( *LoadModule )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugModule *pModule);

        HRESULT ( *UnloadModule )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugModule *pModule);

        HRESULT ( *LoadClass )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugClass *c);

        HRESULT ( *UnloadClass )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugClass *c);

        HRESULT ( *DebuggerError )(
            ICorDebugManagedCallback * This,
              ICorDebugProcess *pProcess,
              HRESULT errorHR,
              DWORD errorCode);

        HRESULT ( *LogMessage )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              LONG lLevel,
              WCHAR *pLogSwitchName,
              WCHAR *pMessage);

        HRESULT ( *LogSwitch )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              LONG lLevel,
              ULONG ulReason,
              WCHAR *pLogSwitchName,
              WCHAR *pParentName);

        HRESULT ( *CreateAppDomain )(
            ICorDebugManagedCallback * This,
              ICorDebugProcess *pProcess,
              ICorDebugAppDomain *pAppDomain);

        HRESULT ( *ExitAppDomain )(
            ICorDebugManagedCallback * This,
              ICorDebugProcess *pProcess,
              ICorDebugAppDomain *pAppDomain);

        HRESULT ( *LoadAssembly )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugAssembly *pAssembly);

        HRESULT ( *UnloadAssembly )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugAssembly *pAssembly);

        HRESULT ( *ControlCTrap )(
            ICorDebugManagedCallback * This,
              ICorDebugProcess *pProcess);

        HRESULT ( *NameChange )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread);

        HRESULT ( *UpdateModuleSymbols )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugModule *pModule,
              IStream *pSymbolStream);

        HRESULT ( *EditAndContinueRemap )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugFunction *pFunction,
              BOOL fAccurate);

        HRESULT ( *BreakpointSetError )(
            ICorDebugManagedCallback * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugBreakpoint *pBreakpoint,
              DWORD dwError);


    } ICorDebugManagedCallbackVtbl;

    struct ICorDebugManagedCallback
    {
        CONST_VTBL struct ICorDebugManagedCallbackVtbl *lpVtbl;
    };
#line 3723
#pragma warning(pop)
#pragma warning(push)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0016_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0016_v0_0_s_ifspec;
#line 3737
 const IID IID_ICorDebugManagedCallback3;
#line 3754
    typedef struct ICorDebugManagedCallback3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugManagedCallback3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugManagedCallback3 * This);

        ULONG ( *Release )(
            ICorDebugManagedCallback3 * This);

        HRESULT ( *CustomNotification )(
            ICorDebugManagedCallback3 * This,
              ICorDebugThread *pThread,
              ICorDebugAppDomain *pAppDomain);


    } ICorDebugManagedCallback3Vtbl;

    struct ICorDebugManagedCallback3
    {
        CONST_VTBL struct ICorDebugManagedCallback3Vtbl *lpVtbl;
    };
#line 3819
 const IID IID_ICorDebugManagedCallback4;
#line 3844
    typedef struct ICorDebugManagedCallback4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugManagedCallback4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugManagedCallback4 * This);

        ULONG ( *Release )(
            ICorDebugManagedCallback4 * This);

        HRESULT ( *BeforeGarbageCollection )(
            ICorDebugManagedCallback4 * This,
              ICorDebugProcess *pProcess);

        HRESULT ( *AfterGarbageCollection )(
            ICorDebugManagedCallback4 * This,
              ICorDebugProcess *pProcess);

        HRESULT ( *DataBreakpoint )(
            ICorDebugManagedCallback4 * This,
              ICorDebugProcess *pProcess,
              ICorDebugThread *pThread,
              BYTE *pContext,
              ULONG32 contextSize);


    } ICorDebugManagedCallback4Vtbl;

    struct ICorDebugManagedCallback4
    {
        CONST_VTBL struct ICorDebugManagedCallback4Vtbl *lpVtbl;
    };
#line 3921
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0018_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0018_v0_0_s_ifspec;
#line 3933
typedef
enum CorDebugExceptionCallbackType
    {
        DEBUG_EXCEPTION_FIRST_CHANCE	= 1,
        DEBUG_EXCEPTION_USER_FIRST_CHANCE	= 2,
        DEBUG_EXCEPTION_CATCH_HANDLER_FOUND	= 3,
        DEBUG_EXCEPTION_UNHANDLED	= 4
    } 	CorDebugExceptionCallbackType;

typedef
enum CorDebugExceptionFlags
    {
        DEBUG_EXCEPTION_NONE	= 0,
        DEBUG_EXCEPTION_CAN_BE_INTERCEPTED	= 0x1
    } 	CorDebugExceptionFlags;

typedef
enum CorDebugExceptionUnwindCallbackType
    {
        DEBUG_EXCEPTION_UNWIND_BEGIN	= 1,
        DEBUG_EXCEPTION_INTERCEPTED	= 2
    } 	CorDebugExceptionUnwindCallbackType;


 const IID IID_ICorDebugManagedCallback2;
#line 4014
    typedef struct ICorDebugManagedCallback2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugManagedCallback2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugManagedCallback2 * This);

        ULONG ( *Release )(
            ICorDebugManagedCallback2 * This);

        HRESULT ( *FunctionRemapOpportunity )(
            ICorDebugManagedCallback2 * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugFunction *pOldFunction,
              ICorDebugFunction *pNewFunction,
              ULONG32 oldILOffset);

        HRESULT ( *CreateConnection )(
            ICorDebugManagedCallback2 * This,
              ICorDebugProcess *pProcess,
              CONNID dwConnectionId,
              WCHAR *pConnName);

        HRESULT ( *ChangeConnection )(
            ICorDebugManagedCallback2 * This,
              ICorDebugProcess *pProcess,
              CONNID dwConnectionId);

        HRESULT ( *DestroyConnection )(
            ICorDebugManagedCallback2 * This,
              ICorDebugProcess *pProcess,
              CONNID dwConnectionId);

        HRESULT ( *Exception )(
            ICorDebugManagedCallback2 * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugFrame *pFrame,
              ULONG32 nOffset,
              CorDebugExceptionCallbackType dwEventType,
              DWORD dwFlags);

        HRESULT ( *ExceptionUnwind )(
            ICorDebugManagedCallback2 * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              CorDebugExceptionUnwindCallbackType dwEventType,
              DWORD dwFlags);

        HRESULT ( *FunctionRemapComplete )(
            ICorDebugManagedCallback2 * This,
              ICorDebugAppDomain *pAppDomain,
              ICorDebugThread *pThread,
              ICorDebugFunction *pFunction);

        HRESULT ( *MDANotification )(
            ICorDebugManagedCallback2 * This,
              ICorDebugController *pController,
              ICorDebugThread *pThread,
              ICorDebugMDA *pMDA);


    } ICorDebugManagedCallback2Vtbl;

    struct ICorDebugManagedCallback2
    {
        CONST_VTBL struct ICorDebugManagedCallback2Vtbl *lpVtbl;
    };
#line 4143
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0019_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0019_v0_0_s_ifspec;
#line 4156
 const IID IID_ICorDebugUnmanagedCallback;
#line 4173
    typedef struct ICorDebugUnmanagedCallbackVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugUnmanagedCallback * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugUnmanagedCallback * This);

        ULONG ( *Release )(
            ICorDebugUnmanagedCallback * This);

        HRESULT ( *DebugEvent )(
            ICorDebugUnmanagedCallback * This,
              LPDEBUG_EVENT pDebugEvent,
              BOOL fOutOfBand);


    } ICorDebugUnmanagedCallbackVtbl;

    struct ICorDebugUnmanagedCallback
    {
        CONST_VTBL struct ICorDebugUnmanagedCallbackVtbl *lpVtbl;
    };
#line 4234
typedef
enum CorDebugCreateProcessFlags
    {
        DEBUG_NO_SPECIAL_OPTIONS	= 0
    } 	CorDebugCreateProcessFlags;

typedef
enum CorDebugHandleType
    {
        HANDLE_STRONG	= 1,
        HANDLE_WEAK_TRACK_RESURRECTION	= 2,
        HANDLE_PINNED	= 3
    } 	CorDebugHandleType;

#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0020_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0020_v0_0_s_ifspec;
#line 4262
 const IID IID_ICorDebug;
#line 4315
    typedef struct ICorDebugVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebug * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebug * This);

        ULONG ( *Release )(
            ICorDebug * This);

        HRESULT ( *Initialize )(
            ICorDebug * This);

        HRESULT ( *Terminate )(
            ICorDebug * This);

        HRESULT ( *SetManagedHandler )(
            ICorDebug * This,
              ICorDebugManagedCallback *pCallback);

        HRESULT ( *SetUnmanagedHandler )(
            ICorDebug * This,
              ICorDebugUnmanagedCallback *pCallback);

        HRESULT ( *CreateProcessW )(
            ICorDebug * This,
              LPCWSTR lpApplicationName,
              LPWSTR lpCommandLine,
              LPSECURITY_ATTRIBUTES lpProcessAttributes,
              LPSECURITY_ATTRIBUTES lpThreadAttributes,
              BOOL bInheritHandles,
              DWORD dwCreationFlags,
              PVOID lpEnvironment,
              LPCWSTR lpCurrentDirectory,
              LPSTARTUPINFOW lpStartupInfo,
              LPPROCESS_INFORMATION lpProcessInformation,
              CorDebugCreateProcessFlags debuggingFlags,
              ICorDebugProcess **ppProcess);

        HRESULT ( *DebugActiveProcess )(
            ICorDebug * This,
              DWORD id,
              BOOL win32Attach,
              ICorDebugProcess **ppProcess);

        HRESULT ( *EnumerateProcesses )(
            ICorDebug * This,
              ICorDebugProcessEnum **ppProcess);

        HRESULT ( *GetProcess )(
            ICorDebug * This,
              DWORD dwProcessId,
              ICorDebugProcess **ppProcess);

        HRESULT ( *CanLaunchOrAttach )(
            ICorDebug * This,
              DWORD dwProcessId,
              BOOL win32DebuggingEnabled);


    } ICorDebugVtbl;

    struct ICorDebug
    {
        CONST_VTBL struct ICorDebugVtbl *lpVtbl;
    };
#line 4444
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0021_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0021_v0_0_s_ifspec;
#line 4457
 const IID IID_ICorDebugRemoteTarget;
#line 4477
    typedef struct ICorDebugRemoteTargetVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugRemoteTarget * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugRemoteTarget * This);

        ULONG ( *Release )(
            ICorDebugRemoteTarget * This);

        HRESULT ( *GetHostName )(
            ICorDebugRemoteTarget * This,
              ULONG32 cchHostName,

            _Out_  ULONG32 *pcchHostName,

            _Out_writes_to_opt_(cchHostName, *pcchHostName)  WCHAR szHostName[  ]);


    } ICorDebugRemoteTargetVtbl;

    struct ICorDebugRemoteTarget
    {
        CONST_VTBL struct ICorDebugRemoteTargetVtbl *lpVtbl;
    };
#line 4545
 const IID IID_ICorDebugRemote;
#line 4580
    typedef struct ICorDebugRemoteVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugRemote * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugRemote * This);

        ULONG ( *Release )(
            ICorDebugRemote * This);

        HRESULT ( *CreateProcessEx )(
            ICorDebugRemote * This,
              ICorDebugRemoteTarget *pRemoteTarget,
              LPCWSTR lpApplicationName,

            _In_  LPWSTR lpCommandLine,
              LPSECURITY_ATTRIBUTES lpProcessAttributes,
              LPSECURITY_ATTRIBUTES lpThreadAttributes,
              BOOL bInheritHandles,
              DWORD dwCreationFlags,
              PVOID lpEnvironment,
              LPCWSTR lpCurrentDirectory,
              LPSTARTUPINFOW lpStartupInfo,
              LPPROCESS_INFORMATION lpProcessInformation,
              CorDebugCreateProcessFlags debuggingFlags,
              ICorDebugProcess **ppProcess);

        HRESULT ( *DebugActiveProcessEx )(
            ICorDebugRemote * This,
              ICorDebugRemoteTarget *pRemoteTarget,
              DWORD dwProcessId,
              BOOL fWin32Attach,
              ICorDebugProcess **ppProcess);


    } ICorDebugRemoteVtbl;

    struct ICorDebugRemote
    {
        CONST_VTBL struct ICorDebugRemoteVtbl *lpVtbl;
    };
#line 4663
typedef struct _COR_VERSION
    {
    DWORD dwMajor;
    DWORD dwMinor;
    DWORD dwBuild;
    DWORD dwSubBuild;
    } 	COR_VERSION;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0023_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0023_v0_0_s_ifspec;
#line 4682
typedef
enum CorDebugInterfaceVersion
    {
        CorDebugInvalidVersion	= 0,
        CorDebugVersion_1_0	= ( CorDebugInvalidVersion + 1 ) ,
        ver_ICorDebugManagedCallback	= CorDebugVersion_1_0,
        ver_ICorDebugUnmanagedCallback	= CorDebugVersion_1_0,
        ver_ICorDebug	= CorDebugVersion_1_0,
        ver_ICorDebugController	= CorDebugVersion_1_0,
        ver_ICorDebugAppDomain	= CorDebugVersion_1_0,
        ver_ICorDebugAssembly	= CorDebugVersion_1_0,
        ver_ICorDebugProcess	= CorDebugVersion_1_0,
        ver_ICorDebugBreakpoint	= CorDebugVersion_1_0,
        ver_ICorDebugFunctionBreakpoint	= CorDebugVersion_1_0,
        ver_ICorDebugModuleBreakpoint	= CorDebugVersion_1_0,
        ver_ICorDebugValueBreakpoint	= CorDebugVersion_1_0,
        ver_ICorDebugStepper	= CorDebugVersion_1_0,
        ver_ICorDebugRegisterSet	= CorDebugVersion_1_0,
        ver_ICorDebugThread	= CorDebugVersion_1_0,
        ver_ICorDebugChain	= CorDebugVersion_1_0,
        ver_ICorDebugFrame	= CorDebugVersion_1_0,
        ver_ICorDebugILFrame	= CorDebugVersion_1_0,
        ver_ICorDebugNativeFrame	= CorDebugVersion_1_0,
        ver_ICorDebugModule	= CorDebugVersion_1_0,
        ver_ICorDebugFunction	= CorDebugVersion_1_0,
        ver_ICorDebugCode	= CorDebugVersion_1_0,
        ver_ICorDebugClass	= CorDebugVersion_1_0,
        ver_ICorDebugEval	= CorDebugVersion_1_0,
        ver_ICorDebugValue	= CorDebugVersion_1_0,
        ver_ICorDebugGenericValue	= CorDebugVersion_1_0,
        ver_ICorDebugReferenceValue	= CorDebugVersion_1_0,
        ver_ICorDebugHeapValue	= CorDebugVersion_1_0,
        ver_ICorDebugObjectValue	= CorDebugVersion_1_0,
        ver_ICorDebugBoxValue	= CorDebugVersion_1_0,
        ver_ICorDebugStringValue	= CorDebugVersion_1_0,
        ver_ICorDebugArrayValue	= CorDebugVersion_1_0,
        ver_ICorDebugContext	= CorDebugVersion_1_0,
        ver_ICorDebugEnum	= CorDebugVersion_1_0,
        ver_ICorDebugObjectEnum	= CorDebugVersion_1_0,
        ver_ICorDebugBreakpointEnum	= CorDebugVersion_1_0,
        ver_ICorDebugStepperEnum	= CorDebugVersion_1_0,
        ver_ICorDebugProcessEnum	= CorDebugVersion_1_0,
        ver_ICorDebugThreadEnum	= CorDebugVersion_1_0,
        ver_ICorDebugFrameEnum	= CorDebugVersion_1_0,
        ver_ICorDebugChainEnum	= CorDebugVersion_1_0,
        ver_ICorDebugModuleEnum	= CorDebugVersion_1_0,
        ver_ICorDebugValueEnum	= CorDebugVersion_1_0,
        ver_ICorDebugCodeEnum	= CorDebugVersion_1_0,
        ver_ICorDebugTypeEnum	= CorDebugVersion_1_0,
        ver_ICorDebugErrorInfoEnum	= CorDebugVersion_1_0,
        ver_ICorDebugAppDomainEnum	= CorDebugVersion_1_0,
        ver_ICorDebugAssemblyEnum	= CorDebugVersion_1_0,
        ver_ICorDebugEditAndContinueErrorInfo	= CorDebugVersion_1_0,
        ver_ICorDebugEditAndContinueSnapshot	= CorDebugVersion_1_0,
        CorDebugVersion_1_1	= ( CorDebugVersion_1_0 + 1 ) ,
        CorDebugVersion_2_0	= ( CorDebugVersion_1_1 + 1 ) ,
        ver_ICorDebugManagedCallback2	= CorDebugVersion_2_0,
        ver_ICorDebugAppDomain2	= CorDebugVersion_2_0,
        ver_ICorDebugAssembly2	= CorDebugVersion_2_0,
        ver_ICorDebugProcess2	= CorDebugVersion_2_0,
        ver_ICorDebugStepper2	= CorDebugVersion_2_0,
        ver_ICorDebugRegisterSet2	= CorDebugVersion_2_0,
        ver_ICorDebugThread2	= CorDebugVersion_2_0,
        ver_ICorDebugILFrame2	= CorDebugVersion_2_0,
        ver_ICorDebugInternalFrame	= CorDebugVersion_2_0,
        ver_ICorDebugModule2	= CorDebugVersion_2_0,
        ver_ICorDebugFunction2	= CorDebugVersion_2_0,
        ver_ICorDebugCode2	= CorDebugVersion_2_0,
        ver_ICorDebugClass2	= CorDebugVersion_2_0,
        ver_ICorDebugValue2	= CorDebugVersion_2_0,
        ver_ICorDebugEval2	= CorDebugVersion_2_0,
        ver_ICorDebugObjectValue2	= CorDebugVersion_2_0,
        CorDebugVersion_4_0	= ( CorDebugVersion_2_0 + 1 ) ,
        ver_ICorDebugThread3	= CorDebugVersion_4_0,
        ver_ICorDebugThread4	= CorDebugVersion_4_0,
        ver_ICorDebugStackWalk	= CorDebugVersion_4_0,
        ver_ICorDebugNativeFrame2	= CorDebugVersion_4_0,
        ver_ICorDebugInternalFrame2	= CorDebugVersion_4_0,
        ver_ICorDebugRuntimeUnwindableFrame	= CorDebugVersion_4_0,
        ver_ICorDebugHeapValue3	= CorDebugVersion_4_0,
        ver_ICorDebugBlockingObjectEnum	= CorDebugVersion_4_0,
        ver_ICorDebugValue3	= CorDebugVersion_4_0,
        CorDebugVersion_4_5	= ( CorDebugVersion_4_0 + 1 ) ,
        ver_ICorDebugComObjectValue	= CorDebugVersion_4_5,
        ver_ICorDebugAppDomain3	= CorDebugVersion_4_5,
        ver_ICorDebugCode3	= CorDebugVersion_4_5,
        ver_ICorDebugILFrame3	= CorDebugVersion_4_5,
        CorDebugLatestVersion	= CorDebugVersion_4_5
    } 	CorDebugInterfaceVersion;


 const IID IID_ICorDebug2;
#line 4786
    typedef struct ICorDebug2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebug2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebug2 * This);

        ULONG ( *Release )(
            ICorDebug2 * This);


    } ICorDebug2Vtbl;

    struct ICorDebug2
    {
        CONST_VTBL struct ICorDebug2Vtbl *lpVtbl;
    };
#line 4839
typedef
enum CorDebugThreadState
    {
        THREAD_RUN	= 0,
        THREAD_SUSPEND	= ( THREAD_RUN + 1 )
    } 	CorDebugThreadState;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0024_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0024_v0_0_s_ifspec;
#line 4858
 const IID IID_ICorDebugController;
#line 4906
    typedef struct ICorDebugControllerVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugController * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugController * This);

        ULONG ( *Release )(
            ICorDebugController * This);

        HRESULT ( *Stop )(
            ICorDebugController * This,
              DWORD dwTimeoutIgnored);

        HRESULT ( *Continue )(
            ICorDebugController * This,
              BOOL fIsOutOfBand);

        HRESULT ( *IsRunning )(
            ICorDebugController * This,
              BOOL *pbRunning);

        HRESULT ( *HasQueuedCallbacks )(
            ICorDebugController * This,
              ICorDebugThread *pThread,
              BOOL *pbQueued);

        HRESULT ( *EnumerateThreads )(
            ICorDebugController * This,
              ICorDebugThreadEnum **ppThreads);

        HRESULT ( *SetAllThreadsDebugState )(
            ICorDebugController * This,
              CorDebugThreadState state,
              ICorDebugThread *pExceptThisThread);

        HRESULT ( *Detach )(
            ICorDebugController * This);

        HRESULT ( *Terminate )(
            ICorDebugController * This,
              UINT exitCode);

        HRESULT ( *CanCommitChanges )(
            ICorDebugController * This,
              ULONG cSnapshots,
              ICorDebugEditAndContinueSnapshot *pSnapshots[  ],
              ICorDebugErrorInfoEnum **pError);

        HRESULT ( *CommitChanges )(
            ICorDebugController * This,
              ULONG cSnapshots,
              ICorDebugEditAndContinueSnapshot *pSnapshots[  ],
              ICorDebugErrorInfoEnum **pError);


    } ICorDebugControllerVtbl;

    struct ICorDebugController
    {
        CONST_VTBL struct ICorDebugControllerVtbl *lpVtbl;
    };
#line 5034
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0025_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0025_v0_0_s_ifspec;
#line 5048
 const IID IID_ICorDebugAppDomain;
#line 5093
    typedef struct ICorDebugAppDomainVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAppDomain * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAppDomain * This);

        ULONG ( *Release )(
            ICorDebugAppDomain * This);

        HRESULT ( *Stop )(
            ICorDebugAppDomain * This,
              DWORD dwTimeoutIgnored);

        HRESULT ( *Continue )(
            ICorDebugAppDomain * This,
              BOOL fIsOutOfBand);

        HRESULT ( *IsRunning )(
            ICorDebugAppDomain * This,
              BOOL *pbRunning);

        HRESULT ( *HasQueuedCallbacks )(
            ICorDebugAppDomain * This,
              ICorDebugThread *pThread,
              BOOL *pbQueued);

        HRESULT ( *EnumerateThreads )(
            ICorDebugAppDomain * This,
              ICorDebugThreadEnum **ppThreads);

        HRESULT ( *SetAllThreadsDebugState )(
            ICorDebugAppDomain * This,
              CorDebugThreadState state,
              ICorDebugThread *pExceptThisThread);

        HRESULT ( *Detach )(
            ICorDebugAppDomain * This);

        HRESULT ( *Terminate )(
            ICorDebugAppDomain * This,
              UINT exitCode);

        HRESULT ( *CanCommitChanges )(
            ICorDebugAppDomain * This,
              ULONG cSnapshots,
              ICorDebugEditAndContinueSnapshot *pSnapshots[  ],
              ICorDebugErrorInfoEnum **pError);

        HRESULT ( *CommitChanges )(
            ICorDebugAppDomain * This,
              ULONG cSnapshots,
              ICorDebugEditAndContinueSnapshot *pSnapshots[  ],
              ICorDebugErrorInfoEnum **pError);

        HRESULT ( *GetProcess )(
            ICorDebugAppDomain * This,
              ICorDebugProcess **ppProcess);

        HRESULT ( *EnumerateAssemblies )(
            ICorDebugAppDomain * This,
              ICorDebugAssemblyEnum **ppAssemblies);

        HRESULT ( *GetModuleFromMetaDataInterface )(
            ICorDebugAppDomain * This,
              IUnknown *pIMetaData,
              ICorDebugModule **ppModule);

        HRESULT ( *EnumerateBreakpoints )(
            ICorDebugAppDomain * This,
              ICorDebugBreakpointEnum **ppBreakpoints);

        HRESULT ( *EnumerateSteppers )(
            ICorDebugAppDomain * This,
              ICorDebugStepperEnum **ppSteppers);

        HRESULT ( *IsAttached )(
            ICorDebugAppDomain * This,
              BOOL *pbAttached);

        HRESULT ( *GetName )(
            ICorDebugAppDomain * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetObject )(
            ICorDebugAppDomain * This,
              ICorDebugValue **ppObject);

        HRESULT ( *Attach )(
            ICorDebugAppDomain * This);

        HRESULT ( *GetID )(
            ICorDebugAppDomain * This,
              ULONG32 *pId);


    } ICorDebugAppDomainVtbl;

    struct ICorDebugAppDomain
    {
        CONST_VTBL struct ICorDebugAppDomainVtbl *lpVtbl;
    };
#line 5294
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0026_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0026_v0_0_s_ifspec;
#line 5307
 const IID IID_ICorDebugAppDomain2;
#line 5331
    typedef struct ICorDebugAppDomain2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAppDomain2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAppDomain2 * This);

        ULONG ( *Release )(
            ICorDebugAppDomain2 * This);

        HRESULT ( *GetArrayOrPointerType )(
            ICorDebugAppDomain2 * This,
              CorElementType elementType,
              ULONG32 nRank,
              ICorDebugType *pTypeArg,
              ICorDebugType **ppType);

        HRESULT ( *GetFunctionPointerType )(
            ICorDebugAppDomain2 * This,
              ULONG32 nTypeArgs,
              ICorDebugType *ppTypeArgs[  ],
              ICorDebugType **ppType);


    } ICorDebugAppDomain2Vtbl;

    struct ICorDebugAppDomain2
    {
        CONST_VTBL struct ICorDebugAppDomain2Vtbl *lpVtbl;
    };
#line 5407
 const IID IID_ICorDebugEnum;
#line 5431
    typedef struct ICorDebugEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugEnum * This);

        ULONG ( *Release )(
            ICorDebugEnum * This);

        HRESULT ( *Skip )(
            ICorDebugEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugEnum * This);

        HRESULT ( *Clone )(
            ICorDebugEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugEnum * This,
              ULONG *pcelt);


    } ICorDebugEnumVtbl;

    struct ICorDebugEnum
    {
        CONST_VTBL struct ICorDebugEnumVtbl *lpVtbl;
    };
#line 5515
 const IID IID_ICorDebugGuidToTypeEnum;
#line 5533
    typedef struct ICorDebugGuidToTypeEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugGuidToTypeEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugGuidToTypeEnum * This);

        ULONG ( *Release )(
            ICorDebugGuidToTypeEnum * This);

        HRESULT ( *Skip )(
            ICorDebugGuidToTypeEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugGuidToTypeEnum * This);

        HRESULT ( *Clone )(
            ICorDebugGuidToTypeEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugGuidToTypeEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugGuidToTypeEnum * This,
              ULONG celt,
              CorDebugGuidToTypeMapping values[  ],
              ULONG *pceltFetched);


    } ICorDebugGuidToTypeEnumVtbl;

    struct ICorDebugGuidToTypeEnum
    {
        CONST_VTBL struct ICorDebugGuidToTypeEnumVtbl *lpVtbl;
    };
#line 5627
 const IID IID_ICorDebugAppDomain3;
#line 5648
    typedef struct ICorDebugAppDomain3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAppDomain3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAppDomain3 * This);

        ULONG ( *Release )(
            ICorDebugAppDomain3 * This);

        HRESULT ( *GetCachedWinRTTypesForIIDs )(
            ICorDebugAppDomain3 * This,
              ULONG32 cReqTypes,
              GUID *iidsToResolve,
              ICorDebugTypeEnum **ppTypesEnum);

        HRESULT ( *GetCachedWinRTTypes )(
            ICorDebugAppDomain3 * This,
              ICorDebugGuidToTypeEnum **ppGuidToTypeEnum);


    } ICorDebugAppDomain3Vtbl;

    struct ICorDebugAppDomain3
    {
        CONST_VTBL struct ICorDebugAppDomain3Vtbl *lpVtbl;
    };
#line 5721
 const IID IID_ICorDebugAppDomain4;
#line 5738
    typedef struct ICorDebugAppDomain4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAppDomain4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAppDomain4 * This);

        ULONG ( *Release )(
            ICorDebugAppDomain4 * This);

        HRESULT ( *GetObjectForCCW )(
            ICorDebugAppDomain4 * This,
              CORDB_ADDRESS ccwPointer,
              ICorDebugValue **ppManagedObject);


    } ICorDebugAppDomain4Vtbl;

    struct ICorDebugAppDomain4
    {
        CONST_VTBL struct ICorDebugAppDomain4Vtbl *lpVtbl;
    };
#line 5799
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0030_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0030_v0_0_s_ifspec;
#line 5813
 const IID IID_ICorDebugAssembly;
#line 5845
    typedef struct ICorDebugAssemblyVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAssembly * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAssembly * This);

        ULONG ( *Release )(
            ICorDebugAssembly * This);

        HRESULT ( *GetProcess )(
            ICorDebugAssembly * This,
              ICorDebugProcess **ppProcess);

        HRESULT ( *GetAppDomain )(
            ICorDebugAssembly * This,
              ICorDebugAppDomain **ppAppDomain);

        HRESULT ( *EnumerateModules )(
            ICorDebugAssembly * This,
              ICorDebugModuleEnum **ppModules);

        HRESULT ( *GetCodeBase )(
            ICorDebugAssembly * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetName )(
            ICorDebugAssembly * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);


    } ICorDebugAssemblyVtbl;

    struct ICorDebugAssembly
    {
        CONST_VTBL struct ICorDebugAssemblyVtbl *lpVtbl;
    };
#line 5937
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0031_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0031_v0_0_s_ifspec;
#line 5950
 const IID IID_ICorDebugAssembly2;
#line 5966
    typedef struct ICorDebugAssembly2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAssembly2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAssembly2 * This);

        ULONG ( *Release )(
            ICorDebugAssembly2 * This);

        HRESULT ( *IsFullyTrusted )(
            ICorDebugAssembly2 * This,
              BOOL *pbFullyTrusted);


    } ICorDebugAssembly2Vtbl;

    struct ICorDebugAssembly2
    {
        CONST_VTBL struct ICorDebugAssembly2Vtbl *lpVtbl;
    };
#line 6030
 const IID IID_ICorDebugAssembly3;
#line 6049
    typedef struct ICorDebugAssembly3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAssembly3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAssembly3 * This);

        ULONG ( *Release )(
            ICorDebugAssembly3 * This);

        HRESULT ( *GetContainerAssembly )(
            ICorDebugAssembly3 * This,
            ICorDebugAssembly **ppAssembly);

        HRESULT ( *EnumerateContainedAssemblies )(
            ICorDebugAssembly3 * This,
            ICorDebugAssemblyEnum **ppAssemblies);


    } ICorDebugAssembly3Vtbl;

    struct ICorDebugAssembly3
    {
        CONST_VTBL struct ICorDebugAssembly3Vtbl *lpVtbl;
    };
#line 6118
typedef struct COR_TYPEID
    {
    UINT64 token1;
    UINT64 token2;
    } 	COR_TYPEID;


typedef struct _COR_HEAPOBJECT
    {
    CORDB_ADDRESS address;
    ULONG64 size;
    COR_TYPEID type;
    } 	COR_HEAPOBJECT;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0033_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0033_v0_0_s_ifspec;
#line 6144
 const IID IID_ICorDebugHeapEnum;
#line 6162
    typedef struct ICorDebugHeapEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHeapEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHeapEnum * This);

        ULONG ( *Release )(
            ICorDebugHeapEnum * This);

        HRESULT ( *Skip )(
            ICorDebugHeapEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugHeapEnum * This);

        HRESULT ( *Clone )(
            ICorDebugHeapEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugHeapEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugHeapEnum * This,
              ULONG celt,
              COR_HEAPOBJECT objects[  ],
              ULONG *pceltFetched);


    } ICorDebugHeapEnumVtbl;

    struct ICorDebugHeapEnum
    {
        CONST_VTBL struct ICorDebugHeapEnumVtbl *lpVtbl;
    };
#line 6252
typedef
enum CorDebugGenerationTypes
    {
        CorDebug_Gen0	= 0,
        CorDebug_Gen1	= 1,
        CorDebug_Gen2	= 2,
        CorDebug_LOH	= 3,
        CorDebug_POH	= 4
    } 	CorDebugGenerationTypes;

typedef struct _COR_SEGMENT
    {
    CORDB_ADDRESS start;
    CORDB_ADDRESS end;
    CorDebugGenerationTypes type;
    ULONG heap;
    } 	COR_SEGMENT;

typedef
enum CorDebugGCType
    {
        CorDebugWorkstationGC	= 0,
        CorDebugServerGC	= ( CorDebugWorkstationGC + 1 )
    } 	CorDebugGCType;

typedef struct _COR_HEAPINFO
    {
    BOOL areGCStructuresValid;
    DWORD pointerSize;
    DWORD numHeaps;
    BOOL concurrent;
    CorDebugGCType gcType;
    } 	COR_HEAPINFO;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0034_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0034_v0_0_s_ifspec;
#line 6298
 const IID IID_ICorDebugHeapSegmentEnum;
#line 6316
    typedef struct ICorDebugHeapSegmentEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHeapSegmentEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHeapSegmentEnum * This);

        ULONG ( *Release )(
            ICorDebugHeapSegmentEnum * This);

        HRESULT ( *Skip )(
            ICorDebugHeapSegmentEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugHeapSegmentEnum * This);

        HRESULT ( *Clone )(
            ICorDebugHeapSegmentEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugHeapSegmentEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugHeapSegmentEnum * This,
              ULONG celt,
              COR_SEGMENT segments[  ],
              ULONG *pceltFetched);


    } ICorDebugHeapSegmentEnumVtbl;

    struct ICorDebugHeapSegmentEnum
    {
        CONST_VTBL struct ICorDebugHeapSegmentEnumVtbl *lpVtbl;
    };
#line 6406
typedef
enum CorGCReferenceType
    {
        CorHandleStrong	= ( 1 << 0 ) ,
        CorHandleStrongPinning	= ( 1 << 1 ) ,
        CorHandleWeakShort	= ( 1 << 2 ) ,
        CorHandleWeakLong	= ( 1 << 3 ) ,
        CorHandleWeakRefCount	= ( 1 << 4 ) ,
        CorHandleStrongRefCount	= ( 1 << 5 ) ,
        CorHandleStrongDependent	= ( 1 << 6 ) ,
        CorHandleStrongAsyncPinned	= ( 1 << 7 ) ,
        CorHandleStrongSizedByref	= ( 1 << 8 ) ,
        CorHandleWeakNativeCom	= ( 1 << 9 ) ,
        CorHandleWeakWinRT	= CorHandleWeakNativeCom,
        CorReferenceStack	= 0x80000001,
        CorReferenceFinalizer	= 80000002,
        CorHandleStrongOnly	= 0x1e3,
        CorHandleWeakOnly	= 0x21c,
        CorHandleAll	= 0x7fffffff
    } 	CorGCReferenceType;



typedef struct COR_GC_REFERENCE
    {
    ICorDebugAppDomain *Domain;
    ICorDebugValue *Location;
    CorGCReferenceType Type;
    UINT64 ExtraData;
    } 	COR_GC_REFERENCE;




extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0035_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0035_v0_0_s_ifspec;
#line 6450
 const IID IID_ICorDebugGCReferenceEnum;
#line 6468
    typedef struct ICorDebugGCReferenceEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugGCReferenceEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugGCReferenceEnum * This);

        ULONG ( *Release )(
            ICorDebugGCReferenceEnum * This);

        HRESULT ( *Skip )(
            ICorDebugGCReferenceEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugGCReferenceEnum * This);

        HRESULT ( *Clone )(
            ICorDebugGCReferenceEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugGCReferenceEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugGCReferenceEnum * This,
              ULONG celt,
              COR_GC_REFERENCE roots[  ],
              ULONG *pceltFetched);


    } ICorDebugGCReferenceEnumVtbl;

    struct ICorDebugGCReferenceEnum
    {
        CONST_VTBL struct ICorDebugGCReferenceEnumVtbl *lpVtbl;
    };
#line 6560
typedef struct COR_ARRAY_LAYOUT
    {
    COR_TYPEID componentID;
    CorElementType componentType;
    ULONG32 firstElementOffset;
    ULONG32 elementSize;
    ULONG32 countOffset;
    ULONG32 rankSize;
    ULONG32 numRanks;
    ULONG32 rankOffset;
    } 	COR_ARRAY_LAYOUT;




typedef struct COR_TYPE_LAYOUT
    {
    COR_TYPEID parentID;
    ULONG32 objectSize;
    ULONG32 numFields;
    ULONG32 boxOffset;
    CorElementType type;
    } 	COR_TYPE_LAYOUT;




typedef struct COR_FIELD
    {
    mdFieldDef token;
    ULONG32 offset;
    COR_TYPEID id;
    CorElementType fieldType;
    } 	COR_FIELD;


#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0036_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0036_v0_0_s_ifspec;
#line 6610
 const IID IID_ICorDebugProcess;
#line 6690
    typedef struct ICorDebugProcessVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess * This);

        ULONG ( *Release )(
            ICorDebugProcess * This);

        HRESULT ( *Stop )(
            ICorDebugProcess * This,
              DWORD dwTimeoutIgnored);

        HRESULT ( *Continue )(
            ICorDebugProcess * This,
              BOOL fIsOutOfBand);

        HRESULT ( *IsRunning )(
            ICorDebugProcess * This,
              BOOL *pbRunning);

        HRESULT ( *HasQueuedCallbacks )(
            ICorDebugProcess * This,
              ICorDebugThread *pThread,
              BOOL *pbQueued);

        HRESULT ( *EnumerateThreads )(
            ICorDebugProcess * This,
              ICorDebugThreadEnum **ppThreads);

        HRESULT ( *SetAllThreadsDebugState )(
            ICorDebugProcess * This,
              CorDebugThreadState state,
              ICorDebugThread *pExceptThisThread);

        HRESULT ( *Detach )(
            ICorDebugProcess * This);

        HRESULT ( *Terminate )(
            ICorDebugProcess * This,
              UINT exitCode);

        HRESULT ( *CanCommitChanges )(
            ICorDebugProcess * This,
              ULONG cSnapshots,
              ICorDebugEditAndContinueSnapshot *pSnapshots[  ],
              ICorDebugErrorInfoEnum **pError);

        HRESULT ( *CommitChanges )(
            ICorDebugProcess * This,
              ULONG cSnapshots,
              ICorDebugEditAndContinueSnapshot *pSnapshots[  ],
              ICorDebugErrorInfoEnum **pError);

        HRESULT ( *GetID )(
            ICorDebugProcess * This,
              DWORD *pdwProcessId);

        HRESULT ( *GetHandle )(
            ICorDebugProcess * This,
              HPROCESS *phProcessHandle);

        HRESULT ( *GetThread )(
            ICorDebugProcess * This,
              DWORD dwThreadId,
              ICorDebugThread **ppThread);

        HRESULT ( *EnumerateObjects )(
            ICorDebugProcess * This,
              ICorDebugObjectEnum **ppObjects);

        HRESULT ( *IsTransitionStub )(
            ICorDebugProcess * This,
              CORDB_ADDRESS address,
              BOOL *pbTransitionStub);

        HRESULT ( *IsOSSuspended )(
            ICorDebugProcess * This,
              DWORD threadID,
              BOOL *pbSuspended);

        HRESULT ( *GetThreadContext )(
            ICorDebugProcess * This,
              DWORD threadID,
              ULONG32 contextSize,
              BYTE context[  ]);

        HRESULT ( *SetThreadContext )(
            ICorDebugProcess * This,
              DWORD threadID,
              ULONG32 contextSize,
              BYTE context[  ]);

        HRESULT ( *ReadMemory )(
            ICorDebugProcess * This,
              CORDB_ADDRESS address,
              DWORD size,
              BYTE buffer[  ],
              SIZE_T *read);

        HRESULT ( *WriteMemory )(
            ICorDebugProcess * This,
              CORDB_ADDRESS address,
              DWORD size,
              BYTE buffer[  ],
              SIZE_T *written);

        HRESULT ( *ClearCurrentException )(
            ICorDebugProcess * This,
              DWORD threadID);

        HRESULT ( *EnableLogMessages )(
            ICorDebugProcess * This,
              BOOL fOnOff);

        HRESULT ( *ModifyLogSwitch )(
            ICorDebugProcess * This,

            _In_  WCHAR *pLogSwitchName,
              LONG lLevel);

        HRESULT ( *EnumerateAppDomains )(
            ICorDebugProcess * This,
              ICorDebugAppDomainEnum **ppAppDomains);

        HRESULT ( *GetObject )(
            ICorDebugProcess * This,
              ICorDebugValue **ppObject);

        HRESULT ( *ThreadForFiberCookie )(
            ICorDebugProcess * This,
              DWORD fiberCookie,
              ICorDebugThread **ppThread);

        HRESULT ( *GetHelperThreadID )(
            ICorDebugProcess * This,
              DWORD *pThreadID);


    } ICorDebugProcessVtbl;

    struct ICorDebugProcess
    {
        CONST_VTBL struct ICorDebugProcessVtbl *lpVtbl;
    };
#line 6954
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0037_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0037_v0_0_s_ifspec;
#line 6967
 const IID IID_ICorDebugProcess2;
#line 7006
    typedef struct ICorDebugProcess2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess2 * This);

        ULONG ( *Release )(
            ICorDebugProcess2 * This);

        HRESULT ( *GetThreadForTaskID )(
            ICorDebugProcess2 * This,
              TASKID taskid,
              ICorDebugThread2 **ppThread);

        HRESULT ( *GetVersion )(
            ICorDebugProcess2 * This,
              COR_VERSION *version);

        HRESULT ( *SetUnmanagedBreakpoint )(
            ICorDebugProcess2 * This,
              CORDB_ADDRESS address,
              ULONG32 bufsize,
              BYTE buffer[  ],
              ULONG32 *bufLen);

        HRESULT ( *ClearUnmanagedBreakpoint )(
            ICorDebugProcess2 * This,
              CORDB_ADDRESS address);

        HRESULT ( *SetDesiredNGENCompilerFlags )(
            ICorDebugProcess2 * This,
              DWORD pdwFlags);

        HRESULT ( *GetDesiredNGENCompilerFlags )(
            ICorDebugProcess2 * This,
              DWORD *pdwFlags);

        HRESULT ( *GetReferenceValueFromGCHandle )(
            ICorDebugProcess2 * This,
              UINT_PTR handle,
              ICorDebugReferenceValue **pOutValue);


    } ICorDebugProcess2Vtbl;

    struct ICorDebugProcess2
    {
        CONST_VTBL struct ICorDebugProcess2Vtbl *lpVtbl;
    };
#line 7117
 const IID IID_ICorDebugProcess3;
#line 7134
    typedef struct ICorDebugProcess3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess3 * This);

        ULONG ( *Release )(
            ICorDebugProcess3 * This);

        HRESULT ( *SetEnableCustomNotification )(
            ICorDebugProcess3 * This,
            ICorDebugClass *pClass,
            BOOL fEnable);


    } ICorDebugProcess3Vtbl;

    struct ICorDebugProcess3
    {
        CONST_VTBL struct ICorDebugProcess3Vtbl *lpVtbl;
    };
#line 7199
 const IID IID_ICorDebugProcess5;
#line 7258
    typedef struct ICorDebugProcess5Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess5 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess5 * This);

        ULONG ( *Release )(
            ICorDebugProcess5 * This);

        HRESULT ( *GetGCHeapInformation )(
            ICorDebugProcess5 * This,
              COR_HEAPINFO *pHeapInfo);

        HRESULT ( *EnumerateHeap )(
            ICorDebugProcess5 * This,
              ICorDebugHeapEnum **ppObjects);

        HRESULT ( *EnumerateHeapRegions )(
            ICorDebugProcess5 * This,
              ICorDebugHeapSegmentEnum **ppRegions);

        HRESULT ( *GetObject )(
            ICorDebugProcess5 * This,
              CORDB_ADDRESS addr,
              ICorDebugObjectValue **pObject);

        HRESULT ( *EnumerateGCReferences )(
            ICorDebugProcess5 * This,
              BOOL enumerateWeakReferences,
              ICorDebugGCReferenceEnum **ppEnum);

        HRESULT ( *EnumerateHandles )(
            ICorDebugProcess5 * This,
              CorGCReferenceType types,
              ICorDebugGCReferenceEnum **ppEnum);

        HRESULT ( *GetTypeID )(
            ICorDebugProcess5 * This,
              CORDB_ADDRESS obj,
              COR_TYPEID *pId);

        HRESULT ( *GetTypeForTypeID )(
            ICorDebugProcess5 * This,
              COR_TYPEID id,
              ICorDebugType **ppType);

        HRESULT ( *GetArrayLayout )(
            ICorDebugProcess5 * This,
              COR_TYPEID id,
              COR_ARRAY_LAYOUT *pLayout);

        HRESULT ( *GetTypeLayout )(
            ICorDebugProcess5 * This,
              COR_TYPEID id,
              COR_TYPE_LAYOUT *pLayout);

        HRESULT ( *GetTypeFields )(
            ICorDebugProcess5 * This,
              COR_TYPEID id,
            ULONG32 celt,
            COR_FIELD fields[  ],
            ULONG32 *pceltNeeded);

        HRESULT ( *EnableNGENPolicy )(
            ICorDebugProcess5 * This,
              CorDebugNGENPolicy ePolicy);


    } ICorDebugProcess5Vtbl;

    struct ICorDebugProcess5
    {
        CONST_VTBL struct ICorDebugProcess5Vtbl *lpVtbl;
    };
#line 7405
typedef
enum CorDebugRecordFormat
    {
        FORMAT_WINDOWS_EXCEPTIONRECORD32	= 1,
        FORMAT_WINDOWS_EXCEPTIONRECORD64	= 2
    } 	CorDebugRecordFormat;

typedef
enum CorDebugDecodeEventFlagsWindows
    {
        IS_FIRST_CHANCE	= 1
    } 	CorDebugDecodeEventFlagsWindows;

typedef
enum CorDebugDebugEventKind
    {
        DEBUG_EVENT_KIND_MODULE_LOADED	= 1,
        DEBUG_EVENT_KIND_MODULE_UNLOADED	= 2,
        DEBUG_EVENT_KIND_MANAGED_EXCEPTION_FIRST_CHANCE	= 3,
        DEBUG_EVENT_KIND_MANAGED_EXCEPTION_USER_FIRST_CHANCE	= 4,
        DEBUG_EVENT_KIND_MANAGED_EXCEPTION_CATCH_HANDLER_FOUND	= 5,
        DEBUG_EVENT_KIND_MANAGED_EXCEPTION_UNHANDLED	= 6
    } 	CorDebugDebugEventKind;

typedef
enum CorDebugStateChange
    {
        PROCESS_RUNNING	= 0x1,
        FLUSH_ALL	= 0x2
    } 	CorDebugStateChange;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0040_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0040_v0_0_s_ifspec;
#line 7448
 const IID IID_ICorDebugDebugEvent;
#line 7467
    typedef struct ICorDebugDebugEventVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugDebugEvent * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugDebugEvent * This);

        ULONG ( *Release )(
            ICorDebugDebugEvent * This);

        HRESULT ( *GetEventKind )(
            ICorDebugDebugEvent * This,
              CorDebugDebugEventKind *pDebugEventKind);

        HRESULT ( *GetThread )(
            ICorDebugDebugEvent * This,
              ICorDebugThread **ppThread);


    } ICorDebugDebugEventVtbl;

    struct ICorDebugDebugEvent
    {
        CONST_VTBL struct ICorDebugDebugEventVtbl *lpVtbl;
    };
#line 7534
typedef
enum CorDebugCodeInvokeKind
    {
        CODE_INVOKE_KIND_NONE	= 0,
        CODE_INVOKE_KIND_RETURN	= ( CODE_INVOKE_KIND_NONE + 1 ) ,
        CODE_INVOKE_KIND_TAILCALL	= ( CODE_INVOKE_KIND_RETURN + 1 )
    } 	CorDebugCodeInvokeKind;

typedef
enum CorDebugCodeInvokePurpose
    {
        CODE_INVOKE_PURPOSE_NONE	= 0,
        CODE_INVOKE_PURPOSE_NATIVE_TO_MANAGED_TRANSITION	= ( CODE_INVOKE_PURPOSE_NONE + 1 ) ,
        CODE_INVOKE_PURPOSE_CLASS_INIT	= ( CODE_INVOKE_PURPOSE_NATIVE_TO_MANAGED_TRANSITION + 1 ) ,
        CODE_INVOKE_PURPOSE_INTERFACE_DISPATCH	= ( CODE_INVOKE_PURPOSE_CLASS_INIT + 1 )
    } 	CorDebugCodeInvokePurpose;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0041_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0041_v0_0_s_ifspec;
#line 7563
 const IID IID_ICorDebugProcess6;
#line 7602
    typedef struct ICorDebugProcess6Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess6 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess6 * This);

        ULONG ( *Release )(
            ICorDebugProcess6 * This);

        HRESULT ( *DecodeEvent )(
            ICorDebugProcess6 * This,
              const BYTE pRecord[  ],
              DWORD countBytes,
              CorDebugRecordFormat format,
              DWORD dwFlags,
              DWORD dwThreadId,
              ICorDebugDebugEvent **ppEvent);

        HRESULT ( *ProcessStateChanged )(
            ICorDebugProcess6 * This,
              CorDebugStateChange change);

        HRESULT ( *GetCode )(
            ICorDebugProcess6 * This,
              CORDB_ADDRESS codeAddress,
              ICorDebugCode **ppCode);

        HRESULT ( *EnableVirtualModuleSplitting )(
            ICorDebugProcess6 * This,
            BOOL enableSplitting);

        HRESULT ( *MarkDebuggerAttached )(
            ICorDebugProcess6 * This,
            BOOL fIsAttached);

        HRESULT ( *GetExportStepInfo )(
            ICorDebugProcess6 * This,
              LPCWSTR pszExportName,
              CorDebugCodeInvokeKind *pInvokeKind,
              CorDebugCodeInvokePurpose *pInvokePurpose);


    } ICorDebugProcess6Vtbl;

    struct ICorDebugProcess6
    {
        CONST_VTBL struct ICorDebugProcess6Vtbl *lpVtbl;
    };
#line 7705
typedef
enum WriteableMetadataUpdateMode
    {
        LegacyCompatPolicy	= 0,
        AlwaysShowUpdates	= ( LegacyCompatPolicy + 1 )
    } 	WriteableMetadataUpdateMode;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0042_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0042_v0_0_s_ifspec;
#line 7724
 const IID IID_ICorDebugProcess7;
#line 7740
    typedef struct ICorDebugProcess7Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess7 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess7 * This);

        ULONG ( *Release )(
            ICorDebugProcess7 * This);

        HRESULT ( *SetWriteableMetadataUpdateMode )(
            ICorDebugProcess7 * This,
            WriteableMetadataUpdateMode flags);


    } ICorDebugProcess7Vtbl;

    struct ICorDebugProcess7
    {
        CONST_VTBL struct ICorDebugProcess7Vtbl *lpVtbl;
    };
#line 7804
 const IID IID_ICorDebugProcess8;
#line 7820
    typedef struct ICorDebugProcess8Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess8 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess8 * This);

        ULONG ( *Release )(
            ICorDebugProcess8 * This);

        HRESULT ( *EnableExceptionCallbacksOutsideOfMyCode )(
            ICorDebugProcess8 * This,
              BOOL enableExceptionsOutsideOfJMC);


    } ICorDebugProcess8Vtbl;

    struct ICorDebugProcess8
    {
        CONST_VTBL struct ICorDebugProcess8Vtbl *lpVtbl;
    };
#line 7884
 const IID IID_ICorDebugProcess10;
#line 7900
    typedef struct ICorDebugProcess10Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess10 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess10 * This);

        ULONG ( *Release )(
            ICorDebugProcess10 * This);

        HRESULT ( *EnableGCNotificationEvents )(
            ICorDebugProcess10 * This,
            BOOL fEnable);


    } ICorDebugProcess10Vtbl;

    struct ICorDebugProcess10
    {
        CONST_VTBL struct ICorDebugProcess10Vtbl *lpVtbl;
    };
#line 7960
typedef struct _COR_MEMORY_RANGE
    {
    CORDB_ADDRESS start;
    CORDB_ADDRESS end;
    } 	COR_MEMORY_RANGE;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0045_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0045_v0_0_s_ifspec;
#line 7978
 const IID IID_ICorDebugMemoryRangeEnum;
#line 7996
    typedef struct ICorDebugMemoryRangeEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugMemoryRangeEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugMemoryRangeEnum * This);

        ULONG ( *Release )(
            ICorDebugMemoryRangeEnum * This);

        HRESULT ( *Skip )(
            ICorDebugMemoryRangeEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugMemoryRangeEnum * This);

        HRESULT ( *Clone )(
            ICorDebugMemoryRangeEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugMemoryRangeEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugMemoryRangeEnum * This,
              ULONG celt,
              COR_MEMORY_RANGE objects[  ],
              ULONG *pceltFetched);


    } ICorDebugMemoryRangeEnumVtbl;

    struct ICorDebugMemoryRangeEnum
    {
        CONST_VTBL struct ICorDebugMemoryRangeEnumVtbl *lpVtbl;
    };
#line 8090
 const IID IID_ICorDebugProcess11;
#line 8106
    typedef struct ICorDebugProcess11Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcess11 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcess11 * This);

        ULONG ( *Release )(
            ICorDebugProcess11 * This);

        HRESULT ( *EnumerateLoaderHeapMemoryRegions )(
            ICorDebugProcess11 * This,
              ICorDebugMemoryRangeEnum **ppRanges);


    } ICorDebugProcess11Vtbl;

    struct ICorDebugProcess11
    {
        CONST_VTBL struct ICorDebugProcess11Vtbl *lpVtbl;
    };
#line 8170
 const IID IID_ICorDebugModuleDebugEvent;
#line 8186
    typedef struct ICorDebugModuleDebugEventVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModuleDebugEvent * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModuleDebugEvent * This);

        ULONG ( *Release )(
            ICorDebugModuleDebugEvent * This);

        HRESULT ( *GetEventKind )(
            ICorDebugModuleDebugEvent * This,
              CorDebugDebugEventKind *pDebugEventKind);

        HRESULT ( *GetThread )(
            ICorDebugModuleDebugEvent * This,
              ICorDebugThread **ppThread);

        HRESULT ( *GetModule )(
            ICorDebugModuleDebugEvent * This,
              ICorDebugModule **ppModule);


    } ICorDebugModuleDebugEventVtbl;

    struct ICorDebugModuleDebugEvent
    {
        CONST_VTBL struct ICorDebugModuleDebugEventVtbl *lpVtbl;
    };
#line 8265
 const IID IID_ICorDebugExceptionDebugEvent;
#line 8287
    typedef struct ICorDebugExceptionDebugEventVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugExceptionDebugEvent * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugExceptionDebugEvent * This);

        ULONG ( *Release )(
            ICorDebugExceptionDebugEvent * This);

        HRESULT ( *GetEventKind )(
            ICorDebugExceptionDebugEvent * This,
              CorDebugDebugEventKind *pDebugEventKind);

        HRESULT ( *GetThread )(
            ICorDebugExceptionDebugEvent * This,
              ICorDebugThread **ppThread);

        HRESULT ( *GetStackPointer )(
            ICorDebugExceptionDebugEvent * This,
              CORDB_ADDRESS *pStackPointer);

        HRESULT ( *GetNativeIP )(
            ICorDebugExceptionDebugEvent * This,
              CORDB_ADDRESS *pIP);

        HRESULT ( *GetFlags )(
            ICorDebugExceptionDebugEvent * This,
              CorDebugExceptionFlags *pdwFlags);


    } ICorDebugExceptionDebugEventVtbl;

    struct ICorDebugExceptionDebugEvent
    {
        CONST_VTBL struct ICorDebugExceptionDebugEventVtbl *lpVtbl;
    };
#line 8380
 const IID IID_ICorDebugBreakpoint;
#line 8399
    typedef struct ICorDebugBreakpointVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugBreakpoint * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugBreakpoint * This);

        ULONG ( *Release )(
            ICorDebugBreakpoint * This);

        HRESULT ( *Activate )(
            ICorDebugBreakpoint * This,
              BOOL bActive);

        HRESULT ( *IsActive )(
            ICorDebugBreakpoint * This,
              BOOL *pbActive);


    } ICorDebugBreakpointVtbl;

    struct ICorDebugBreakpoint
    {
        CONST_VTBL struct ICorDebugBreakpointVtbl *lpVtbl;
    };
#line 8470
 const IID IID_ICorDebugFunctionBreakpoint;
#line 8489
    typedef struct ICorDebugFunctionBreakpointVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFunctionBreakpoint * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFunctionBreakpoint * This);

        ULONG ( *Release )(
            ICorDebugFunctionBreakpoint * This);

        HRESULT ( *Activate )(
            ICorDebugFunctionBreakpoint * This,
              BOOL bActive);

        HRESULT ( *IsActive )(
            ICorDebugFunctionBreakpoint * This,
              BOOL *pbActive);

        HRESULT ( *GetFunction )(
            ICorDebugFunctionBreakpoint * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetOffset )(
            ICorDebugFunctionBreakpoint * This,
              ULONG32 *pnOffset);


    } ICorDebugFunctionBreakpointVtbl;

    struct ICorDebugFunctionBreakpoint
    {
        CONST_VTBL struct ICorDebugFunctionBreakpointVtbl *lpVtbl;
    };
#line 8575
 const IID IID_ICorDebugModuleBreakpoint;
#line 8591
    typedef struct ICorDebugModuleBreakpointVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModuleBreakpoint * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModuleBreakpoint * This);

        ULONG ( *Release )(
            ICorDebugModuleBreakpoint * This);

        HRESULT ( *Activate )(
            ICorDebugModuleBreakpoint * This,
              BOOL bActive);

        HRESULT ( *IsActive )(
            ICorDebugModuleBreakpoint * This,
              BOOL *pbActive);

        HRESULT ( *GetModule )(
            ICorDebugModuleBreakpoint * This,
              ICorDebugModule **ppModule);


    } ICorDebugModuleBreakpointVtbl;

    struct ICorDebugModuleBreakpoint
    {
        CONST_VTBL struct ICorDebugModuleBreakpointVtbl *lpVtbl;
    };
#line 8670
 const IID IID_ICorDebugValueBreakpoint;
#line 8686
    typedef struct ICorDebugValueBreakpointVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugValueBreakpoint * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugValueBreakpoint * This);

        ULONG ( *Release )(
            ICorDebugValueBreakpoint * This);

        HRESULT ( *Activate )(
            ICorDebugValueBreakpoint * This,
              BOOL bActive);

        HRESULT ( *IsActive )(
            ICorDebugValueBreakpoint * This,
              BOOL *pbActive);

        HRESULT ( *GetValue )(
            ICorDebugValueBreakpoint * This,
              ICorDebugValue **ppValue);


    } ICorDebugValueBreakpointVtbl;

    struct ICorDebugValueBreakpoint
    {
        CONST_VTBL struct ICorDebugValueBreakpointVtbl *lpVtbl;
    };
#line 8764
typedef
enum CorDebugIntercept
    {
        INTERCEPT_NONE	= 0,
        INTERCEPT_CLASS_INIT	= 0x1,
        INTERCEPT_EXCEPTION_FILTER	= 0x2,
        INTERCEPT_SECURITY	= 0x4,
        INTERCEPT_CONTEXT_POLICY	= 0x8,
        INTERCEPT_INTERCEPTION	= 0x10,
        INTERCEPT_ALL	= 0xffff
    } 	CorDebugIntercept;

typedef
enum CorDebugUnmappedStop
    {
        STOP_NONE	= 0,
        STOP_PROLOG	= 0x1,
        STOP_EPILOG	= 0x2,
        STOP_NO_MAPPING_INFO	= 0x4,
        STOP_OTHER_UNMAPPED	= 0x8,
        STOP_UNMANAGED	= 0x10,
        STOP_ALL	= 0xffff
    } 	CorDebugUnmappedStop;

typedef struct COR_DEBUG_STEP_RANGE
    {
    ULONG32 startOffset;
    ULONG32 endOffset;
    } 	COR_DEBUG_STEP_RANGE;


 const IID IID_ICorDebugStepper;
#line 8832
    typedef struct ICorDebugStepperVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugStepper * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugStepper * This);

        ULONG ( *Release )(
            ICorDebugStepper * This);

        HRESULT ( *IsActive )(
            ICorDebugStepper * This,
              BOOL *pbActive);

        HRESULT ( *Deactivate )(
            ICorDebugStepper * This);

        HRESULT ( *SetInterceptMask )(
            ICorDebugStepper * This,
              CorDebugIntercept mask);

        HRESULT ( *SetUnmappedStopMask )(
            ICorDebugStepper * This,
              CorDebugUnmappedStop mask);

        HRESULT ( *Step )(
            ICorDebugStepper * This,
              BOOL bStepIn);

        HRESULT ( *StepRange )(
            ICorDebugStepper * This,
              BOOL bStepIn,
              COR_DEBUG_STEP_RANGE ranges[  ],
              ULONG32 cRangeCount);

        HRESULT ( *StepOut )(
            ICorDebugStepper * This);

        HRESULT ( *SetRangeIL )(
            ICorDebugStepper * This,
              BOOL bIL);


    } ICorDebugStepperVtbl;

    struct ICorDebugStepper
    {
        CONST_VTBL struct ICorDebugStepperVtbl *lpVtbl;
    };
#line 8945
 const IID IID_ICorDebugStepper2;
#line 8961
    typedef struct ICorDebugStepper2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugStepper2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugStepper2 * This);

        ULONG ( *Release )(
            ICorDebugStepper2 * This);

        HRESULT ( *SetJMC )(
            ICorDebugStepper2 * This,
              BOOL fIsJMCStepper);


    } ICorDebugStepper2Vtbl;

    struct ICorDebugStepper2
    {
        CONST_VTBL struct ICorDebugStepper2Vtbl *lpVtbl;
    };
#line 9024
typedef
enum CorDebugRegister
    {
        REGISTER_INSTRUCTION_POINTER	= 0,
        REGISTER_STACK_POINTER	= ( REGISTER_INSTRUCTION_POINTER + 1 ) ,
        REGISTER_FRAME_POINTER	= ( REGISTER_STACK_POINTER + 1 ) ,
        REGISTER_X86_EIP	= 0,
        REGISTER_X86_ESP	= ( REGISTER_X86_EIP + 1 ) ,
        REGISTER_X86_EBP	= ( REGISTER_X86_ESP + 1 ) ,
        REGISTER_X86_EAX	= ( REGISTER_X86_EBP + 1 ) ,
        REGISTER_X86_ECX	= ( REGISTER_X86_EAX + 1 ) ,
        REGISTER_X86_EDX	= ( REGISTER_X86_ECX + 1 ) ,
        REGISTER_X86_EBX	= ( REGISTER_X86_EDX + 1 ) ,
        REGISTER_X86_ESI	= ( REGISTER_X86_EBX + 1 ) ,
        REGISTER_X86_EDI	= ( REGISTER_X86_ESI + 1 ) ,
        REGISTER_X86_FPSTACK_0	= ( REGISTER_X86_EDI + 1 ) ,
        REGISTER_X86_FPSTACK_1	= ( REGISTER_X86_FPSTACK_0 + 1 ) ,
        REGISTER_X86_FPSTACK_2	= ( REGISTER_X86_FPSTACK_1 + 1 ) ,
        REGISTER_X86_FPSTACK_3	= ( REGISTER_X86_FPSTACK_2 + 1 ) ,
        REGISTER_X86_FPSTACK_4	= ( REGISTER_X86_FPSTACK_3 + 1 ) ,
        REGISTER_X86_FPSTACK_5	= ( REGISTER_X86_FPSTACK_4 + 1 ) ,
        REGISTER_X86_FPSTACK_6	= ( REGISTER_X86_FPSTACK_5 + 1 ) ,
        REGISTER_X86_FPSTACK_7	= ( REGISTER_X86_FPSTACK_6 + 1 ) ,
        REGISTER_AMD64_RIP	= 0,
        REGISTER_AMD64_RSP	= ( REGISTER_AMD64_RIP + 1 ) ,
        REGISTER_AMD64_RBP	= ( REGISTER_AMD64_RSP + 1 ) ,
        REGISTER_AMD64_RAX	= ( REGISTER_AMD64_RBP + 1 ) ,
        REGISTER_AMD64_RCX	= ( REGISTER_AMD64_RAX + 1 ) ,
        REGISTER_AMD64_RDX	= ( REGISTER_AMD64_RCX + 1 ) ,
        REGISTER_AMD64_RBX	= ( REGISTER_AMD64_RDX + 1 ) ,
        REGISTER_AMD64_RSI	= ( REGISTER_AMD64_RBX + 1 ) ,
        REGISTER_AMD64_RDI	= ( REGISTER_AMD64_RSI + 1 ) ,
        REGISTER_AMD64_R8	= ( REGISTER_AMD64_RDI + 1 ) ,
        REGISTER_AMD64_R9	= ( REGISTER_AMD64_R8 + 1 ) ,
        REGISTER_AMD64_R10	= ( REGISTER_AMD64_R9 + 1 ) ,
        REGISTER_AMD64_R11	= ( REGISTER_AMD64_R10 + 1 ) ,
        REGISTER_AMD64_R12	= ( REGISTER_AMD64_R11 + 1 ) ,
        REGISTER_AMD64_R13	= ( REGISTER_AMD64_R12 + 1 ) ,
        REGISTER_AMD64_R14	= ( REGISTER_AMD64_R13 + 1 ) ,
        REGISTER_AMD64_R15	= ( REGISTER_AMD64_R14 + 1 ) ,
        REGISTER_AMD64_XMM0	= ( REGISTER_AMD64_R15 + 1 ) ,
        REGISTER_AMD64_XMM1	= ( REGISTER_AMD64_XMM0 + 1 ) ,
        REGISTER_AMD64_XMM2	= ( REGISTER_AMD64_XMM1 + 1 ) ,
        REGISTER_AMD64_XMM3	= ( REGISTER_AMD64_XMM2 + 1 ) ,
        REGISTER_AMD64_XMM4	= ( REGISTER_AMD64_XMM3 + 1 ) ,
        REGISTER_AMD64_XMM5	= ( REGISTER_AMD64_XMM4 + 1 ) ,
        REGISTER_AMD64_XMM6	= ( REGISTER_AMD64_XMM5 + 1 ) ,
        REGISTER_AMD64_XMM7	= ( REGISTER_AMD64_XMM6 + 1 ) ,
        REGISTER_AMD64_XMM8	= ( REGISTER_AMD64_XMM7 + 1 ) ,
        REGISTER_AMD64_XMM9	= ( REGISTER_AMD64_XMM8 + 1 ) ,
        REGISTER_AMD64_XMM10	= ( REGISTER_AMD64_XMM9 + 1 ) ,
        REGISTER_AMD64_XMM11	= ( REGISTER_AMD64_XMM10 + 1 ) ,
        REGISTER_AMD64_XMM12	= ( REGISTER_AMD64_XMM11 + 1 ) ,
        REGISTER_AMD64_XMM13	= ( REGISTER_AMD64_XMM12 + 1 ) ,
        REGISTER_AMD64_XMM14	= ( REGISTER_AMD64_XMM13 + 1 ) ,
        REGISTER_AMD64_XMM15	= ( REGISTER_AMD64_XMM14 + 1 ) ,
        REGISTER_IA64_BSP	= REGISTER_FRAME_POINTER,
        REGISTER_IA64_R0	= ( REGISTER_IA64_BSP + 1 ) ,
        REGISTER_IA64_F0	= ( REGISTER_IA64_R0 + 128 ) ,
        REGISTER_ARM_PC	= 0,
        REGISTER_ARM_SP	= ( REGISTER_ARM_PC + 1 ) ,
        REGISTER_ARM_R0	= ( REGISTER_ARM_SP + 1 ) ,
        REGISTER_ARM_R1	= ( REGISTER_ARM_R0 + 1 ) ,
        REGISTER_ARM_R2	= ( REGISTER_ARM_R1 + 1 ) ,
        REGISTER_ARM_R3	= ( REGISTER_ARM_R2 + 1 ) ,
        REGISTER_ARM_R4	= ( REGISTER_ARM_R3 + 1 ) ,
        REGISTER_ARM_R5	= ( REGISTER_ARM_R4 + 1 ) ,
        REGISTER_ARM_R6	= ( REGISTER_ARM_R5 + 1 ) ,
        REGISTER_ARM_R7	= ( REGISTER_ARM_R6 + 1 ) ,
        REGISTER_ARM_R8	= ( REGISTER_ARM_R7 + 1 ) ,
        REGISTER_ARM_R9	= ( REGISTER_ARM_R8 + 1 ) ,
        REGISTER_ARM_R10	= ( REGISTER_ARM_R9 + 1 ) ,
        REGISTER_ARM_R11	= ( REGISTER_ARM_R10 + 1 ) ,
        REGISTER_ARM_R12	= ( REGISTER_ARM_R11 + 1 ) ,
        REGISTER_ARM_LR	= ( REGISTER_ARM_R12 + 1 ) ,
        REGISTER_ARM_D0	= ( REGISTER_ARM_LR + 1 ) ,
        REGISTER_ARM_D1	= ( REGISTER_ARM_D0 + 1 ) ,
        REGISTER_ARM_D2	= ( REGISTER_ARM_D1 + 1 ) ,
        REGISTER_ARM_D3	= ( REGISTER_ARM_D2 + 1 ) ,
        REGISTER_ARM_D4	= ( REGISTER_ARM_D3 + 1 ) ,
        REGISTER_ARM_D5	= ( REGISTER_ARM_D4 + 1 ) ,
        REGISTER_ARM_D6	= ( REGISTER_ARM_D5 + 1 ) ,
        REGISTER_ARM_D7	= ( REGISTER_ARM_D6 + 1 ) ,
        REGISTER_ARM_D8	= ( REGISTER_ARM_D7 + 1 ) ,
        REGISTER_ARM_D9	= ( REGISTER_ARM_D8 + 1 ) ,
        REGISTER_ARM_D10	= ( REGISTER_ARM_D9 + 1 ) ,
        REGISTER_ARM_D11	= ( REGISTER_ARM_D10 + 1 ) ,
        REGISTER_ARM_D12	= ( REGISTER_ARM_D11 + 1 ) ,
        REGISTER_ARM_D13	= ( REGISTER_ARM_D12 + 1 ) ,
        REGISTER_ARM_D14	= ( REGISTER_ARM_D13 + 1 ) ,
        REGISTER_ARM_D15	= ( REGISTER_ARM_D14 + 1 ) ,
        REGISTER_ARM_D16	= ( REGISTER_ARM_D15 + 1 ) ,
        REGISTER_ARM_D17	= ( REGISTER_ARM_D16 + 1 ) ,
        REGISTER_ARM_D18	= ( REGISTER_ARM_D17 + 1 ) ,
        REGISTER_ARM_D19	= ( REGISTER_ARM_D18 + 1 ) ,
        REGISTER_ARM_D20	= ( REGISTER_ARM_D19 + 1 ) ,
        REGISTER_ARM_D21	= ( REGISTER_ARM_D20 + 1 ) ,
        REGISTER_ARM_D22	= ( REGISTER_ARM_D21 + 1 ) ,
        REGISTER_ARM_D23	= ( REGISTER_ARM_D22 + 1 ) ,
        REGISTER_ARM_D24	= ( REGISTER_ARM_D23 + 1 ) ,
        REGISTER_ARM_D25	= ( REGISTER_ARM_D24 + 1 ) ,
        REGISTER_ARM_D26	= ( REGISTER_ARM_D25 + 1 ) ,
        REGISTER_ARM_D27	= ( REGISTER_ARM_D26 + 1 ) ,
        REGISTER_ARM_D28	= ( REGISTER_ARM_D27 + 1 ) ,
        REGISTER_ARM_D29	= ( REGISTER_ARM_D28 + 1 ) ,
        REGISTER_ARM_D30	= ( REGISTER_ARM_D29 + 1 ) ,
        REGISTER_ARM_D31	= ( REGISTER_ARM_D30 + 1 ) ,
        REGISTER_ARM64_PC	= 0,
        REGISTER_ARM64_SP	= ( REGISTER_ARM64_PC + 1 ) ,
        REGISTER_ARM64_FP	= ( REGISTER_ARM64_SP + 1 ) ,
        REGISTER_ARM64_X0	= ( REGISTER_ARM64_FP + 1 ) ,
        REGISTER_ARM64_X1	= ( REGISTER_ARM64_X0 + 1 ) ,
        REGISTER_ARM64_X2	= ( REGISTER_ARM64_X1 + 1 ) ,
        REGISTER_ARM64_X3	= ( REGISTER_ARM64_X2 + 1 ) ,
        REGISTER_ARM64_X4	= ( REGISTER_ARM64_X3 + 1 ) ,
        REGISTER_ARM64_X5	= ( REGISTER_ARM64_X4 + 1 ) ,
        REGISTER_ARM64_X6	= ( REGISTER_ARM64_X5 + 1 ) ,
        REGISTER_ARM64_X7	= ( REGISTER_ARM64_X6 + 1 ) ,
        REGISTER_ARM64_X8	= ( REGISTER_ARM64_X7 + 1 ) ,
        REGISTER_ARM64_X9	= ( REGISTER_ARM64_X8 + 1 ) ,
        REGISTER_ARM64_X10	= ( REGISTER_ARM64_X9 + 1 ) ,
        REGISTER_ARM64_X11	= ( REGISTER_ARM64_X10 + 1 ) ,
        REGISTER_ARM64_X12	= ( REGISTER_ARM64_X11 + 1 ) ,
        REGISTER_ARM64_X13	= ( REGISTER_ARM64_X12 + 1 ) ,
        REGISTER_ARM64_X14	= ( REGISTER_ARM64_X13 + 1 ) ,
        REGISTER_ARM64_X15	= ( REGISTER_ARM64_X14 + 1 ) ,
        REGISTER_ARM64_X16	= ( REGISTER_ARM64_X15 + 1 ) ,
        REGISTER_ARM64_X17	= ( REGISTER_ARM64_X16 + 1 ) ,
        REGISTER_ARM64_X18	= ( REGISTER_ARM64_X17 + 1 ) ,
        REGISTER_ARM64_X19	= ( REGISTER_ARM64_X18 + 1 ) ,
        REGISTER_ARM64_X20	= ( REGISTER_ARM64_X19 + 1 ) ,
        REGISTER_ARM64_X21	= ( REGISTER_ARM64_X20 + 1 ) ,
        REGISTER_ARM64_X22	= ( REGISTER_ARM64_X21 + 1 ) ,
        REGISTER_ARM64_X23	= ( REGISTER_ARM64_X22 + 1 ) ,
        REGISTER_ARM64_X24	= ( REGISTER_ARM64_X23 + 1 ) ,
        REGISTER_ARM64_X25	= ( REGISTER_ARM64_X24 + 1 ) ,
        REGISTER_ARM64_X26	= ( REGISTER_ARM64_X25 + 1 ) ,
        REGISTER_ARM64_X27	= ( REGISTER_ARM64_X26 + 1 ) ,
        REGISTER_ARM64_X28	= ( REGISTER_ARM64_X27 + 1 ) ,
        REGISTER_ARM64_LR	= ( REGISTER_ARM64_X28 + 1 ) ,
        REGISTER_ARM64_V0	= ( REGISTER_ARM64_LR + 1 ) ,
        REGISTER_ARM64_V1	= ( REGISTER_ARM64_V0 + 1 ) ,
        REGISTER_ARM64_V2	= ( REGISTER_ARM64_V1 + 1 ) ,
        REGISTER_ARM64_V3	= ( REGISTER_ARM64_V2 + 1 ) ,
        REGISTER_ARM64_V4	= ( REGISTER_ARM64_V3 + 1 ) ,
        REGISTER_ARM64_V5	= ( REGISTER_ARM64_V4 + 1 ) ,
        REGISTER_ARM64_V6	= ( REGISTER_ARM64_V5 + 1 ) ,
        REGISTER_ARM64_V7	= ( REGISTER_ARM64_V6 + 1 ) ,
        REGISTER_ARM64_V8	= ( REGISTER_ARM64_V7 + 1 ) ,
        REGISTER_ARM64_V9	= ( REGISTER_ARM64_V8 + 1 ) ,
        REGISTER_ARM64_V10	= ( REGISTER_ARM64_V9 + 1 ) ,
        REGISTER_ARM64_V11	= ( REGISTER_ARM64_V10 + 1 ) ,
        REGISTER_ARM64_V12	= ( REGISTER_ARM64_V11 + 1 ) ,
        REGISTER_ARM64_V13	= ( REGISTER_ARM64_V12 + 1 ) ,
        REGISTER_ARM64_V14	= ( REGISTER_ARM64_V13 + 1 ) ,
        REGISTER_ARM64_V15	= ( REGISTER_ARM64_V14 + 1 ) ,
        REGISTER_ARM64_V16	= ( REGISTER_ARM64_V15 + 1 ) ,
        REGISTER_ARM64_V17	= ( REGISTER_ARM64_V16 + 1 ) ,
        REGISTER_ARM64_V18	= ( REGISTER_ARM64_V17 + 1 ) ,
        REGISTER_ARM64_V19	= ( REGISTER_ARM64_V18 + 1 ) ,
        REGISTER_ARM64_V20	= ( REGISTER_ARM64_V19 + 1 ) ,
        REGISTER_ARM64_V21	= ( REGISTER_ARM64_V20 + 1 ) ,
        REGISTER_ARM64_V22	= ( REGISTER_ARM64_V21 + 1 ) ,
        REGISTER_ARM64_V23	= ( REGISTER_ARM64_V22 + 1 ) ,
        REGISTER_ARM64_V24	= ( REGISTER_ARM64_V23 + 1 ) ,
        REGISTER_ARM64_V25	= ( REGISTER_ARM64_V24 + 1 ) ,
        REGISTER_ARM64_V26	= ( REGISTER_ARM64_V25 + 1 ) ,
        REGISTER_ARM64_V27	= ( REGISTER_ARM64_V26 + 1 ) ,
        REGISTER_ARM64_V28	= ( REGISTER_ARM64_V27 + 1 ) ,
        REGISTER_ARM64_V29	= ( REGISTER_ARM64_V28 + 1 ) ,
        REGISTER_ARM64_V30	= ( REGISTER_ARM64_V29 + 1 ) ,
        REGISTER_ARM64_V31	= ( REGISTER_ARM64_V30 + 1 ) ,
        REGISTER_LOONGARCH64_PC = 0,
        REGISTER_LOONGARCH64_SP = ( REGISTER_LOONGARCH64_PC + 1 ) ,
        REGISTER_LOONGARCH64_FP = ( REGISTER_LOONGARCH64_SP + 1 ) ,
        REGISTER_LOONGARCH64_RA = ( REGISTER_LOONGARCH64_FP + 1 ) ,
        REGISTER_LOONGARCH64_TP = ( REGISTER_LOONGARCH64_RA + 1 ) ,
        REGISTER_LOONGARCH64_A0 = ( REGISTER_LOONGARCH64_TP + 1 ) ,
        REGISTER_LOONGARCH64_A1 = ( REGISTER_LOONGARCH64_A0 + 1 ) ,
        REGISTER_LOONGARCH64_A2 = ( REGISTER_LOONGARCH64_A1 + 1 ) ,
        REGISTER_LOONGARCH64_A3 = ( REGISTER_LOONGARCH64_A2 + 1 ) ,
        REGISTER_LOONGARCH64_A4 = ( REGISTER_LOONGARCH64_A3 + 1 ) ,
        REGISTER_LOONGARCH64_A5 = ( REGISTER_LOONGARCH64_A4 + 1 ) ,
        REGISTER_LOONGARCH64_A6 = ( REGISTER_LOONGARCH64_A5 + 1 ) ,
        REGISTER_LOONGARCH64_A7 = ( REGISTER_LOONGARCH64_A6 + 1 ) ,
        REGISTER_LOONGARCH64_T0 = ( REGISTER_LOONGARCH64_A7 + 1 ) ,
        REGISTER_LOONGARCH64_T1 = ( REGISTER_LOONGARCH64_T0 + 1 ) ,
        REGISTER_LOONGARCH64_T2 = ( REGISTER_LOONGARCH64_T1 + 1 ) ,
        REGISTER_LOONGARCH64_T3 = ( REGISTER_LOONGARCH64_T2 + 1 ) ,
        REGISTER_LOONGARCH64_T4 = ( REGISTER_LOONGARCH64_T3 + 1 ) ,
        REGISTER_LOONGARCH64_T5 = ( REGISTER_LOONGARCH64_T4 + 1 ) ,
        REGISTER_LOONGARCH64_T6 = ( REGISTER_LOONGARCH64_T5 + 1 ) ,
        REGISTER_LOONGARCH64_T7 = ( REGISTER_LOONGARCH64_T6 + 1 ) ,
        REGISTER_LOONGARCH64_T8 = ( REGISTER_LOONGARCH64_T7 + 1 ) ,
        REGISTER_LOONGARCH64_X0 = ( REGISTER_LOONGARCH64_T8 + 1 ) ,
        REGISTER_LOONGARCH64_S0 = ( REGISTER_LOONGARCH64_X0 + 1 ) ,
        REGISTER_LOONGARCH64_S1 = ( REGISTER_LOONGARCH64_S0 + 1 ) ,
        REGISTER_LOONGARCH64_S2 = ( REGISTER_LOONGARCH64_S1 + 1 ) ,
        REGISTER_LOONGARCH64_S3 = ( REGISTER_LOONGARCH64_S2 + 1 ) ,
        REGISTER_LOONGARCH64_S4 = ( REGISTER_LOONGARCH64_S3 + 1 ) ,
        REGISTER_LOONGARCH64_S5 = ( REGISTER_LOONGARCH64_S4 + 1 ) ,
        REGISTER_LOONGARCH64_S6 = ( REGISTER_LOONGARCH64_S5 + 1 ) ,
        REGISTER_LOONGARCH64_S7 = ( REGISTER_LOONGARCH64_S6 + 1 ) ,
        REGISTER_LOONGARCH64_S8 = ( REGISTER_LOONGARCH64_S7 + 1 ) ,
        REGISTER_LOONGARCH64_F0 = ( REGISTER_LOONGARCH64_S8 + 1 ) ,
        REGISTER_LOONGARCH64_F1 = ( REGISTER_LOONGARCH64_F0 + 1 ) ,
        REGISTER_LOONGARCH64_F2 = ( REGISTER_LOONGARCH64_F1 + 1 ) ,
        REGISTER_LOONGARCH64_F3 = ( REGISTER_LOONGARCH64_F2 + 1 ) ,
        REGISTER_LOONGARCH64_F4 = ( REGISTER_LOONGARCH64_F3 + 1 ) ,
        REGISTER_LOONGARCH64_F5 = ( REGISTER_LOONGARCH64_F4 + 1 ) ,
        REGISTER_LOONGARCH64_F6 = ( REGISTER_LOONGARCH64_F5 + 1 ) ,
        REGISTER_LOONGARCH64_F7 = ( REGISTER_LOONGARCH64_F6 + 1 ) ,
        REGISTER_LOONGARCH64_F8 = ( REGISTER_LOONGARCH64_F7 + 1 ) ,
        REGISTER_LOONGARCH64_F9 = ( REGISTER_LOONGARCH64_F8 + 1 ) ,
        REGISTER_LOONGARCH64_F10 = ( REGISTER_LOONGARCH64_F9 + 1 ) ,
        REGISTER_LOONGARCH64_F11 = ( REGISTER_LOONGARCH64_F10 + 1 ) ,
        REGISTER_LOONGARCH64_F12 = ( REGISTER_LOONGARCH64_F11 + 1 ) ,
        REGISTER_LOONGARCH64_F13 = ( REGISTER_LOONGARCH64_F12 + 1 ) ,
        REGISTER_LOONGARCH64_F14 = ( REGISTER_LOONGARCH64_F13 + 1 ) ,
        REGISTER_LOONGARCH64_F15 = ( REGISTER_LOONGARCH64_F14 + 1 ) ,
        REGISTER_LOONGARCH64_F16 = ( REGISTER_LOONGARCH64_F15 + 1 ) ,
        REGISTER_LOONGARCH64_F17 = ( REGISTER_LOONGARCH64_F16 + 1 ) ,
        REGISTER_LOONGARCH64_F18 = ( REGISTER_LOONGARCH64_F17 + 1 ) ,
        REGISTER_LOONGARCH64_F19 = ( REGISTER_LOONGARCH64_F18 + 1 ) ,
        REGISTER_LOONGARCH64_F20 = ( REGISTER_LOONGARCH64_F19 + 1 ) ,
        REGISTER_LOONGARCH64_F21 = ( REGISTER_LOONGARCH64_F20 + 1 ) ,
        REGISTER_LOONGARCH64_F22 = ( REGISTER_LOONGARCH64_F21 + 1 ) ,
        REGISTER_LOONGARCH64_F23 = ( REGISTER_LOONGARCH64_F22 + 1 ) ,
        REGISTER_LOONGARCH64_F24 = ( REGISTER_LOONGARCH64_F23 + 1 ) ,
        REGISTER_LOONGARCH64_F25 = ( REGISTER_LOONGARCH64_F24 + 1 ) ,
        REGISTER_LOONGARCH64_F26 = ( REGISTER_LOONGARCH64_F25 + 1 ) ,
        REGISTER_LOONGARCH64_F27 = ( REGISTER_LOONGARCH64_F26 + 1 ) ,
        REGISTER_LOONGARCH64_F28 = ( REGISTER_LOONGARCH64_F27 + 1 ) ,
        REGISTER_LOONGARCH64_F29 = ( REGISTER_LOONGARCH64_F28 + 1 ) ,
        REGISTER_LOONGARCH64_F30 = ( REGISTER_LOONGARCH64_F29 + 1 ) ,
        REGISTER_LOONGARCH64_F31 = ( REGISTER_LOONGARCH64_F30 + 1 )
    } 	CorDebugRegister;


 const IID IID_ICorDebugRegisterSet;
#line 9297
    typedef struct ICorDebugRegisterSetVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugRegisterSet * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugRegisterSet * This);

        ULONG ( *Release )(
            ICorDebugRegisterSet * This);

        HRESULT ( *GetRegistersAvailable )(
            ICorDebugRegisterSet * This,
              ULONG64 *pAvailable);

        HRESULT ( *GetRegisters )(
            ICorDebugRegisterSet * This,
              ULONG64 mask,
              ULONG32 regCount,
              CORDB_REGISTER regBuffer[  ]);

        HRESULT ( *SetRegisters )(
            ICorDebugRegisterSet * This,
              ULONG64 mask,
              ULONG32 regCount,
              CORDB_REGISTER regBuffer[  ]);

        HRESULT ( *GetThreadContext )(
            ICorDebugRegisterSet * This,
              ULONG32 contextSize,
              BYTE context[  ]);

        HRESULT ( *SetThreadContext )(
            ICorDebugRegisterSet * This,
              ULONG32 contextSize,
              BYTE context[  ]);


    } ICorDebugRegisterSetVtbl;

    struct ICorDebugRegisterSet
    {
        CONST_VTBL struct ICorDebugRegisterSetVtbl *lpVtbl;
    };
#line 9395
 const IID IID_ICorDebugRegisterSet2;
#line 9424
    typedef struct ICorDebugRegisterSet2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugRegisterSet2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugRegisterSet2 * This);

        ULONG ( *Release )(
            ICorDebugRegisterSet2 * This);

        HRESULT ( *GetRegistersAvailable )(
            ICorDebugRegisterSet2 * This,
              ULONG32 numChunks,
              BYTE availableRegChunks[  ]);

        HRESULT ( *GetRegisters )(
            ICorDebugRegisterSet2 * This,
              ULONG32 maskCount,
              BYTE mask[  ],
              ULONG32 regCount,
              CORDB_REGISTER regBuffer[  ]);

        HRESULT ( *SetRegisters )(
            ICorDebugRegisterSet2 * This,
              ULONG32 maskCount,
              BYTE mask[  ],
              ULONG32 regCount,
              CORDB_REGISTER regBuffer[  ]);


    } ICorDebugRegisterSet2Vtbl;

    struct ICorDebugRegisterSet2
    {
        CONST_VTBL struct ICorDebugRegisterSet2Vtbl *lpVtbl;
    };
#line 9508
typedef
enum CorDebugUserState
    {
        USER_STOP_REQUESTED	= 0x1,
        USER_SUSPEND_REQUESTED	= 0x2,
        USER_BACKGROUND	= 0x4,
        USER_UNSTARTED	= 0x8,
        USER_STOPPED	= 0x10,
        USER_WAIT_SLEEP_JOIN	= 0x20,
        USER_SUSPENDED	= 0x40,
        USER_UNSAFE_POINT	= 0x80,
        USER_THREADPOOL	= 0x100
    } 	CorDebugUserState;


 const IID IID_ICorDebugThread;
#line 9583
    typedef struct ICorDebugThreadVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugThread * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugThread * This);

        ULONG ( *Release )(
            ICorDebugThread * This);

        HRESULT ( *GetProcess )(
            ICorDebugThread * This,
              ICorDebugProcess **ppProcess);

        HRESULT ( *GetID )(
            ICorDebugThread * This,
              DWORD *pdwThreadId);

        HRESULT ( *GetHandle )(
            ICorDebugThread * This,
              HTHREAD *phThreadHandle);

        HRESULT ( *GetAppDomain )(
            ICorDebugThread * This,
              ICorDebugAppDomain **ppAppDomain);

        HRESULT ( *SetDebugState )(
            ICorDebugThread * This,
              CorDebugThreadState state);

        HRESULT ( *GetDebugState )(
            ICorDebugThread * This,
              CorDebugThreadState *pState);

        HRESULT ( *GetUserState )(
            ICorDebugThread * This,
              CorDebugUserState *pState);

        HRESULT ( *GetCurrentException )(
            ICorDebugThread * This,
              ICorDebugValue **ppExceptionObject);

        HRESULT ( *ClearCurrentException )(
            ICorDebugThread * This);

        HRESULT ( *CreateStepper )(
            ICorDebugThread * This,
              ICorDebugStepper **ppStepper);

        HRESULT ( *EnumerateChains )(
            ICorDebugThread * This,
              ICorDebugChainEnum **ppChains);

        HRESULT ( *GetActiveChain )(
            ICorDebugThread * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetActiveFrame )(
            ICorDebugThread * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetRegisterSet )(
            ICorDebugThread * This,
              ICorDebugRegisterSet **ppRegisters);

        HRESULT ( *CreateEval )(
            ICorDebugThread * This,
              ICorDebugEval **ppEval);

        HRESULT ( *GetObject )(
            ICorDebugThread * This,
              ICorDebugValue **ppObject);


    } ICorDebugThreadVtbl;

    struct ICorDebugThread
    {
        CONST_VTBL struct ICorDebugThreadVtbl *lpVtbl;
    };
#line 9750
typedef struct _COR_ACTIVE_FUNCTION
    {
    ICorDebugAppDomain *pAppDomain;
    ICorDebugModule *pModule;
    ICorDebugFunction2 *pFunction;
    ULONG32 ilOffset;
    ULONG32 flags;
    } 	COR_ACTIVE_FUNCTION;


 const IID IID_ICorDebugThread2;
#line 9790
    typedef struct ICorDebugThread2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugThread2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugThread2 * This);

        ULONG ( *Release )(
            ICorDebugThread2 * This);

        HRESULT ( *GetActiveFunctions )(
            ICorDebugThread2 * This,
              ULONG32 cFunctions,
              ULONG32 *pcFunctions,
              COR_ACTIVE_FUNCTION pFunctions[  ]);

        HRESULT ( *GetConnectionID )(
            ICorDebugThread2 * This,
              CONNID *pdwConnectionId);

        HRESULT ( *GetTaskID )(
            ICorDebugThread2 * This,
              TASKID *pTaskId);

        HRESULT ( *GetVolatileOSThreadID )(
            ICorDebugThread2 * This,
              DWORD *pdwTid);

        HRESULT ( *InterceptCurrentException )(
            ICorDebugThread2 * This,
              ICorDebugFrame *pFrame);


    } ICorDebugThread2Vtbl;

    struct ICorDebugThread2
    {
        CONST_VTBL struct ICorDebugThread2Vtbl *lpVtbl;
    };
#line 9884
 const IID IID_ICorDebugThread3;
#line 9905
    typedef struct ICorDebugThread3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugThread3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugThread3 * This);

        ULONG ( *Release )(
            ICorDebugThread3 * This);

        HRESULT ( *CreateStackWalk )(
            ICorDebugThread3 * This,
              ICorDebugStackWalk **ppStackWalk);

        HRESULT ( *GetActiveInternalFrames )(
            ICorDebugThread3 * This,
              ULONG32 cInternalFrames,
              ULONG32 *pcInternalFrames,
              ICorDebugInternalFrame2 *ppInternalFrames[  ]);


    } ICorDebugThread3Vtbl;

    struct ICorDebugThread3
    {
        CONST_VTBL struct ICorDebugThread3Vtbl *lpVtbl;
    };
#line 9978
 const IID IID_ICorDebugThread4;
#line 9999
    typedef struct ICorDebugThread4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugThread4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugThread4 * This);

        ULONG ( *Release )(
            ICorDebugThread4 * This);

        HRESULT ( *HasUnhandledException )(
            ICorDebugThread4 * This);

        HRESULT ( *GetBlockingObjects )(
            ICorDebugThread4 * This,
              ICorDebugBlockingObjectEnum **ppBlockingObjectEnum);

        HRESULT ( *GetCurrentCustomDebuggerNotification )(
            ICorDebugThread4 * This,
              ICorDebugValue **ppNotificationObject);


    } ICorDebugThread4Vtbl;

    struct ICorDebugThread4
    {
        CONST_VTBL struct ICorDebugThread4Vtbl *lpVtbl;
    };
#line 10076
 const IID IID_ICorDebugThread5;
#line 10093
    typedef struct ICorDebugThread5Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugThread5 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugThread5 * This);

        ULONG ( *Release )(
            ICorDebugThread5 * This);

        HRESULT ( *GetBytesAllocated )(
            ICorDebugThread5 * This,
              ULONG64 *pSohAllocatedBytes,
              ULONG64 *pUohAllocatedBytes);


    } ICorDebugThread5Vtbl;

    struct ICorDebugThread5
    {
        CONST_VTBL struct ICorDebugThread5Vtbl *lpVtbl;
    };
#line 10157
typedef
enum CorDebugSetContextFlag
    {
        SET_CONTEXT_FLAG_ACTIVE_FRAME	= 0x1,
        SET_CONTEXT_FLAG_UNWIND_FRAME	= 0x2
    } 	CorDebugSetContextFlag;


 const IID IID_ICorDebugStackWalk;
#line 10194
    typedef struct ICorDebugStackWalkVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugStackWalk * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugStackWalk * This);

        ULONG ( *Release )(
            ICorDebugStackWalk * This);

        HRESULT ( *GetContext )(
            ICorDebugStackWalk * This,
              ULONG32 contextFlags,
              ULONG32 contextBufSize,
              ULONG32 *contextSize,
              BYTE contextBuf[  ]);

        HRESULT ( *SetContext )(
            ICorDebugStackWalk * This,
              CorDebugSetContextFlag flag,
              ULONG32 contextSize,
              BYTE context[  ]);

        HRESULT ( *Next )(
            ICorDebugStackWalk * This);

        HRESULT ( *GetFrame )(
            ICorDebugStackWalk * This,
              ICorDebugFrame **pFrame);


    } ICorDebugStackWalkVtbl;

    struct ICorDebugStackWalk
    {
        CONST_VTBL struct ICorDebugStackWalkVtbl *lpVtbl;
    };
#line 10282
typedef
enum CorDebugChainReason
    {
        CHAIN_NONE	= 0,
        CHAIN_CLASS_INIT	= 0x1,
        CHAIN_EXCEPTION_FILTER	= 0x2,
        CHAIN_SECURITY	= 0x4,
        CHAIN_CONTEXT_POLICY	= 0x8,
        CHAIN_INTERCEPTION	= 0x10,
        CHAIN_PROCESS_START	= 0x20,
        CHAIN_THREAD_START	= 0x40,
        CHAIN_ENTER_MANAGED	= 0x80,
        CHAIN_ENTER_UNMANAGED	= 0x100,
        CHAIN_DEBUGGER_EVAL	= 0x200,
        CHAIN_CONTEXT_SWITCH	= 0x400,
        CHAIN_FUNC_EVAL	= 0x800
    } 	CorDebugChainReason;


 const IID IID_ICorDebugChain;
#line 10351
    typedef struct ICorDebugChainVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugChain * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugChain * This);

        ULONG ( *Release )(
            ICorDebugChain * This);

        HRESULT ( *GetThread )(
            ICorDebugChain * This,
              ICorDebugThread **ppThread);

        HRESULT ( *GetStackRange )(
            ICorDebugChain * This,
              CORDB_ADDRESS *pStart,
              CORDB_ADDRESS *pEnd);

        HRESULT ( *GetContext )(
            ICorDebugChain * This,
              ICorDebugContext **ppContext);

        HRESULT ( *GetCaller )(
            ICorDebugChain * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetCallee )(
            ICorDebugChain * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetPrevious )(
            ICorDebugChain * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetNext )(
            ICorDebugChain * This,
              ICorDebugChain **ppChain);

        HRESULT ( *IsManaged )(
            ICorDebugChain * This,
              BOOL *pManaged);

        HRESULT ( *EnumerateFrames )(
            ICorDebugChain * This,
              ICorDebugFrameEnum **ppFrames);

        HRESULT ( *GetActiveFrame )(
            ICorDebugChain * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetRegisterSet )(
            ICorDebugChain * This,
              ICorDebugRegisterSet **ppRegisters);

        HRESULT ( *GetReason )(
            ICorDebugChain * This,
              CorDebugChainReason *pReason);


    } ICorDebugChainVtbl;

    struct ICorDebugChain
    {
        CONST_VTBL struct ICorDebugChainVtbl *lpVtbl;
    };
#line 10493
 const IID IID_ICorDebugFrame;
#line 10531
    typedef struct ICorDebugFrameVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFrame * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFrame * This);

        ULONG ( *Release )(
            ICorDebugFrame * This);

        HRESULT ( *GetChain )(
            ICorDebugFrame * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetCode )(
            ICorDebugFrame * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetFunction )(
            ICorDebugFrame * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetFunctionToken )(
            ICorDebugFrame * This,
              mdMethodDef *pToken);

        HRESULT ( *GetStackRange )(
            ICorDebugFrame * This,
              CORDB_ADDRESS *pStart,
              CORDB_ADDRESS *pEnd);

        HRESULT ( *GetCaller )(
            ICorDebugFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetCallee )(
            ICorDebugFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *CreateStepper )(
            ICorDebugFrame * This,
              ICorDebugStepper **ppStepper);


    } ICorDebugFrameVtbl;

    struct ICorDebugFrame
    {
        CONST_VTBL struct ICorDebugFrameVtbl *lpVtbl;
    };
#line 10644
typedef
enum CorDebugInternalFrameType
    {
        STUBFRAME_NONE	= 0,
        STUBFRAME_M2U	= 0x1,
        STUBFRAME_U2M	= 0x2,
        STUBFRAME_APPDOMAIN_TRANSITION	= 0x3,
        STUBFRAME_LIGHTWEIGHT_FUNCTION	= 0x4,
        STUBFRAME_FUNC_EVAL	= 0x5,
        STUBFRAME_INTERNALCALL	= 0x6,
        STUBFRAME_CLASS_INIT	= 0x7,
        STUBFRAME_EXCEPTION	= 0x8,
        STUBFRAME_SECURITY	= 0x9,
        STUBFRAME_JIT_COMPILATION	= 0xa
    } 	CorDebugInternalFrameType;


 const IID IID_ICorDebugInternalFrame;
#line 10677
    typedef struct ICorDebugInternalFrameVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugInternalFrame * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugInternalFrame * This);

        ULONG ( *Release )(
            ICorDebugInternalFrame * This);

        HRESULT ( *GetChain )(
            ICorDebugInternalFrame * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetCode )(
            ICorDebugInternalFrame * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetFunction )(
            ICorDebugInternalFrame * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetFunctionToken )(
            ICorDebugInternalFrame * This,
              mdMethodDef *pToken);

        HRESULT ( *GetStackRange )(
            ICorDebugInternalFrame * This,
              CORDB_ADDRESS *pStart,
              CORDB_ADDRESS *pEnd);

        HRESULT ( *GetCaller )(
            ICorDebugInternalFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetCallee )(
            ICorDebugInternalFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *CreateStepper )(
            ICorDebugInternalFrame * This,
              ICorDebugStepper **ppStepper);

        HRESULT ( *GetFrameType )(
            ICorDebugInternalFrame * This,
              CorDebugInternalFrameType *pType);


    } ICorDebugInternalFrameVtbl;

    struct ICorDebugInternalFrame
    {
        CONST_VTBL struct ICorDebugInternalFrameVtbl *lpVtbl;
    };
#line 10799
 const IID IID_ICorDebugInternalFrame2;
#line 10819
    typedef struct ICorDebugInternalFrame2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugInternalFrame2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugInternalFrame2 * This);

        ULONG ( *Release )(
            ICorDebugInternalFrame2 * This);

        HRESULT ( *GetAddress )(
            ICorDebugInternalFrame2 * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *IsCloserToLeaf )(
            ICorDebugInternalFrame2 * This,
              ICorDebugFrame *pFrameToCompare,
              BOOL *pIsCloser);


    } ICorDebugInternalFrame2Vtbl;

    struct ICorDebugInternalFrame2
    {
        CONST_VTBL struct ICorDebugInternalFrame2Vtbl *lpVtbl;
    };
#line 10890
typedef
enum CorDebugMappingResult
    {
        MAPPING_PROLOG	= 0x1,
        MAPPING_EPILOG	= 0x2,
        MAPPING_NO_INFO	= 0x4,
        MAPPING_UNMAPPED_ADDRESS	= 0x8,
        MAPPING_EXACT	= 0x10,
        MAPPING_APPROXIMATE	= 0x20
    } 	CorDebugMappingResult;


 const IID IID_ICorDebugILFrame;
#line 10946
    typedef struct ICorDebugILFrameVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugILFrame * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugILFrame * This);

        ULONG ( *Release )(
            ICorDebugILFrame * This);

        HRESULT ( *GetChain )(
            ICorDebugILFrame * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetCode )(
            ICorDebugILFrame * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetFunction )(
            ICorDebugILFrame * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetFunctionToken )(
            ICorDebugILFrame * This,
              mdMethodDef *pToken);

        HRESULT ( *GetStackRange )(
            ICorDebugILFrame * This,
              CORDB_ADDRESS *pStart,
              CORDB_ADDRESS *pEnd);

        HRESULT ( *GetCaller )(
            ICorDebugILFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetCallee )(
            ICorDebugILFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *CreateStepper )(
            ICorDebugILFrame * This,
              ICorDebugStepper **ppStepper);

        HRESULT ( *GetIP )(
            ICorDebugILFrame * This,
              ULONG32 *pnOffset,
              CorDebugMappingResult *pMappingResult);

        HRESULT ( *SetIP )(
            ICorDebugILFrame * This,
              ULONG32 nOffset);

        HRESULT ( *EnumerateLocalVariables )(
            ICorDebugILFrame * This,
              ICorDebugValueEnum **ppValueEnum);

        HRESULT ( *GetLocalVariable )(
            ICorDebugILFrame * This,
              DWORD dwIndex,
              ICorDebugValue **ppValue);

        HRESULT ( *EnumerateArguments )(
            ICorDebugILFrame * This,
              ICorDebugValueEnum **ppValueEnum);

        HRESULT ( *GetArgument )(
            ICorDebugILFrame * This,
              DWORD dwIndex,
              ICorDebugValue **ppValue);

        HRESULT ( *GetStackDepth )(
            ICorDebugILFrame * This,
              ULONG32 *pDepth);

        HRESULT ( *GetStackValue )(
            ICorDebugILFrame * This,
              DWORD dwIndex,
              ICorDebugValue **ppValue);

        HRESULT ( *CanSetIP )(
            ICorDebugILFrame * This,
              ULONG32 nOffset);


    } ICorDebugILFrameVtbl;

    struct ICorDebugILFrame
    {
        CONST_VTBL struct ICorDebugILFrameVtbl *lpVtbl;
    };
#line 11128
 const IID IID_ICorDebugILFrame2;
#line 11147
    typedef struct ICorDebugILFrame2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugILFrame2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugILFrame2 * This);

        ULONG ( *Release )(
            ICorDebugILFrame2 * This);

        HRESULT ( *RemapFunction )(
            ICorDebugILFrame2 * This,
              ULONG32 newILOffset);

        HRESULT ( *EnumerateTypeParameters )(
            ICorDebugILFrame2 * This,
              ICorDebugTypeEnum **ppTyParEnum);


    } ICorDebugILFrame2Vtbl;

    struct ICorDebugILFrame2
    {
        CONST_VTBL struct ICorDebugILFrame2Vtbl *lpVtbl;
    };
#line 11218
 const IID IID_ICorDebugILFrame3;
#line 11235
    typedef struct ICorDebugILFrame3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugILFrame3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugILFrame3 * This);

        ULONG ( *Release )(
            ICorDebugILFrame3 * This);

        HRESULT ( *GetReturnValueForILOffset )(
            ICorDebugILFrame3 * This,
            ULONG32 ILoffset,
              ICorDebugValue **ppReturnValue);


    } ICorDebugILFrame3Vtbl;

    struct ICorDebugILFrame3
    {
        CONST_VTBL struct ICorDebugILFrame3Vtbl *lpVtbl;
    };
#line 11296
typedef
enum ILCodeKind
    {
        ILCODE_ORIGINAL_IL	= 0x1,
        ILCODE_REJIT_IL	= 0x2
    } 	ILCodeKind;



extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0070_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0070_v0_0_s_ifspec;
#line 11315
 const IID IID_ICorDebugILFrame4;
#line 11341
    typedef struct ICorDebugILFrame4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugILFrame4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugILFrame4 * This);

        ULONG ( *Release )(
            ICorDebugILFrame4 * This);

        HRESULT ( *EnumerateLocalVariablesEx )(
            ICorDebugILFrame4 * This,
              ILCodeKind flags,
              ICorDebugValueEnum **ppValueEnum);

        HRESULT ( *GetLocalVariableEx )(
            ICorDebugILFrame4 * This,
              ILCodeKind flags,
              DWORD dwIndex,
              ICorDebugValue **ppValue);

        HRESULT ( *GetCodeEx )(
            ICorDebugILFrame4 * This,
              ILCodeKind flags,
              ICorDebugCode **ppCode);


    } ICorDebugILFrame4Vtbl;

    struct ICorDebugILFrame4
    {
        CONST_VTBL struct ICorDebugILFrame4Vtbl *lpVtbl;
    };
#line 11423
 const IID IID_ICorDebugNativeFrame;
#line 11481
    typedef struct ICorDebugNativeFrameVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugNativeFrame * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugNativeFrame * This);

        ULONG ( *Release )(
            ICorDebugNativeFrame * This);

        HRESULT ( *GetChain )(
            ICorDebugNativeFrame * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetCode )(
            ICorDebugNativeFrame * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetFunction )(
            ICorDebugNativeFrame * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetFunctionToken )(
            ICorDebugNativeFrame * This,
              mdMethodDef *pToken);

        HRESULT ( *GetStackRange )(
            ICorDebugNativeFrame * This,
              CORDB_ADDRESS *pStart,
              CORDB_ADDRESS *pEnd);

        HRESULT ( *GetCaller )(
            ICorDebugNativeFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetCallee )(
            ICorDebugNativeFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *CreateStepper )(
            ICorDebugNativeFrame * This,
              ICorDebugStepper **ppStepper);

        HRESULT ( *GetIP )(
            ICorDebugNativeFrame * This,
              ULONG32 *pnOffset);

        HRESULT ( *SetIP )(
            ICorDebugNativeFrame * This,
              ULONG32 nOffset);

        HRESULT ( *GetRegisterSet )(
            ICorDebugNativeFrame * This,
              ICorDebugRegisterSet **ppRegisters);

        HRESULT ( *GetLocalRegisterValue )(
            ICorDebugNativeFrame * This,
              CorDebugRegister reg,
              ULONG cbSigBlob,
              PCCOR_SIGNATURE pvSigBlob,
              ICorDebugValue **ppValue);

        HRESULT ( *GetLocalDoubleRegisterValue )(
            ICorDebugNativeFrame * This,
              CorDebugRegister highWordReg,
              CorDebugRegister lowWordReg,
              ULONG cbSigBlob,
              PCCOR_SIGNATURE pvSigBlob,
              ICorDebugValue **ppValue);

        HRESULT ( *GetLocalMemoryValue )(
            ICorDebugNativeFrame * This,
              CORDB_ADDRESS address,
              ULONG cbSigBlob,
              PCCOR_SIGNATURE pvSigBlob,
              ICorDebugValue **ppValue);

        HRESULT ( *GetLocalRegisterMemoryValue )(
            ICorDebugNativeFrame * This,
              CorDebugRegister highWordReg,
              CORDB_ADDRESS lowWordAddress,
              ULONG cbSigBlob,
              PCCOR_SIGNATURE pvSigBlob,
              ICorDebugValue **ppValue);

        HRESULT ( *GetLocalMemoryRegisterValue )(
            ICorDebugNativeFrame * This,
              CORDB_ADDRESS highWordAddress,
              CorDebugRegister lowWordRegister,
              ULONG cbSigBlob,
              PCCOR_SIGNATURE pvSigBlob,
              ICorDebugValue **ppValue);

        HRESULT ( *CanSetIP )(
            ICorDebugNativeFrame * This,
              ULONG32 nOffset);


    } ICorDebugNativeFrameVtbl;

    struct ICorDebugNativeFrame
    {
        CONST_VTBL struct ICorDebugNativeFrameVtbl *lpVtbl;
    };
#line 11673
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0072_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0072_v0_0_s_ifspec;
#line 11687
 const IID IID_ICorDebugNativeFrame2;
#line 11710
    typedef struct ICorDebugNativeFrame2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugNativeFrame2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugNativeFrame2 * This);

        ULONG ( *Release )(
            ICorDebugNativeFrame2 * This);

        HRESULT ( *IsChild )(
            ICorDebugNativeFrame2 * This,
              BOOL *pIsChild);

        HRESULT ( *IsMatchingParentFrame )(
            ICorDebugNativeFrame2 * This,
              ICorDebugNativeFrame2 *pPotentialParentFrame,
              BOOL *pIsParent);

        HRESULT ( *GetStackParameterSize )(
            ICorDebugNativeFrame2 * This,
              ULONG32 *pSize);


    } ICorDebugNativeFrame2Vtbl;

    struct ICorDebugNativeFrame2
    {
        CONST_VTBL struct ICorDebugNativeFrame2Vtbl *lpVtbl;
    };
#line 11789
 const IID IID_ICorDebugModule3;
#line 11806
    typedef struct ICorDebugModule3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModule3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModule3 * This);

        ULONG ( *Release )(
            ICorDebugModule3 * This);

        HRESULT ( *CreateReaderForInMemorySymbols )(
            ICorDebugModule3 * This,
              const IID * riid,
              void **ppObj);


    } ICorDebugModule3Vtbl;

    struct ICorDebugModule3
    {
        CONST_VTBL struct ICorDebugModule3Vtbl *lpVtbl;
    };
#line 11871
 const IID IID_ICorDebugModule4;
#line 11887
    typedef struct ICorDebugModule4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModule4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModule4 * This);

        ULONG ( *Release )(
            ICorDebugModule4 * This);

        HRESULT ( *IsMappedLayout )(
            ICorDebugModule4 * This,
              BOOL *pIsMapped);


    } ICorDebugModule4Vtbl;

    struct ICorDebugModule4
    {
        CONST_VTBL struct ICorDebugModule4Vtbl *lpVtbl;
    };
#line 11951
 const IID IID_ICorDebugRuntimeUnwindableFrame;
#line 11964
    typedef struct ICorDebugRuntimeUnwindableFrameVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugRuntimeUnwindableFrame * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugRuntimeUnwindableFrame * This);

        ULONG ( *Release )(
            ICorDebugRuntimeUnwindableFrame * This);

        HRESULT ( *GetChain )(
            ICorDebugRuntimeUnwindableFrame * This,
              ICorDebugChain **ppChain);

        HRESULT ( *GetCode )(
            ICorDebugRuntimeUnwindableFrame * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetFunction )(
            ICorDebugRuntimeUnwindableFrame * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetFunctionToken )(
            ICorDebugRuntimeUnwindableFrame * This,
              mdMethodDef *pToken);

        HRESULT ( *GetStackRange )(
            ICorDebugRuntimeUnwindableFrame * This,
              CORDB_ADDRESS *pStart,
              CORDB_ADDRESS *pEnd);

        HRESULT ( *GetCaller )(
            ICorDebugRuntimeUnwindableFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *GetCallee )(
            ICorDebugRuntimeUnwindableFrame * This,
              ICorDebugFrame **ppFrame);

        HRESULT ( *CreateStepper )(
            ICorDebugRuntimeUnwindableFrame * This,
              ICorDebugStepper **ppStepper);


    } ICorDebugRuntimeUnwindableFrameVtbl;

    struct ICorDebugRuntimeUnwindableFrame
    {
        CONST_VTBL struct ICorDebugRuntimeUnwindableFrameVtbl *lpVtbl;
    };
#line 12079
 const IID IID_ICorDebugModule;
#line 12151
    typedef struct ICorDebugModuleVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModule * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModule * This);

        ULONG ( *Release )(
            ICorDebugModule * This);

        HRESULT ( *GetProcess )(
            ICorDebugModule * This,
              ICorDebugProcess **ppProcess);

        HRESULT ( *GetBaseAddress )(
            ICorDebugModule * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *GetAssembly )(
            ICorDebugModule * This,
              ICorDebugAssembly **ppAssembly);

        HRESULT ( *GetName )(
            ICorDebugModule * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *EnableJITDebugging )(
            ICorDebugModule * This,
              BOOL bTrackJITInfo,
              BOOL bAllowJitOpts);

        HRESULT ( *EnableClassLoadCallbacks )(
            ICorDebugModule * This,
              BOOL bClassLoadCallbacks);

        HRESULT ( *GetFunctionFromToken )(
            ICorDebugModule * This,
              mdMethodDef methodDef,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetFunctionFromRVA )(
            ICorDebugModule * This,
              CORDB_ADDRESS rva,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetClassFromToken )(
            ICorDebugModule * This,
              mdTypeDef typeDef,
              ICorDebugClass **ppClass);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugModule * This,
              ICorDebugModuleBreakpoint **ppBreakpoint);

        HRESULT ( *GetEditAndContinueSnapshot )(
            ICorDebugModule * This,
              ICorDebugEditAndContinueSnapshot **ppEditAndContinueSnapshot);

        HRESULT ( *GetMetaDataInterface )(
            ICorDebugModule * This,
              const IID * riid,
              IUnknown **ppObj);

        HRESULT ( *GetToken )(
            ICorDebugModule * This,
              mdModule *pToken);

        HRESULT ( *IsDynamic )(
            ICorDebugModule * This,
              BOOL *pDynamic);

        HRESULT ( *GetGlobalVariableValue )(
            ICorDebugModule * This,
              mdFieldDef fieldDef,
              ICorDebugValue **ppValue);

        HRESULT ( *GetSize )(
            ICorDebugModule * This,
              ULONG32 *pcBytes);

        HRESULT ( *IsInMemory )(
            ICorDebugModule * This,
              BOOL *pInMemory);


    } ICorDebugModuleVtbl;

    struct ICorDebugModule
    {
        CONST_VTBL struct ICorDebugModuleVtbl *lpVtbl;
    };
#line 12331
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0077_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0077_v0_0_s_ifspec;
#line 12344
 const IID IID_ICorDebugModule2;
#line 12378
    typedef struct ICorDebugModule2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModule2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModule2 * This);

        ULONG ( *Release )(
            ICorDebugModule2 * This);

        HRESULT ( *SetJMCStatus )(
            ICorDebugModule2 * This,
              BOOL bIsJustMyCode,
              ULONG32 cTokens,
              mdToken pTokens[  ]);

        HRESULT ( *ApplyChanges )(
            ICorDebugModule2 * This,
              ULONG cbMetadata,
              BYTE pbMetadata[  ],
              ULONG cbIL,
              BYTE pbIL[  ]);

        HRESULT ( *SetJITCompilerFlags )(
            ICorDebugModule2 * This,
              DWORD dwFlags);

        HRESULT ( *GetJITCompilerFlags )(
            ICorDebugModule2 * This,
              DWORD *pdwFlags);

        HRESULT ( *ResolveAssembly )(
            ICorDebugModule2 * This,
              mdToken tkAssemblyRef,
              ICorDebugAssembly **ppAssembly);


    } ICorDebugModule2Vtbl;

    struct ICorDebugModule2
    {
        CONST_VTBL struct ICorDebugModule2Vtbl *lpVtbl;
    };
#line 12476
 const IID IID_ICorDebugFunction;
#line 12513
    typedef struct ICorDebugFunctionVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFunction * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFunction * This);

        ULONG ( *Release )(
            ICorDebugFunction * This);

        HRESULT ( *GetModule )(
            ICorDebugFunction * This,
              ICorDebugModule **ppModule);

        HRESULT ( *GetClass )(
            ICorDebugFunction * This,
              ICorDebugClass **ppClass);

        HRESULT ( *GetToken )(
            ICorDebugFunction * This,
              mdMethodDef *pMethodDef);

        HRESULT ( *GetILCode )(
            ICorDebugFunction * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetNativeCode )(
            ICorDebugFunction * This,
              ICorDebugCode **ppCode);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugFunction * This,
              ICorDebugFunctionBreakpoint **ppBreakpoint);

        HRESULT ( *GetLocalVarSigToken )(
            ICorDebugFunction * This,
              mdSignature *pmdSig);

        HRESULT ( *GetCurrentVersionNumber )(
            ICorDebugFunction * This,
              ULONG32 *pnCurrentVersion);


    } ICorDebugFunctionVtbl;

    struct ICorDebugFunction
    {
        CONST_VTBL struct ICorDebugFunctionVtbl *lpVtbl;
    };
#line 12626
 const IID IID_ICorDebugFunction2;
#line 12651
    typedef struct ICorDebugFunction2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFunction2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFunction2 * This);

        ULONG ( *Release )(
            ICorDebugFunction2 * This);

        HRESULT ( *SetJMCStatus )(
            ICorDebugFunction2 * This,
              BOOL bIsJustMyCode);

        HRESULT ( *GetJMCStatus )(
            ICorDebugFunction2 * This,
              BOOL *pbIsJustMyCode);

        HRESULT ( *EnumerateNativeCode )(
            ICorDebugFunction2 * This,
              ICorDebugCodeEnum **ppCodeEnum);

        HRESULT ( *GetVersionNumber )(
            ICorDebugFunction2 * This,
              ULONG32 *pnVersion);


    } ICorDebugFunction2Vtbl;

    struct ICorDebugFunction2
    {
        CONST_VTBL struct ICorDebugFunction2Vtbl *lpVtbl;
    };
#line 12736
 const IID IID_ICorDebugFunction3;
#line 12752
    typedef struct ICorDebugFunction3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFunction3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFunction3 * This);

        ULONG ( *Release )(
            ICorDebugFunction3 * This);

        HRESULT ( *GetActiveReJitRequestILCode )(
            ICorDebugFunction3 * This,
            ICorDebugILCode **ppReJitedILCode);


    } ICorDebugFunction3Vtbl;

    struct ICorDebugFunction3
    {
        CONST_VTBL struct ICorDebugFunction3Vtbl *lpVtbl;
    };
#line 12816
 const IID IID_ICorDebugFunction4;
#line 12832
    typedef struct ICorDebugFunction4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFunction4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFunction4 * This);

        ULONG ( *Release )(
            ICorDebugFunction4 * This);

        HRESULT ( *CreateNativeBreakpoint )(
            ICorDebugFunction4 * This,
            ICorDebugFunctionBreakpoint **ppBreakpoint);


    } ICorDebugFunction4Vtbl;

    struct ICorDebugFunction4
    {
        CONST_VTBL struct ICorDebugFunction4Vtbl *lpVtbl;
    };
#line 12896
 const IID IID_ICorDebugCode;
#line 12945
    typedef struct ICorDebugCodeVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugCode * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugCode * This);

        ULONG ( *Release )(
            ICorDebugCode * This);

        HRESULT ( *IsIL )(
            ICorDebugCode * This,
              BOOL *pbIL);

        HRESULT ( *GetFunction )(
            ICorDebugCode * This,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetAddress )(
            ICorDebugCode * This,
              CORDB_ADDRESS *pStart);

        HRESULT ( *GetSize )(
            ICorDebugCode * This,
              ULONG32 *pcBytes);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugCode * This,
              ULONG32 offset,
              ICorDebugFunctionBreakpoint **ppBreakpoint);

        HRESULT ( *GetCode )(
            ICorDebugCode * This,
              ULONG32 startOffset,
              ULONG32 endOffset,
              ULONG32 cBufferAlloc,
              BYTE buffer[  ],
              ULONG32 *pcBufferSize);

        HRESULT ( *GetVersionNumber )(
            ICorDebugCode * This,
              ULONG32 *nVersion);

        HRESULT ( *GetILToNativeMapping )(
            ICorDebugCode * This,
              ULONG32 cMap,
              ULONG32 *pcMap,
              COR_DEBUG_IL_TO_NATIVE_MAP map[  ]);

        HRESULT ( *GetEnCRemapSequencePoints )(
            ICorDebugCode * This,
              ULONG32 cMap,
              ULONG32 *pcMap,
              ULONG32 offsets[  ]);


    } ICorDebugCodeVtbl;

    struct ICorDebugCode
    {
        CONST_VTBL struct ICorDebugCodeVtbl *lpVtbl;
    };
#line 13073
typedef struct _CodeChunkInfo
    {
    CORDB_ADDRESS startAddr;
    ULONG32 length;
    } 	CodeChunkInfo;


 const IID IID_ICorDebugCode2;
#line 13101
    typedef struct ICorDebugCode2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugCode2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugCode2 * This);

        ULONG ( *Release )(
            ICorDebugCode2 * This);

        HRESULT ( *GetCodeChunks )(
            ICorDebugCode2 * This,
              ULONG32 cbufSize,
              ULONG32 *pcnumChunks,
              CodeChunkInfo chunks[  ]);

        HRESULT ( *GetCompilerFlags )(
            ICorDebugCode2 * This,
              DWORD *pdwFlags);


    } ICorDebugCode2Vtbl;

    struct ICorDebugCode2
    {
        CONST_VTBL struct ICorDebugCode2Vtbl *lpVtbl;
    };
#line 13174
 const IID IID_ICorDebugCode3;
#line 13193
    typedef struct ICorDebugCode3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugCode3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugCode3 * This);

        ULONG ( *Release )(
            ICorDebugCode3 * This);

        HRESULT ( *GetReturnValueLiveOffset )(
            ICorDebugCode3 * This,
              ULONG32 ILoffset,
              ULONG32 bufferSize,
              ULONG32 *pFetched,
              ULONG32 pOffsets[  ]);


    } ICorDebugCode3Vtbl;

    struct ICorDebugCode3
    {
        CONST_VTBL struct ICorDebugCode3Vtbl *lpVtbl;
    };
#line 13260
 const IID IID_ICorDebugCode4;
#line 13276
    typedef struct ICorDebugCode4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugCode4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugCode4 * This);

        ULONG ( *Release )(
            ICorDebugCode4 * This);

        HRESULT ( *EnumerateVariableHomes )(
            ICorDebugCode4 * This,
              ICorDebugVariableHomeEnum **ppEnum);


    } ICorDebugCode4Vtbl;

    struct ICorDebugCode4
    {
        CONST_VTBL struct ICorDebugCode4Vtbl *lpVtbl;
    };
#line 13339
typedef struct _CorDebugEHClause
    {
    ULONG32 Flags;
    ULONG32 TryOffset;
    ULONG32 TryLength;
    ULONG32 HandlerOffset;
    ULONG32 HandlerLength;
    ULONG32 ClassToken;
    ULONG32 FilterOffset;
    } 	CorDebugEHClause;


 const IID IID_ICorDebugILCode;
#line 13369
    typedef struct ICorDebugILCodeVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugILCode * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugILCode * This);

        ULONG ( *Release )(
            ICorDebugILCode * This);

        HRESULT ( *GetEHClauses )(
            ICorDebugILCode * This,
              ULONG32 cClauses,
              ULONG32 *pcClauses,
              CorDebugEHClause clauses[  ]);


    } ICorDebugILCodeVtbl;

    struct ICorDebugILCode
    {
        CONST_VTBL struct ICorDebugILCodeVtbl *lpVtbl;
    };
#line 13435
 const IID IID_ICorDebugILCode2;
#line 13456
    typedef struct ICorDebugILCode2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugILCode2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugILCode2 * This);

        ULONG ( *Release )(
            ICorDebugILCode2 * This);

        HRESULT ( *GetLocalVarSigToken )(
            ICorDebugILCode2 * This,
              mdSignature *pmdSig);

        HRESULT ( *GetInstrumentedILMap )(
            ICorDebugILCode2 * This,
              ULONG32 cMap,
              ULONG32 *pcMap,
              COR_IL_MAP map[  ]);


    } ICorDebugILCode2Vtbl;

    struct ICorDebugILCode2
    {
        CONST_VTBL struct ICorDebugILCode2Vtbl *lpVtbl;
    };
#line 13529
 const IID IID_ICorDebugClass;
#line 13553
    typedef struct ICorDebugClassVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugClass * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugClass * This);

        ULONG ( *Release )(
            ICorDebugClass * This);

        HRESULT ( *GetModule )(
            ICorDebugClass * This,
              ICorDebugModule **pModule);

        HRESULT ( *GetToken )(
            ICorDebugClass * This,
              mdTypeDef *pTypeDef);

        HRESULT ( *GetStaticFieldValue )(
            ICorDebugClass * This,
              mdFieldDef fieldDef,
              ICorDebugFrame *pFrame,
              ICorDebugValue **ppValue);


    } ICorDebugClassVtbl;

    struct ICorDebugClass
    {
        CONST_VTBL struct ICorDebugClassVtbl *lpVtbl;
    };
#line 13633
 const IID IID_ICorDebugClass2;
#line 13655
    typedef struct ICorDebugClass2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugClass2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugClass2 * This);

        ULONG ( *Release )(
            ICorDebugClass2 * This);

        HRESULT ( *GetParameterizedType )(
            ICorDebugClass2 * This,
              CorElementType elementType,
              ULONG32 nTypeArgs,
              ICorDebugType *ppTypeArgs[  ],
              ICorDebugType **ppType);

        HRESULT ( *SetJMCStatus )(
            ICorDebugClass2 * This,
              BOOL bIsJustMyCode);


    } ICorDebugClass2Vtbl;

    struct ICorDebugClass2
    {
        CONST_VTBL struct ICorDebugClass2Vtbl *lpVtbl;
    };
#line 13729
 const IID IID_ICorDebugEval;
#line 13781
    typedef struct ICorDebugEvalVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugEval * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugEval * This);

        ULONG ( *Release )(
            ICorDebugEval * This);

        HRESULT ( *CallFunction )(
            ICorDebugEval * This,
              ICorDebugFunction *pFunction,
              ULONG32 nArgs,
              ICorDebugValue *ppArgs[  ]);

        HRESULT ( *NewObject )(
            ICorDebugEval * This,
              ICorDebugFunction *pConstructor,
              ULONG32 nArgs,
              ICorDebugValue *ppArgs[  ]);

        HRESULT ( *NewObjectNoConstructor )(
            ICorDebugEval * This,
              ICorDebugClass *pClass);

        HRESULT ( *NewString )(
            ICorDebugEval * This,
              LPCWSTR string);

        HRESULT ( *NewArray )(
            ICorDebugEval * This,
              CorElementType elementType,
              ICorDebugClass *pElementClass,
              ULONG32 rank,
              ULONG32 dims[  ],
              ULONG32 lowBounds[  ]);

        HRESULT ( *IsActive )(
            ICorDebugEval * This,
              BOOL *pbActive);

        HRESULT ( *Abort )(
            ICorDebugEval * This);

        HRESULT ( *GetResult )(
            ICorDebugEval * This,
              ICorDebugValue **ppResult);

        HRESULT ( *GetThread )(
            ICorDebugEval * This,
              ICorDebugThread **ppThread);

        HRESULT ( *CreateValue )(
            ICorDebugEval * This,
              CorElementType elementType,
              ICorDebugClass *pElementClass,
              ICorDebugValue **ppValue);


    } ICorDebugEvalVtbl;

    struct ICorDebugEval
    {
        CONST_VTBL struct ICorDebugEvalVtbl *lpVtbl;
    };
#line 13917
 const IID IID_ICorDebugEval2;
#line 13965
    typedef struct ICorDebugEval2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugEval2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugEval2 * This);

        ULONG ( *Release )(
            ICorDebugEval2 * This);

        HRESULT ( *CallParameterizedFunction )(
            ICorDebugEval2 * This,
              ICorDebugFunction *pFunction,
              ULONG32 nTypeArgs,
              ICorDebugType *ppTypeArgs[  ],
              ULONG32 nArgs,
              ICorDebugValue *ppArgs[  ]);

        HRESULT ( *CreateValueForType )(
            ICorDebugEval2 * This,
              ICorDebugType *pType,
              ICorDebugValue **ppValue);

        HRESULT ( *NewParameterizedObject )(
            ICorDebugEval2 * This,
              ICorDebugFunction *pConstructor,
              ULONG32 nTypeArgs,
              ICorDebugType *ppTypeArgs[  ],
              ULONG32 nArgs,
              ICorDebugValue *ppArgs[  ]);

        HRESULT ( *NewParameterizedObjectNoConstructor )(
            ICorDebugEval2 * This,
              ICorDebugClass *pClass,
              ULONG32 nTypeArgs,
              ICorDebugType *ppTypeArgs[  ]);

        HRESULT ( *NewParameterizedArray )(
            ICorDebugEval2 * This,
              ICorDebugType *pElementType,
              ULONG32 rank,
              ULONG32 dims[  ],
              ULONG32 lowBounds[  ]);

        HRESULT ( *NewStringWithLength )(
            ICorDebugEval2 * This,
              LPCWSTR string,
              UINT uiLength);

        HRESULT ( *RudeAbort )(
            ICorDebugEval2 * This);


    } ICorDebugEval2Vtbl;

    struct ICorDebugEval2
    {
        CONST_VTBL struct ICorDebugEval2Vtbl *lpVtbl;
    };
#line 14085
 const IID IID_ICorDebugValue;
#line 14110
    typedef struct ICorDebugValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugValue * This);

        ULONG ( *Release )(
            ICorDebugValue * This);

        HRESULT ( *GetType )(
            ICorDebugValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);


    } ICorDebugValueVtbl;

    struct ICorDebugValue
    {
        CONST_VTBL struct ICorDebugValueVtbl *lpVtbl;
    };
#line 14195
 const IID IID_ICorDebugValue2;
#line 14211
    typedef struct ICorDebugValue2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugValue2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugValue2 * This);

        ULONG ( *Release )(
            ICorDebugValue2 * This);

        HRESULT ( *GetExactType )(
            ICorDebugValue2 * This,
              ICorDebugType **ppType);


    } ICorDebugValue2Vtbl;

    struct ICorDebugValue2
    {
        CONST_VTBL struct ICorDebugValue2Vtbl *lpVtbl;
    };
#line 14275
 const IID IID_ICorDebugValue3;
#line 14291
    typedef struct ICorDebugValue3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugValue3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugValue3 * This);

        ULONG ( *Release )(
            ICorDebugValue3 * This);

        HRESULT ( *GetSize64 )(
            ICorDebugValue3 * This,
              ULONG64 *pSize);


    } ICorDebugValue3Vtbl;

    struct ICorDebugValue3
    {
        CONST_VTBL struct ICorDebugValue3Vtbl *lpVtbl;
    };
#line 14355
 const IID IID_ICorDebugGenericValue;
#line 14374
    typedef struct ICorDebugGenericValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugGenericValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugGenericValue * This);

        ULONG ( *Release )(
            ICorDebugGenericValue * This);

        HRESULT ( *GetType )(
            ICorDebugGenericValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugGenericValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugGenericValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugGenericValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *GetValue )(
            ICorDebugGenericValue * This,
              void *pTo);

        HRESULT ( *SetValue )(
            ICorDebugGenericValue * This,
              void *pFrom);


    } ICorDebugGenericValueVtbl;

    struct ICorDebugGenericValue
    {
        CONST_VTBL struct ICorDebugGenericValueVtbl *lpVtbl;
    };
#line 14474
 const IID IID_ICorDebugReferenceValue;
#line 14502
    typedef struct ICorDebugReferenceValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugReferenceValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugReferenceValue * This);

        ULONG ( *Release )(
            ICorDebugReferenceValue * This);

        HRESULT ( *GetType )(
            ICorDebugReferenceValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugReferenceValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugReferenceValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugReferenceValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *IsNull )(
            ICorDebugReferenceValue * This,
              BOOL *pbNull);

        HRESULT ( *GetValue )(
            ICorDebugReferenceValue * This,
              CORDB_ADDRESS *pValue);

        HRESULT ( *SetValue )(
            ICorDebugReferenceValue * This,
              CORDB_ADDRESS value);

        HRESULT ( *Dereference )(
            ICorDebugReferenceValue * This,
              ICorDebugValue **ppValue);

        HRESULT ( *DereferenceStrong )(
            ICorDebugReferenceValue * This,
              ICorDebugValue **ppValue);


    } ICorDebugReferenceValueVtbl;

    struct ICorDebugReferenceValue
    {
        CONST_VTBL struct ICorDebugReferenceValueVtbl *lpVtbl;
    };
#line 14623
 const IID IID_ICorDebugHeapValue;
#line 14642
    typedef struct ICorDebugHeapValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHeapValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHeapValue * This);

        ULONG ( *Release )(
            ICorDebugHeapValue * This);

        HRESULT ( *GetType )(
            ICorDebugHeapValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugHeapValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugHeapValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugHeapValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *IsValid )(
            ICorDebugHeapValue * This,
              BOOL *pbValid);

        HRESULT ( *CreateRelocBreakpoint )(
            ICorDebugHeapValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);


    } ICorDebugHeapValueVtbl;

    struct ICorDebugHeapValue
    {
        CONST_VTBL struct ICorDebugHeapValueVtbl *lpVtbl;
    };
#line 14742
 const IID IID_ICorDebugHeapValue2;
#line 14759
    typedef struct ICorDebugHeapValue2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHeapValue2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHeapValue2 * This);

        ULONG ( *Release )(
            ICorDebugHeapValue2 * This);

        HRESULT ( *CreateHandle )(
            ICorDebugHeapValue2 * This,
              CorDebugHandleType type,
              ICorDebugHandleValue **ppHandle);


    } ICorDebugHeapValue2Vtbl;

    struct ICorDebugHeapValue2
    {
        CONST_VTBL struct ICorDebugHeapValue2Vtbl *lpVtbl;
    };
#line 14824
 const IID IID_ICorDebugHeapValue3;
#line 14844
    typedef struct ICorDebugHeapValue3Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHeapValue3 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHeapValue3 * This);

        ULONG ( *Release )(
            ICorDebugHeapValue3 * This);

        HRESULT ( *GetThreadOwningMonitorLock )(
            ICorDebugHeapValue3 * This,
              ICorDebugThread **ppThread,
              DWORD *pAcquisitionCount);

        HRESULT ( *GetMonitorEventWaitList )(
            ICorDebugHeapValue3 * This,
              ICorDebugThreadEnum **ppThreadEnum);


    } ICorDebugHeapValue3Vtbl;

    struct ICorDebugHeapValue3
    {
        CONST_VTBL struct ICorDebugHeapValue3Vtbl *lpVtbl;
    };
#line 14916
 const IID IID_ICorDebugHeapValue4;
#line 14932
    typedef struct ICorDebugHeapValue4Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHeapValue4 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHeapValue4 * This);

        ULONG ( *Release )(
            ICorDebugHeapValue4 * This);

        HRESULT ( *CreatePinnedHandle )(
            ICorDebugHeapValue4 * This,
              ICorDebugHandleValue **ppHandle);


    } ICorDebugHeapValue4Vtbl;

    struct ICorDebugHeapValue4
    {
        CONST_VTBL struct ICorDebugHeapValue4Vtbl *lpVtbl;
    };
#line 14996
 const IID IID_ICorDebugObjectValue;
#line 15033
    typedef struct ICorDebugObjectValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugObjectValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugObjectValue * This);

        ULONG ( *Release )(
            ICorDebugObjectValue * This);

        HRESULT ( *GetType )(
            ICorDebugObjectValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugObjectValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugObjectValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugObjectValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *GetClass )(
            ICorDebugObjectValue * This,
              ICorDebugClass **ppClass);

        HRESULT ( *GetFieldValue )(
            ICorDebugObjectValue * This,
              ICorDebugClass *pClass,
              mdFieldDef fieldDef,
              ICorDebugValue **ppValue);

        HRESULT ( *GetVirtualMethod )(
            ICorDebugObjectValue * This,
              mdMemberRef memberRef,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetContext )(
            ICorDebugObjectValue * This,
              ICorDebugContext **ppContext);

        HRESULT ( *IsValueClass )(
            ICorDebugObjectValue * This,
              BOOL *pbIsValueClass);

        HRESULT ( *GetManagedCopy )(
            ICorDebugObjectValue * This,
              IUnknown **ppObject);

        HRESULT ( *SetFromManagedCopy )(
            ICorDebugObjectValue * This,
              IUnknown *pObject);


    } ICorDebugObjectValueVtbl;

    struct ICorDebugObjectValue
    {
        CONST_VTBL struct ICorDebugObjectValueVtbl *lpVtbl;
    };
#line 15171
 const IID IID_ICorDebugObjectValue2;
#line 15189
    typedef struct ICorDebugObjectValue2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugObjectValue2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugObjectValue2 * This);

        ULONG ( *Release )(
            ICorDebugObjectValue2 * This);

        HRESULT ( *GetVirtualMethodAndType )(
            ICorDebugObjectValue2 * This,
              mdMemberRef memberRef,
              ICorDebugFunction **ppFunction,
              ICorDebugType **ppType);


    } ICorDebugObjectValue2Vtbl;

    struct ICorDebugObjectValue2
    {
        CONST_VTBL struct ICorDebugObjectValue2Vtbl *lpVtbl;
    };
#line 15255
 const IID IID_ICorDebugDelegateObjectValue;
#line 15274
    typedef struct ICorDebugDelegateObjectValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugDelegateObjectValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugDelegateObjectValue * This);

        ULONG ( *Release )(
            ICorDebugDelegateObjectValue * This);

        HRESULT ( *GetTarget )(
            ICorDebugDelegateObjectValue * This,
              ICorDebugReferenceValue **ppObject);

        HRESULT ( *GetFunction )(
            ICorDebugDelegateObjectValue * This,
              ICorDebugFunction **ppFunction);


    } ICorDebugDelegateObjectValueVtbl;

    struct ICorDebugDelegateObjectValue
    {
        CONST_VTBL struct ICorDebugDelegateObjectValueVtbl *lpVtbl;
    };
#line 15345
 const IID IID_ICorDebugBoxValue;
#line 15361
    typedef struct ICorDebugBoxValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugBoxValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugBoxValue * This);

        ULONG ( *Release )(
            ICorDebugBoxValue * This);

        HRESULT ( *GetType )(
            ICorDebugBoxValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugBoxValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugBoxValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugBoxValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *IsValid )(
            ICorDebugBoxValue * This,
              BOOL *pbValid);

        HRESULT ( *CreateRelocBreakpoint )(
            ICorDebugBoxValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *GetObject )(
            ICorDebugBoxValue * This,
              ICorDebugObjectValue **ppObject);


    } ICorDebugBoxValueVtbl;

    struct ICorDebugBoxValue
    {
        CONST_VTBL struct ICorDebugBoxValueVtbl *lpVtbl;
    };
#line 15465
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0105_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0105_v0_0_s_ifspec;
#line 15479
 const IID IID_ICorDebugStringValue;
#line 15500
    typedef struct ICorDebugStringValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugStringValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugStringValue * This);

        ULONG ( *Release )(
            ICorDebugStringValue * This);

        HRESULT ( *GetType )(
            ICorDebugStringValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugStringValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugStringValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugStringValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *IsValid )(
            ICorDebugStringValue * This,
              BOOL *pbValid);

        HRESULT ( *CreateRelocBreakpoint )(
            ICorDebugStringValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *GetLength )(
            ICorDebugStringValue * This,
              ULONG32 *pcchString);

        HRESULT ( *GetString )(
            ICorDebugStringValue * This,
              ULONG32 cchString,
              ULONG32 *pcchString,
              WCHAR szString[  ]);


    } ICorDebugStringValueVtbl;

    struct ICorDebugStringValue
    {
        CONST_VTBL struct ICorDebugStringValueVtbl *lpVtbl;
    };
#line 15613
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0106_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0106_v0_0_s_ifspec;
#line 15626
 const IID IID_ICorDebugArrayValue;
#line 15668
    typedef struct ICorDebugArrayValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugArrayValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugArrayValue * This);

        ULONG ( *Release )(
            ICorDebugArrayValue * This);

        HRESULT ( *GetType )(
            ICorDebugArrayValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugArrayValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugArrayValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugArrayValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *IsValid )(
            ICorDebugArrayValue * This,
              BOOL *pbValid);

        HRESULT ( *CreateRelocBreakpoint )(
            ICorDebugArrayValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *GetElementType )(
            ICorDebugArrayValue * This,
              CorElementType *pType);

        HRESULT ( *GetRank )(
            ICorDebugArrayValue * This,
              ULONG32 *pnRank);

        HRESULT ( *GetCount )(
            ICorDebugArrayValue * This,
              ULONG32 *pnCount);

        HRESULT ( *GetDimensions )(
            ICorDebugArrayValue * This,
              ULONG32 cdim,
              ULONG32 dims[  ]);

        HRESULT ( *HasBaseIndicies )(
            ICorDebugArrayValue * This,
              BOOL *pbHasBaseIndicies);

        HRESULT ( *GetBaseIndicies )(
            ICorDebugArrayValue * This,
              ULONG32 cdim,
              ULONG32 indicies[  ]);

        HRESULT ( *GetElement )(
            ICorDebugArrayValue * This,
              ULONG32 cdim,
              ULONG32 indices[  ],
              ICorDebugValue **ppValue);

        HRESULT ( *GetElementAtPosition )(
            ICorDebugArrayValue * This,
              ULONG32 nPosition,
              ICorDebugValue **ppValue);


    } ICorDebugArrayValueVtbl;

    struct ICorDebugArrayValue
    {
        CONST_VTBL struct ICorDebugArrayValueVtbl *lpVtbl;
    };
#line 15829
typedef
enum VariableLocationType
    {
        VLT_REGISTER	= 0,
        VLT_REGISTER_RELATIVE	= ( VLT_REGISTER + 1 ) ,
        VLT_INVALID	= ( VLT_REGISTER_RELATIVE + 1 )
    } 	VariableLocationType;


 const IID IID_ICorDebugVariableHome;
#line 15873
    typedef struct ICorDebugVariableHomeVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugVariableHome * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugVariableHome * This);

        ULONG ( *Release )(
            ICorDebugVariableHome * This);

        HRESULT ( *GetCode )(
            ICorDebugVariableHome * This,
              ICorDebugCode **ppCode);

        HRESULT ( *GetSlotIndex )(
            ICorDebugVariableHome * This,
              ULONG32 *pSlotIndex);

        HRESULT ( *GetArgumentIndex )(
            ICorDebugVariableHome * This,
              ULONG32 *pArgumentIndex);

        HRESULT ( *GetLiveRange )(
            ICorDebugVariableHome * This,
              ULONG32 *pStartOffset,
              ULONG32 *pEndOffset);

        HRESULT ( *GetLocationType )(
            ICorDebugVariableHome * This,
              VariableLocationType *pLocationType);

        HRESULT ( *GetRegister )(
            ICorDebugVariableHome * This,
              CorDebugRegister *pRegister);

        HRESULT ( *GetOffset )(
            ICorDebugVariableHome * This,
              LONG *pOffset);


    } ICorDebugVariableHomeVtbl;

    struct ICorDebugVariableHome
    {
        CONST_VTBL struct ICorDebugVariableHomeVtbl *lpVtbl;
    };
#line 15980
 const IID IID_ICorDebugHandleValue;
#line 15998
    typedef struct ICorDebugHandleValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugHandleValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugHandleValue * This);

        ULONG ( *Release )(
            ICorDebugHandleValue * This);

        HRESULT ( *GetType )(
            ICorDebugHandleValue * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugHandleValue * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugHandleValue * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugHandleValue * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *IsNull )(
            ICorDebugHandleValue * This,
              BOOL *pbNull);

        HRESULT ( *GetValue )(
            ICorDebugHandleValue * This,
              CORDB_ADDRESS *pValue);

        HRESULT ( *SetValue )(
            ICorDebugHandleValue * This,
              CORDB_ADDRESS value);

        HRESULT ( *Dereference )(
            ICorDebugHandleValue * This,
              ICorDebugValue **ppValue);

        HRESULT ( *DereferenceStrong )(
            ICorDebugHandleValue * This,
              ICorDebugValue **ppValue);

        HRESULT ( *GetHandleType )(
            ICorDebugHandleValue * This,
              CorDebugHandleType *pType);

        HRESULT ( *Dispose )(
            ICorDebugHandleValue * This);


    } ICorDebugHandleValueVtbl;

    struct ICorDebugHandleValue
    {
        CONST_VTBL struct ICorDebugHandleValueVtbl *lpVtbl;
    };
#line 16133
 const IID IID_ICorDebugContext;
#line 16146
    typedef struct ICorDebugContextVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugContext * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugContext * This);

        ULONG ( *Release )(
            ICorDebugContext * This);

        HRESULT ( *GetType )(
            ICorDebugContext * This,
              CorElementType *pType);

        HRESULT ( *GetSize )(
            ICorDebugContext * This,
              ULONG32 *pSize);

        HRESULT ( *GetAddress )(
            ICorDebugContext * This,
              CORDB_ADDRESS *pAddress);

        HRESULT ( *CreateBreakpoint )(
            ICorDebugContext * This,
              ICorDebugValueBreakpoint **ppBreakpoint);

        HRESULT ( *GetClass )(
            ICorDebugContext * This,
              ICorDebugClass **ppClass);

        HRESULT ( *GetFieldValue )(
            ICorDebugContext * This,
              ICorDebugClass *pClass,
              mdFieldDef fieldDef,
              ICorDebugValue **ppValue);

        HRESULT ( *GetVirtualMethod )(
            ICorDebugContext * This,
              mdMemberRef memberRef,
              ICorDebugFunction **ppFunction);

        HRESULT ( *GetContext )(
            ICorDebugContext * This,
              ICorDebugContext **ppContext);

        HRESULT ( *IsValueClass )(
            ICorDebugContext * This,
              BOOL *pbIsValueClass);

        HRESULT ( *GetManagedCopy )(
            ICorDebugContext * This,
              IUnknown **ppObject);

        HRESULT ( *SetFromManagedCopy )(
            ICorDebugContext * This,
              IUnknown *pObject);


    } ICorDebugContextVtbl;

    struct ICorDebugContext
    {
        CONST_VTBL struct ICorDebugContextVtbl *lpVtbl;
    };
#line 16285
 const IID IID_ICorDebugComObjectValue;
#line 16308
    typedef struct ICorDebugComObjectValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugComObjectValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugComObjectValue * This);

        ULONG ( *Release )(
            ICorDebugComObjectValue * This);

        HRESULT ( *GetCachedInterfaceTypes )(
            ICorDebugComObjectValue * This,
              BOOL bIInspectableOnly,
              ICorDebugTypeEnum **ppInterfacesEnum);

        HRESULT ( *GetCachedInterfacePointers )(
            ICorDebugComObjectValue * This,
              BOOL bIInspectableOnly,
              ULONG32 celt,
              ULONG32 *pcEltFetched,
              CORDB_ADDRESS *ptrs);


    } ICorDebugComObjectValueVtbl;

    struct ICorDebugComObjectValue
    {
        CONST_VTBL struct ICorDebugComObjectValueVtbl *lpVtbl;
    };
#line 16383
 const IID IID_ICorDebugObjectEnum;
#line 16401
    typedef struct ICorDebugObjectEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugObjectEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugObjectEnum * This);

        ULONG ( *Release )(
            ICorDebugObjectEnum * This);

        HRESULT ( *Skip )(
            ICorDebugObjectEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugObjectEnum * This);

        HRESULT ( *Clone )(
            ICorDebugObjectEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugObjectEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugObjectEnum * This,
              ULONG celt,
              CORDB_ADDRESS objects[  ],
              ULONG *pceltFetched);


    } ICorDebugObjectEnumVtbl;

    struct ICorDebugObjectEnum
    {
        CONST_VTBL struct ICorDebugObjectEnumVtbl *lpVtbl;
    };
#line 16495
 const IID IID_ICorDebugBreakpointEnum;
#line 16513
    typedef struct ICorDebugBreakpointEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugBreakpointEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugBreakpointEnum * This);

        ULONG ( *Release )(
            ICorDebugBreakpointEnum * This);

        HRESULT ( *Skip )(
            ICorDebugBreakpointEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugBreakpointEnum * This);

        HRESULT ( *Clone )(
            ICorDebugBreakpointEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugBreakpointEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugBreakpointEnum * This,
              ULONG celt,
              ICorDebugBreakpoint *breakpoints[  ],
              ULONG *pceltFetched);


    } ICorDebugBreakpointEnumVtbl;

    struct ICorDebugBreakpointEnum
    {
        CONST_VTBL struct ICorDebugBreakpointEnumVtbl *lpVtbl;
    };
#line 16607
 const IID IID_ICorDebugStepperEnum;
#line 16625
    typedef struct ICorDebugStepperEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugStepperEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugStepperEnum * This);

        ULONG ( *Release )(
            ICorDebugStepperEnum * This);

        HRESULT ( *Skip )(
            ICorDebugStepperEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugStepperEnum * This);

        HRESULT ( *Clone )(
            ICorDebugStepperEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugStepperEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugStepperEnum * This,
              ULONG celt,
              ICorDebugStepper *steppers[  ],
              ULONG *pceltFetched);


    } ICorDebugStepperEnumVtbl;

    struct ICorDebugStepperEnum
    {
        CONST_VTBL struct ICorDebugStepperEnumVtbl *lpVtbl;
    };
#line 16719
 const IID IID_ICorDebugProcessEnum;
#line 16737
    typedef struct ICorDebugProcessEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugProcessEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugProcessEnum * This);

        ULONG ( *Release )(
            ICorDebugProcessEnum * This);

        HRESULT ( *Skip )(
            ICorDebugProcessEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugProcessEnum * This);

        HRESULT ( *Clone )(
            ICorDebugProcessEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugProcessEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugProcessEnum * This,
              ULONG celt,
              ICorDebugProcess *processes[  ],
              ULONG *pceltFetched);


    } ICorDebugProcessEnumVtbl;

    struct ICorDebugProcessEnum
    {
        CONST_VTBL struct ICorDebugProcessEnumVtbl *lpVtbl;
    };
#line 16831
 const IID IID_ICorDebugThreadEnum;
#line 16849
    typedef struct ICorDebugThreadEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugThreadEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugThreadEnum * This);

        ULONG ( *Release )(
            ICorDebugThreadEnum * This);

        HRESULT ( *Skip )(
            ICorDebugThreadEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugThreadEnum * This);

        HRESULT ( *Clone )(
            ICorDebugThreadEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugThreadEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugThreadEnum * This,
              ULONG celt,
              ICorDebugThread *threads[  ],
              ULONG *pceltFetched);


    } ICorDebugThreadEnumVtbl;

    struct ICorDebugThreadEnum
    {
        CONST_VTBL struct ICorDebugThreadEnumVtbl *lpVtbl;
    };
#line 16943
 const IID IID_ICorDebugFrameEnum;
#line 16961
    typedef struct ICorDebugFrameEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugFrameEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugFrameEnum * This);

        ULONG ( *Release )(
            ICorDebugFrameEnum * This);

        HRESULT ( *Skip )(
            ICorDebugFrameEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugFrameEnum * This);

        HRESULT ( *Clone )(
            ICorDebugFrameEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugFrameEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugFrameEnum * This,
              ULONG celt,
              ICorDebugFrame *frames[  ],
              ULONG *pceltFetched);


    } ICorDebugFrameEnumVtbl;

    struct ICorDebugFrameEnum
    {
        CONST_VTBL struct ICorDebugFrameEnumVtbl *lpVtbl;
    };
#line 17055
 const IID IID_ICorDebugChainEnum;
#line 17073
    typedef struct ICorDebugChainEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugChainEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugChainEnum * This);

        ULONG ( *Release )(
            ICorDebugChainEnum * This);

        HRESULT ( *Skip )(
            ICorDebugChainEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugChainEnum * This);

        HRESULT ( *Clone )(
            ICorDebugChainEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugChainEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugChainEnum * This,
              ULONG celt,
              ICorDebugChain *chains[  ],
              ULONG *pceltFetched);


    } ICorDebugChainEnumVtbl;

    struct ICorDebugChainEnum
    {
        CONST_VTBL struct ICorDebugChainEnumVtbl *lpVtbl;
    };
#line 17167
 const IID IID_ICorDebugModuleEnum;
#line 17185
    typedef struct ICorDebugModuleEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugModuleEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugModuleEnum * This);

        ULONG ( *Release )(
            ICorDebugModuleEnum * This);

        HRESULT ( *Skip )(
            ICorDebugModuleEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugModuleEnum * This);

        HRESULT ( *Clone )(
            ICorDebugModuleEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugModuleEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugModuleEnum * This,
              ULONG celt,
              ICorDebugModule *modules[  ],
              ULONG *pceltFetched);


    } ICorDebugModuleEnumVtbl;

    struct ICorDebugModuleEnum
    {
        CONST_VTBL struct ICorDebugModuleEnumVtbl *lpVtbl;
    };
#line 17279
 const IID IID_ICorDebugValueEnum;
#line 17297
    typedef struct ICorDebugValueEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugValueEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugValueEnum * This);

        ULONG ( *Release )(
            ICorDebugValueEnum * This);

        HRESULT ( *Skip )(
            ICorDebugValueEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugValueEnum * This);

        HRESULT ( *Clone )(
            ICorDebugValueEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugValueEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugValueEnum * This,
              ULONG celt,
              ICorDebugValue *values[  ],
              ULONG *pceltFetched);


    } ICorDebugValueEnumVtbl;

    struct ICorDebugValueEnum
    {
        CONST_VTBL struct ICorDebugValueEnumVtbl *lpVtbl;
    };
#line 17391
 const IID IID_ICorDebugVariableHomeEnum;
#line 17409
    typedef struct ICorDebugVariableHomeEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugVariableHomeEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugVariableHomeEnum * This);

        ULONG ( *Release )(
            ICorDebugVariableHomeEnum * This);

        HRESULT ( *Skip )(
            ICorDebugVariableHomeEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugVariableHomeEnum * This);

        HRESULT ( *Clone )(
            ICorDebugVariableHomeEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugVariableHomeEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugVariableHomeEnum * This,
              ULONG celt,
              ICorDebugVariableHome *homes[  ],
              ULONG *pceltFetched);


    } ICorDebugVariableHomeEnumVtbl;

    struct ICorDebugVariableHomeEnum
    {
        CONST_VTBL struct ICorDebugVariableHomeEnumVtbl *lpVtbl;
    };
#line 17503
 const IID IID_ICorDebugCodeEnum;
#line 17521
    typedef struct ICorDebugCodeEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugCodeEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugCodeEnum * This);

        ULONG ( *Release )(
            ICorDebugCodeEnum * This);

        HRESULT ( *Skip )(
            ICorDebugCodeEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugCodeEnum * This);

        HRESULT ( *Clone )(
            ICorDebugCodeEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugCodeEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugCodeEnum * This,
              ULONG celt,
              ICorDebugCode *values[  ],
              ULONG *pceltFetched);


    } ICorDebugCodeEnumVtbl;

    struct ICorDebugCodeEnum
    {
        CONST_VTBL struct ICorDebugCodeEnumVtbl *lpVtbl;
    };
#line 17615
 const IID IID_ICorDebugTypeEnum;
#line 17633
    typedef struct ICorDebugTypeEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugTypeEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugTypeEnum * This);

        ULONG ( *Release )(
            ICorDebugTypeEnum * This);

        HRESULT ( *Skip )(
            ICorDebugTypeEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugTypeEnum * This);

        HRESULT ( *Clone )(
            ICorDebugTypeEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugTypeEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugTypeEnum * This,
              ULONG celt,
              ICorDebugType *values[  ],
              ULONG *pceltFetched);


    } ICorDebugTypeEnumVtbl;

    struct ICorDebugTypeEnum
    {
        CONST_VTBL struct ICorDebugTypeEnumVtbl *lpVtbl;
    };
#line 17727
 const IID IID_ICorDebugType;
#line 17763
    typedef struct ICorDebugTypeVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugType * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugType * This);

        ULONG ( *Release )(
            ICorDebugType * This);

        HRESULT ( *GetType )(
            ICorDebugType * This,
              CorElementType *ty);

        HRESULT ( *GetClass )(
            ICorDebugType * This,
              ICorDebugClass **ppClass);

        HRESULT ( *EnumerateTypeParameters )(
            ICorDebugType * This,
              ICorDebugTypeEnum **ppTyParEnum);

        HRESULT ( *GetFirstTypeParameter )(
            ICorDebugType * This,
              ICorDebugType **value);

        HRESULT ( *GetBase )(
            ICorDebugType * This,
              ICorDebugType **pBase);

        HRESULT ( *GetStaticFieldValue )(
            ICorDebugType * This,
              mdFieldDef fieldDef,
              ICorDebugFrame *pFrame,
              ICorDebugValue **ppValue);

        HRESULT ( *GetRank )(
            ICorDebugType * This,
              ULONG32 *pnRank);


    } ICorDebugTypeVtbl;

    struct ICorDebugType
    {
        CONST_VTBL struct ICorDebugTypeVtbl *lpVtbl;
    };
#line 17871
 const IID IID_ICorDebugType2;
#line 17887
    typedef struct ICorDebugType2Vtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugType2 * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugType2 * This);

        ULONG ( *Release )(
            ICorDebugType2 * This);

        HRESULT ( *GetTypeID )(
            ICorDebugType2 * This,
              COR_TYPEID *id);


    } ICorDebugType2Vtbl;

    struct ICorDebugType2
    {
        CONST_VTBL struct ICorDebugType2Vtbl *lpVtbl;
    };
#line 17951
 const IID IID_ICorDebugErrorInfoEnum;
#line 17969
    typedef struct ICorDebugErrorInfoEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugErrorInfoEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugErrorInfoEnum * This);

        ULONG ( *Release )(
            ICorDebugErrorInfoEnum * This);

        HRESULT ( *Skip )(
            ICorDebugErrorInfoEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugErrorInfoEnum * This);

        HRESULT ( *Clone )(
            ICorDebugErrorInfoEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugErrorInfoEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugErrorInfoEnum * This,
              ULONG celt,
              ICorDebugEditAndContinueErrorInfo *errors[  ],
              ULONG *pceltFetched);


    } ICorDebugErrorInfoEnumVtbl;

    struct ICorDebugErrorInfoEnum
    {
        CONST_VTBL struct ICorDebugErrorInfoEnumVtbl *lpVtbl;
    };
#line 18063
 const IID IID_ICorDebugAppDomainEnum;
#line 18081
    typedef struct ICorDebugAppDomainEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAppDomainEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAppDomainEnum * This);

        ULONG ( *Release )(
            ICorDebugAppDomainEnum * This);

        HRESULT ( *Skip )(
            ICorDebugAppDomainEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugAppDomainEnum * This);

        HRESULT ( *Clone )(
            ICorDebugAppDomainEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugAppDomainEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugAppDomainEnum * This,
              ULONG celt,
              ICorDebugAppDomain *values[  ],
              ULONG *pceltFetched);


    } ICorDebugAppDomainEnumVtbl;

    struct ICorDebugAppDomainEnum
    {
        CONST_VTBL struct ICorDebugAppDomainEnumVtbl *lpVtbl;
    };
#line 18175
 const IID IID_ICorDebugAssemblyEnum;
#line 18193
    typedef struct ICorDebugAssemblyEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugAssemblyEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugAssemblyEnum * This);

        ULONG ( *Release )(
            ICorDebugAssemblyEnum * This);

        HRESULT ( *Skip )(
            ICorDebugAssemblyEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugAssemblyEnum * This);

        HRESULT ( *Clone )(
            ICorDebugAssemblyEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugAssemblyEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugAssemblyEnum * This,
              ULONG celt,
              ICorDebugAssembly *values[  ],
              ULONG *pceltFetched);


    } ICorDebugAssemblyEnumVtbl;

    struct ICorDebugAssemblyEnum
    {
        CONST_VTBL struct ICorDebugAssemblyEnumVtbl *lpVtbl;
    };
#line 18287
 const IID IID_ICorDebugBlockingObjectEnum;
#line 18305
    typedef struct ICorDebugBlockingObjectEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugBlockingObjectEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugBlockingObjectEnum * This);

        ULONG ( *Release )(
            ICorDebugBlockingObjectEnum * This);

        HRESULT ( *Skip )(
            ICorDebugBlockingObjectEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugBlockingObjectEnum * This);

        HRESULT ( *Clone )(
            ICorDebugBlockingObjectEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugBlockingObjectEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugBlockingObjectEnum * This,
              ULONG celt,
              CorDebugBlockingObject values[  ],
              ULONG *pceltFetched);


    } ICorDebugBlockingObjectEnumVtbl;

    struct ICorDebugBlockingObjectEnum
    {
        CONST_VTBL struct ICorDebugBlockingObjectEnumVtbl *lpVtbl;
    };
#line 18395
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0130_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0130_v0_0_s_ifspec;
#line 18408
typedef
enum CorDebugMDAFlags
    {
        MDA_FLAG_SLIP	= 0x2
    } 	CorDebugMDAFlags;


 const IID IID_ICorDebugMDA;
#line 18449
    typedef struct ICorDebugMDAVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugMDA * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugMDA * This);

        ULONG ( *Release )(
            ICorDebugMDA * This);

        HRESULT ( *GetName )(
            ICorDebugMDA * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetDescription )(
            ICorDebugMDA * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetXML )(
            ICorDebugMDA * This,
              ULONG32 cchName,
              ULONG32 *pcchName,
              WCHAR szName[  ]);

        HRESULT ( *GetFlags )(
            ICorDebugMDA * This,
              CorDebugMDAFlags *pFlags);

        HRESULT ( *GetOSThreadId )(
            ICorDebugMDA * This,
              DWORD *pOsTid);


    } ICorDebugMDAVtbl;

    struct ICorDebugMDA
    {
        CONST_VTBL struct ICorDebugMDAVtbl *lpVtbl;
    };
#line 18543
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable:28718)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0131_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0131_v0_0_s_ifspec;
#line 18558
 const IID IID_ICorDebugEditAndContinueErrorInfo;
#line 18585
    typedef struct ICorDebugEditAndContinueErrorInfoVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugEditAndContinueErrorInfo * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugEditAndContinueErrorInfo * This);

        ULONG ( *Release )(
            ICorDebugEditAndContinueErrorInfo * This);

        HRESULT ( *GetModule )(
            ICorDebugEditAndContinueErrorInfo * This,
              ICorDebugModule **ppModule);

        HRESULT ( *GetToken )(
            ICorDebugEditAndContinueErrorInfo * This,
              mdToken *pToken);

        HRESULT ( *GetErrorCode )(
            ICorDebugEditAndContinueErrorInfo * This,
              HRESULT *pHr);

        HRESULT ( *GetString )(
            ICorDebugEditAndContinueErrorInfo * This,
              ULONG32 cchString,
              ULONG32 *pcchString,
              WCHAR szString[  ]);


    } ICorDebugEditAndContinueErrorInfoVtbl;

    struct ICorDebugEditAndContinueErrorInfo
    {
        CONST_VTBL struct ICorDebugEditAndContinueErrorInfoVtbl *lpVtbl;
    };
#line 18668
#pragma warning(pop)


extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0132_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_cordebug_0000_0132_v0_0_s_ifspec;
#line 18681
 const IID IID_ICorDebugEditAndContinueSnapshot;
#line 18718
    typedef struct ICorDebugEditAndContinueSnapshotVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugEditAndContinueSnapshot * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugEditAndContinueSnapshot * This);

        ULONG ( *Release )(
            ICorDebugEditAndContinueSnapshot * This);

        HRESULT ( *CopyMetaData )(
            ICorDebugEditAndContinueSnapshot * This,
              IStream *pIStream,
              GUID *pMvid);

        HRESULT ( *GetMvid )(
            ICorDebugEditAndContinueSnapshot * This,
              GUID *pMvid);

        HRESULT ( *GetRoDataRVA )(
            ICorDebugEditAndContinueSnapshot * This,
              ULONG32 *pRoDataRVA);

        HRESULT ( *GetRwDataRVA )(
            ICorDebugEditAndContinueSnapshot * This,
              ULONG32 *pRwDataRVA);

        HRESULT ( *SetPEBytes )(
            ICorDebugEditAndContinueSnapshot * This,
              IStream *pIStream);

        HRESULT ( *SetILMap )(
            ICorDebugEditAndContinueSnapshot * This,
              mdToken mdFunction,
              ULONG cMapSize,
              COR_IL_MAP map[  ]);

        HRESULT ( *SetPESymbolBytes )(
            ICorDebugEditAndContinueSnapshot * This,
              IStream *pIStream);


    } ICorDebugEditAndContinueSnapshotVtbl;

    struct ICorDebugEditAndContinueSnapshot
    {
        CONST_VTBL struct ICorDebugEditAndContinueSnapshotVtbl *lpVtbl;
    };
#line 18827
 const IID IID_ICorDebugExceptionObjectCallStackEnum;
#line 18845
    typedef struct ICorDebugExceptionObjectCallStackEnumVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugExceptionObjectCallStackEnum * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugExceptionObjectCallStackEnum * This);

        ULONG ( *Release )(
            ICorDebugExceptionObjectCallStackEnum * This);

        HRESULT ( *Skip )(
            ICorDebugExceptionObjectCallStackEnum * This,
              ULONG celt);

        HRESULT ( *Reset )(
            ICorDebugExceptionObjectCallStackEnum * This);

        HRESULT ( *Clone )(
            ICorDebugExceptionObjectCallStackEnum * This,
              ICorDebugEnum **ppEnum);

        HRESULT ( *GetCount )(
            ICorDebugExceptionObjectCallStackEnum * This,
              ULONG *pcelt);

        HRESULT ( *Next )(
            ICorDebugExceptionObjectCallStackEnum * This,
              ULONG celt,
              CorDebugExceptionObjectStackFrame values[  ],
              ULONG *pceltFetched);


    } ICorDebugExceptionObjectCallStackEnumVtbl;

    struct ICorDebugExceptionObjectCallStackEnum
    {
        CONST_VTBL struct ICorDebugExceptionObjectCallStackEnumVtbl *lpVtbl;
    };
#line 18939
 const IID IID_ICorDebugExceptionObjectValue;
#line 18955
    typedef struct ICorDebugExceptionObjectValueVtbl
    {


        HRESULT ( *QueryInterface )(
            ICorDebugExceptionObjectValue * This,
              const IID * riid,

            _COM_Outptr_  void **ppvObject);

        ULONG ( *AddRef )(
            ICorDebugExceptionObjectValue * This);

        ULONG ( *Release )(
            ICorDebugExceptionObjectValue * This);

        HRESULT ( *EnumerateExceptionCallStack )(
            ICorDebugExceptionObjectValue * This,
              ICorDebugExceptionObjectCallStackEnum **ppCallStackEnum);


    } ICorDebugExceptionObjectValueVtbl;

    struct ICorDebugExceptionObjectValue
    {
        CONST_VTBL struct ICorDebugExceptionObjectValueVtbl *lpVtbl;
    };
#line 19050
 const IID LIBID_CORDBLib;

 const CLSID CLSID_CorDebug;
#line 19060
 const CLSID CLSID_EmbeddedCLRCorDebug;
