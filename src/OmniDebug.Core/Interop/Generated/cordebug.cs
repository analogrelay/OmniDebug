// ReSharper disable All
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

unsafe record struct CorDebugManagedCallbackPtr(IntPtr Pointer)
{
    public CorDebugManagedCallback? Deref() => CorDebugManagedCallback.Create(this);
}

unsafe class CorDebugManagedCallback: CallableCOMWrapper
{
    ref readonly ICorDebugManagedCallbackVTable VTable => ref Unsafe.AsRef<ICorDebugManagedCallbackVTable>(_vtable);
    public static CorDebugManagedCallback? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugManagedCallback(punk) : null;
    public static CorDebugManagedCallback? Create(CorDebugManagedCallbackPtr p) => Create(p.Pointer);
    CorDebugManagedCallback(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugManagedCallback, punk)
    {
        SuppressRelease();
    }

    public HResult Breakpoint(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint)
        => VTable.BreakpointPtr(Self, pAppDomain, pThread, pBreakpoint);

    public HResult StepComplete(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugStepperPtr pStepper, CorDebugStepReason reason)
        => VTable.StepCompletePtr(Self, pAppDomain, pThread, pStepper, reason);

    public HResult Break(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread)
        => VTable.BreakPtr(Self, pAppDomain, thread);

    public HResult Exception(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, bool unhandled)
        => VTable.ExceptionPtr(Self, pAppDomain, pThread, unhandled);

    public HResult EvalComplete(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval)
        => VTable.EvalCompletePtr(Self, pAppDomain, pThread, pEval);

    public HResult EvalException(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval)
        => VTable.EvalExceptionPtr(Self, pAppDomain, pThread, pEval);

    public HResult CreateProcessW(CorDebugProcessPtr pProcess)
        => VTable.CreateProcessWPtr(Self, pProcess);

    public HResult ExitProcess(CorDebugProcessPtr pProcess)
        => VTable.ExitProcessPtr(Self, pProcess);

    public HResult CreateThread(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread)
        => VTable.CreateThreadPtr(Self, pAppDomain, thread);

    public HResult ExitThread(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread)
        => VTable.ExitThreadPtr(Self, pAppDomain, thread);

    public HResult LoadModule(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule)
        => VTable.LoadModulePtr(Self, pAppDomain, pModule);

    public HResult UnloadModule(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule)
        => VTable.UnloadModulePtr(Self, pAppDomain, pModule);

    public HResult LoadClass(CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c)
        => VTable.LoadClassPtr(Self, pAppDomain, c);

    public HResult UnloadClass(CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c)
        => VTable.UnloadClassPtr(Self, pAppDomain, c);

    public HResult DebuggerError(CorDebugProcessPtr pProcess, HResult errorHR, uint errorCode)
        => VTable.DebuggerErrorPtr(Self, pProcess, errorHR, errorCode);

    public HResult LogMessage(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, int* pLogSwitchName, int* pMessage)
        => VTable.LogMessagePtr(Self, pAppDomain, pThread, lLevel, pLogSwitchName, pMessage);

    public HResult LogSwitch(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, int* pLogSwitchName, int* pParentName)
        => VTable.LogSwitchPtr(Self, pAppDomain, pThread, lLevel, ulReason, pLogSwitchName, pParentName);

    public HResult CreateAppDomain(CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain)
        => VTable.CreateAppDomainPtr(Self, pProcess, pAppDomain);

    public HResult ExitAppDomain(CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain)
        => VTable.ExitAppDomainPtr(Self, pProcess, pAppDomain);

    public HResult LoadAssembly(CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly)
        => VTable.LoadAssemblyPtr(Self, pAppDomain, pAssembly);

    public HResult UnloadAssembly(CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly)
        => VTable.UnloadAssemblyPtr(Self, pAppDomain, pAssembly);

    public HResult ControlCTrap(CorDebugProcessPtr pProcess)
        => VTable.ControlCTrapPtr(Self, pProcess);

    public HResult NameChange(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread)
        => VTable.NameChangePtr(Self, pAppDomain, pThread);

    public HResult UpdateModuleSymbols(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule, IntPtr pSymbolStream)
        => VTable.UpdateModuleSymbolsPtr(Self, pAppDomain, pModule, pSymbolStream);

    public HResult EditAndContinueRemap(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction, bool fAccurate)
        => VTable.EditAndContinueRemapPtr(Self, pAppDomain, pThread, pFunction, fAccurate);

    public HResult BreakpointSetError(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint, uint dwError)
        => VTable.BreakpointSetErrorPtr(Self, pAppDomain, pThread, pBreakpoint, dwError);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugManagedCallbackVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugBreakpointPtr, HResult> BreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugStepperPtr, CorDebugStepReason, HResult> StepCompletePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, HResult> BreakPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, bool, HResult> ExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugEvalPtr, HResult> EvalCompletePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugEvalPtr, HResult> EvalExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, HResult> CreateProcessWPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, HResult> ExitProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, HResult> CreateThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, HResult> ExitThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugModulePtr, HResult> LoadModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugModulePtr, HResult> UnloadModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugClassPtr, HResult> LoadClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugClassPtr, HResult> UnloadClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, HResult, uint, HResult> DebuggerErrorPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, int, int*, int*, HResult> LogMessagePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, int, uint, int*, int*, HResult> LogSwitchPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, CorDebugAppDomainPtr, HResult> CreateAppDomainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, CorDebugAppDomainPtr, HResult> ExitAppDomainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugAssemblyPtr, HResult> LoadAssemblyPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugAssemblyPtr, HResult> UnloadAssemblyPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, HResult> ControlCTrapPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, HResult> NameChangePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugModulePtr, IntPtr, HResult> UpdateModuleSymbolsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugFunctionPtr, bool, HResult> EditAndContinueRemapPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugBreakpointPtr, uint, HResult> BreakpointSetErrorPtr;
    }
}


enum CorDebugStepReason
{
    STEP_NORMAL = 0,
    STEP_RETURN = 1,
    STEP_CALL = 2,
    STEP_EXCEPTION_FILTER = 3,
    STEP_EXCEPTION_HANDLER = 4,
    STEP_INTERCEPT = 5,
    STEP_EXIT = 6,
}

unsafe record struct CorDebugManagedCallback2Ptr(IntPtr Pointer)
{
    public CorDebugManagedCallback2? Deref() => CorDebugManagedCallback2.Create(this);
}

unsafe class CorDebugManagedCallback2: CallableCOMWrapper
{
    ref readonly ICorDebugManagedCallback2VTable VTable => ref Unsafe.AsRef<ICorDebugManagedCallback2VTable>(_vtable);
    public static CorDebugManagedCallback2? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugManagedCallback2(punk) : null;
    public static CorDebugManagedCallback2? Create(CorDebugManagedCallback2Ptr p) => Create(p.Pointer);
    CorDebugManagedCallback2(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugManagedCallback2, punk)
    {
        SuppressRelease();
    }

    public HResult FunctionRemapOpportunity(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pOldFunction, CorDebugFunctionPtr pNewFunction, uint oldILOffset)
        => VTable.FunctionRemapOpportunityPtr(Self, pAppDomain, pThread, pOldFunction, pNewFunction, oldILOffset);

    public HResult CreateConnection(CorDebugProcessPtr pProcess, uint dwConnectionId, int* pConnName)
        => VTable.CreateConnectionPtr(Self, pProcess, dwConnectionId, pConnName);

    public HResult ChangeConnection(CorDebugProcessPtr pProcess, uint dwConnectionId)
        => VTable.ChangeConnectionPtr(Self, pProcess, dwConnectionId);

    public HResult DestroyConnection(CorDebugProcessPtr pProcess, uint dwConnectionId)
        => VTable.DestroyConnectionPtr(Self, pProcess, dwConnectionId);

    public HResult Exception(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFramePtr pFrame, uint nOffset, CorDebugExceptionCallbackType dwEventType, uint dwFlags)
        => VTable.ExceptionPtr(Self, pAppDomain, pThread, pFrame, nOffset, dwEventType, dwFlags);

    public HResult ExceptionUnwind(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugExceptionUnwindCallbackType dwEventType, uint dwFlags)
        => VTable.ExceptionUnwindPtr(Self, pAppDomain, pThread, dwEventType, dwFlags);

    public HResult FunctionRemapComplete(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction)
        => VTable.FunctionRemapCompletePtr(Self, pAppDomain, pThread, pFunction);

    public HResult MDANotification(CorDebugControllerPtr pController, CorDebugThreadPtr pThread, CorDebugMDAPtr pMDA)
        => VTable.MDANotificationPtr(Self, pController, pThread, pMDA);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugManagedCallback2VTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugFunctionPtr, CorDebugFunctionPtr, uint, HResult> FunctionRemapOpportunityPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, uint, int*, HResult> CreateConnectionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, uint, HResult> ChangeConnectionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, uint, HResult> DestroyConnectionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugFramePtr, uint, CorDebugExceptionCallbackType, uint, HResult> ExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugExceptionUnwindCallbackType, uint, HResult> ExceptionUnwindPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, CorDebugFunctionPtr, HResult> FunctionRemapCompletePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugControllerPtr, CorDebugThreadPtr, CorDebugMDAPtr, HResult> MDANotificationPtr;
    }
}


enum CorDebugExceptionCallbackType
{
    DEBUG_EXCEPTION_FIRST_CHANCE = 1,
    DEBUG_EXCEPTION_USER_FIRST_CHANCE = 2,
    DEBUG_EXCEPTION_CATCH_HANDLER_FOUND = 3,
    DEBUG_EXCEPTION_UNHANDLED = 4,
}

enum CorDebugExceptionUnwindCallbackType
{
    DEBUG_EXCEPTION_UNWIND_BEGIN = 1,
    DEBUG_EXCEPTION_INTERCEPTED = 2,
}

unsafe record struct CorDebugPtr(IntPtr Pointer)
{
    public CorDebug? Deref() => CorDebug.Create(this);
}

unsafe class CorDebug: CallableCOMWrapper
{
    ref readonly ICorDebugVTable VTable => ref Unsafe.AsRef<ICorDebugVTable>(_vtable);
    public static CorDebug? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebug(punk) : null;
    public static CorDebug? Create(CorDebugPtr p) => Create(p.Pointer);
    CorDebug(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebug, punk)
    {
        SuppressRelease();
    }

    public HResult Initialize()
        => VTable.InitializePtr(Self);

    public HResult Terminate()
        => VTable.TerminatePtr(Self);

    public HResult SetManagedHandler(CorDebugManagedCallbackPtr pCallback)
        => VTable.SetManagedHandlerPtr(Self, pCallback);

    public HResult SetUnmanagedHandler(CorDebugUnmanagedCallbackPtr pCallback)
        => VTable.SetUnmanagedHandlerPtr(Self, pCallback);

    public HResult CreateProcessW(int* lpApplicationName, int* lpCommandLine, _SECURITY_ATTRIBUTES* lpProcessAttributes, _SECURITY_ATTRIBUTES* lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, void* lpEnvironment, int* lpCurrentDirectory, _STARTUPINFOW* lpStartupInfo, _PROCESS_INFORMATION* lpProcessInformation, CorDebugCreateProcessFlags debuggingFlags, CorDebugProcessPtr* ppProcess)
        => VTable.CreateProcessWPtr(Self, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, debuggingFlags, ppProcess);

    public HResult DebugActiveProcess(uint id, bool win32Attach, CorDebugProcessPtr* ppProcess)
        => VTable.DebugActiveProcessPtr(Self, id, win32Attach, ppProcess);

    public HResult EnumerateProcesses(CorDebugProcessEnumPtr* ppProcess)
        => VTable.EnumerateProcessesPtr(Self, ppProcess);

    public HResult GetProcess(uint dwProcessId, CorDebugProcessPtr* ppProcess)
        => VTable.GetProcessPtr(Self, dwProcessId, ppProcess);

    public HResult CanLaunchOrAttach(uint dwProcessId, bool win32DebuggingEnabled)
        => VTable.CanLaunchOrAttachPtr(Self, dwProcessId, win32DebuggingEnabled);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> InitializePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugManagedCallbackPtr, HResult> SetManagedHandlerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugUnmanagedCallbackPtr, HResult> SetUnmanagedHandlerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, int*, _SECURITY_ATTRIBUTES*, _SECURITY_ATTRIBUTES*, bool, uint, void*, int*, _STARTUPINFOW*, _PROCESS_INFORMATION*, CorDebugCreateProcessFlags, CorDebugProcessPtr*, HResult> CreateProcessWPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, bool, CorDebugProcessPtr*, HResult> DebugActiveProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessEnumPtr*, HResult> EnumerateProcessesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugProcessPtr*, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, bool, HResult> CanLaunchOrAttachPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct _SECURITY_ATTRIBUTES
{
    [FieldOffset(0)]
    public uint nLength;
    [FieldOffset(64)]
    public void* lpSecurityDescriptor;
    [FieldOffset(128)]
    public bool bInheritHandle;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _STARTUPINFOW
{
    [FieldOffset(0)]
    public uint cb;
    [FieldOffset(64)]
    public int* lpReserved_PAL_Undefined;
    [FieldOffset(128)]
    public int* lpDesktop_PAL_Undefined;
    [FieldOffset(192)]
    public int* lpTitle_PAL_Undefined;
    [FieldOffset(256)]
    public uint dwX_PAL_Undefined;
    [FieldOffset(288)]
    public uint dwY_PAL_Undefined;
    [FieldOffset(320)]
    public uint dwXSize_PAL_Undefined;
    [FieldOffset(352)]
    public uint dwYSize_PAL_Undefined;
    [FieldOffset(384)]
    public uint dwXCountChars_PAL_Undefined;
    [FieldOffset(416)]
    public uint dwYCountChars_PAL_Undefined;
    [FieldOffset(448)]
    public uint dwFillAttribute_PAL_Undefined;
    [FieldOffset(480)]
    public uint dwFlags;
    [FieldOffset(512)]
    public ushort wShowWindow_PAL_Undefined;
    [FieldOffset(528)]
    public ushort cbReserved2_PAL_Undefined;
    [FieldOffset(576)]
    public byte* lpReserved2_PAL_Undefined;
    [FieldOffset(640)]
    public void* hStdInput;
    [FieldOffset(704)]
    public void* hStdOutput;
    [FieldOffset(768)]
    public void* hStdError;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _PROCESS_INFORMATION
{
    [FieldOffset(0)]
    public void* hProcess;
    [FieldOffset(64)]
    public void* hThread;
    [FieldOffset(128)]
    public uint dwProcessId;
    [FieldOffset(160)]
    public uint dwThreadId_PAL_Undefined;
}

enum CorDebugCreateProcessFlags
{
    DEBUG_NO_SPECIAL_OPTIONS = 0,
}

unsafe record struct CorDebugControllerPtr(IntPtr Pointer)
{
    public CorDebugController? Deref() => CorDebugController.Create(this);
}

unsafe class CorDebugController: CallableCOMWrapper
{
    ref readonly ICorDebugControllerVTable VTable => ref Unsafe.AsRef<ICorDebugControllerVTable>(_vtable);
    public static CorDebugController? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugController(punk) : null;
    public static CorDebugController? Create(CorDebugControllerPtr p) => Create(p.Pointer);
    CorDebugController(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugController, punk)
    {
        SuppressRelease();
    }

    public HResult Stop(uint dwTimeoutIgnored)
        => VTable.StopPtr(Self, dwTimeoutIgnored);

    public HResult Continue(bool fIsOutOfBand)
        => VTable.ContinuePtr(Self, fIsOutOfBand);

    public HResult IsRunning(int* pbRunning)
        => VTable.IsRunningPtr(Self, pbRunning);

    public HResult HasQueuedCallbacks(CorDebugThreadPtr pThread, int* pbQueued)
        => VTable.HasQueuedCallbacksPtr(Self, pThread, pbQueued);

    public HResult EnumerateThreads(CorDebugThreadEnumPtr* ppThreads)
        => VTable.EnumerateThreadsPtr(Self, ppThreads);

    public HResult SetAllThreadsDebugState(CorDebugThreadState state, CorDebugThreadPtr pExceptThisThread)
        => VTable.SetAllThreadsDebugStatePtr(Self, state, pExceptThisThread);

    public HResult Detach()
        => VTable.DetachPtr(Self);

    public HResult Terminate(uint exitCode)
        => VTable.TerminatePtr(Self, exitCode);

    public HResult CanCommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, CorDebugErrorInfoEnumPtr* pError)
        => VTable.CanCommitChangesPtr(Self, cSnapshots, pSnapshots, pError);

    public HResult CommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, CorDebugErrorInfoEnumPtr* pError)
        => VTable.CommitChangesPtr(Self, cSnapshots, pSnapshots, pError);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugControllerVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> StopPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ContinuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsRunningPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr, int*, HResult> HasQueuedCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadEnumPtr*, HResult> EnumerateThreadsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, CorDebugThreadPtr, HResult> SetAllThreadsDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DetachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], CorDebugErrorInfoEnumPtr*, HResult> CanCommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], CorDebugErrorInfoEnumPtr*, HResult> CommitChangesPtr;
    }
}


enum CorDebugThreadState
{
    THREAD_RUN = 0,
    THREAD_SUSPEND = 1,
}

unsafe record struct CorDebugAppDomainPtr(IntPtr Pointer)
{
    public CorDebugAppDomain? Deref() => CorDebugAppDomain.Create(this);
}

unsafe class CorDebugAppDomain: CallableCOMWrapper
{
    ref readonly ICorDebugAppDomainVTable VTable => ref Unsafe.AsRef<ICorDebugAppDomainVTable>(_vtable);
    public static CorDebugAppDomain? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugAppDomain(punk) : null;
    public static CorDebugAppDomain? Create(CorDebugAppDomainPtr p) => Create(p.Pointer);
    CorDebugAppDomain(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugAppDomain, punk)
    {
        SuppressRelease();
    }

    public HResult Stop(uint dwTimeoutIgnored)
        => VTable.StopPtr(Self, dwTimeoutIgnored);

    public HResult Continue(bool fIsOutOfBand)
        => VTable.ContinuePtr(Self, fIsOutOfBand);

    public HResult IsRunning(int* pbRunning)
        => VTable.IsRunningPtr(Self, pbRunning);

    public HResult HasQueuedCallbacks(CorDebugThreadPtr pThread, int* pbQueued)
        => VTable.HasQueuedCallbacksPtr(Self, pThread, pbQueued);

    public HResult EnumerateThreads(CorDebugThreadEnumPtr* ppThreads)
        => VTable.EnumerateThreadsPtr(Self, ppThreads);

    public HResult SetAllThreadsDebugState(CorDebugThreadState state, CorDebugThreadPtr pExceptThisThread)
        => VTable.SetAllThreadsDebugStatePtr(Self, state, pExceptThisThread);

    public HResult Detach()
        => VTable.DetachPtr(Self);

    public HResult Terminate(uint exitCode)
        => VTable.TerminatePtr(Self, exitCode);

    public HResult CanCommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, CorDebugErrorInfoEnumPtr* pError)
        => VTable.CanCommitChangesPtr(Self, cSnapshots, pSnapshots, pError);

    public HResult CommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, CorDebugErrorInfoEnumPtr* pError)
        => VTable.CommitChangesPtr(Self, cSnapshots, pSnapshots, pError);

    public HResult GetProcess(CorDebugProcessPtr* ppProcess)
        => VTable.GetProcessPtr(Self, ppProcess);

    public HResult EnumerateAssemblies(CorDebugAssemblyEnumPtr* ppAssemblies)
        => VTable.EnumerateAssembliesPtr(Self, ppAssemblies);

    public HResult GetModuleFromMetaDataInterface(IntPtr pIMetaData, CorDebugModulePtr* ppModule)
        => VTable.GetModuleFromMetaDataInterfacePtr(Self, pIMetaData, ppModule);

    public HResult EnumerateBreakpoints(CorDebugBreakpointEnumPtr* ppBreakpoints)
        => VTable.EnumerateBreakpointsPtr(Self, ppBreakpoints);

    public HResult EnumerateSteppers(CorDebugStepperEnumPtr* ppSteppers)
        => VTable.EnumerateSteppersPtr(Self, ppSteppers);

    public HResult IsAttached(int* pbAttached)
        => VTable.IsAttachedPtr(Self, pbAttached);

    public HResult GetName(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetNamePtr(Self, cchName, pcchName, szName);

    public HResult GetObject(CorDebugValuePtr* ppObject)
        => VTable.GetObjectPtr(Self, ppObject);

    public HResult Attach()
        => VTable.AttachPtr(Self);

    public HResult GetID(uint* pId)
        => VTable.GetIDPtr(Self, pId);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAppDomainVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> StopPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ContinuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsRunningPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr, int*, HResult> HasQueuedCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadEnumPtr*, HResult> EnumerateThreadsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, CorDebugThreadPtr, HResult> SetAllThreadsDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DetachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], CorDebugErrorInfoEnumPtr*, HResult> CanCommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], CorDebugErrorInfoEnumPtr*, HResult> CommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr*, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAssemblyEnumPtr*, HResult> EnumerateAssembliesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, CorDebugModulePtr*, HResult> GetModuleFromMetaDataInterfacePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugBreakpointEnumPtr*, HResult> EnumerateBreakpointsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugStepperEnumPtr*, HResult> EnumerateSteppersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsAttachedPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValuePtr*, HResult> GetObjectPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> AttachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetIDPtr;
    }
}


unsafe record struct CorDebugAssemblyPtr(IntPtr Pointer)
{
    public CorDebugAssembly? Deref() => CorDebugAssembly.Create(this);
}

unsafe class CorDebugAssembly: CallableCOMWrapper
{
    ref readonly ICorDebugAssemblyVTable VTable => ref Unsafe.AsRef<ICorDebugAssemblyVTable>(_vtable);
    public static CorDebugAssembly? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugAssembly(punk) : null;
    public static CorDebugAssembly? Create(CorDebugAssemblyPtr p) => Create(p.Pointer);
    CorDebugAssembly(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugAssembly, punk)
    {
        SuppressRelease();
    }

    public HResult GetProcess(CorDebugProcessPtr* ppProcess)
        => VTable.GetProcessPtr(Self, ppProcess);

    public HResult GetAppDomain(CorDebugAppDomainPtr* ppAppDomain)
        => VTable.GetAppDomainPtr(Self, ppAppDomain);

    public HResult EnumerateModules(CorDebugModuleEnumPtr* ppModules)
        => VTable.EnumerateModulesPtr(Self, ppModules);

    public HResult GetCodeBase(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetCodeBasePtr(Self, cchName, pcchName, szName);

    public HResult GetName(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetNamePtr(Self, cchName, pcchName, szName);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAssemblyVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr*, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr*, HResult> GetAppDomainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugModuleEnumPtr*, HResult> EnumerateModulesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetCodeBasePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetNamePtr;
    }
}


unsafe record struct CorDebugProcessPtr(IntPtr Pointer)
{
    public CorDebugProcess? Deref() => CorDebugProcess.Create(this);
}

unsafe class CorDebugProcess: CallableCOMWrapper
{
    ref readonly ICorDebugProcessVTable VTable => ref Unsafe.AsRef<ICorDebugProcessVTable>(_vtable);
    public static CorDebugProcess? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugProcess(punk) : null;
    public static CorDebugProcess? Create(CorDebugProcessPtr p) => Create(p.Pointer);
    CorDebugProcess(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugProcess, punk)
    {
        SuppressRelease();
    }

    public HResult Stop(uint dwTimeoutIgnored)
        => VTable.StopPtr(Self, dwTimeoutIgnored);

    public HResult Continue(bool fIsOutOfBand)
        => VTable.ContinuePtr(Self, fIsOutOfBand);

    public HResult IsRunning(int* pbRunning)
        => VTable.IsRunningPtr(Self, pbRunning);

    public HResult HasQueuedCallbacks(CorDebugThreadPtr pThread, int* pbQueued)
        => VTable.HasQueuedCallbacksPtr(Self, pThread, pbQueued);

    public HResult EnumerateThreads(CorDebugThreadEnumPtr* ppThreads)
        => VTable.EnumerateThreadsPtr(Self, ppThreads);

    public HResult SetAllThreadsDebugState(CorDebugThreadState state, CorDebugThreadPtr pExceptThisThread)
        => VTable.SetAllThreadsDebugStatePtr(Self, state, pExceptThisThread);

    public HResult Detach()
        => VTable.DetachPtr(Self);

    public HResult Terminate(uint exitCode)
        => VTable.TerminatePtr(Self, exitCode);

    public HResult CanCommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, CorDebugErrorInfoEnumPtr* pError)
        => VTable.CanCommitChangesPtr(Self, cSnapshots, pSnapshots, pError);

    public HResult CommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, CorDebugErrorInfoEnumPtr* pError)
        => VTable.CommitChangesPtr(Self, cSnapshots, pSnapshots, pError);

    public HResult GetID(uint* pdwProcessId)
        => VTable.GetIDPtr(Self, pdwProcessId);

    public HResult GetHandle(void** phProcessHandle)
        => VTable.GetHandlePtr(Self, phProcessHandle);

    public HResult GetThread(uint dwThreadId, CorDebugThreadPtr* ppThread)
        => VTable.GetThreadPtr(Self, dwThreadId, ppThread);

    public HResult EnumerateObjects(CorDebugObjectEnumPtr* ppObjects)
        => VTable.EnumerateObjectsPtr(Self, ppObjects);

    public HResult IsTransitionStub(ulong address, int* pbTransitionStub)
        => VTable.IsTransitionStubPtr(Self, address, pbTransitionStub);

    public HResult IsOSSuspended(uint threadID, int* pbSuspended)
        => VTable.IsOSSuspendedPtr(Self, threadID, pbSuspended);

    public HResult GetThreadContext(uint threadID, uint contextSize, byte[] context)
        => VTable.GetThreadContextPtr(Self, threadID, contextSize, context);

    public HResult SetThreadContext(uint threadID, uint contextSize, byte[] context)
        => VTable.SetThreadContextPtr(Self, threadID, contextSize, context);

    public HResult ReadMemory(ulong address, uint size, byte[] buffer, uint* read)
        => VTable.ReadMemoryPtr(Self, address, size, buffer, read);

    public HResult WriteMemory(ulong address, uint size, byte[] buffer, uint* written)
        => VTable.WriteMemoryPtr(Self, address, size, buffer, written);

    public HResult ClearCurrentException(uint threadID)
        => VTable.ClearCurrentExceptionPtr(Self, threadID);

    public HResult EnableLogMessages(bool fOnOff)
        => VTable.EnableLogMessagesPtr(Self, fOnOff);

    public HResult ModifyLogSwitch(int WCHAR)
        => VTable.ModifyLogSwitchPtr(Self, WCHAR);

    public HResult EnumerateAppDomains(CorDebugAppDomainEnumPtr* ppAppDomains)
        => VTable.EnumerateAppDomainsPtr(Self, ppAppDomains);

    public HResult GetObject(CorDebugValuePtr* ppObject)
        => VTable.GetObjectPtr(Self, ppObject);

    public HResult ThreadForFiberCookie(uint fiberCookie, CorDebugThreadPtr* ppThread)
        => VTable.ThreadForFiberCookiePtr(Self, fiberCookie, ppThread);

    public HResult GetHelperThreadID(uint* pThreadID)
        => VTable.GetHelperThreadIDPtr(Self, pThreadID);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugProcessVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> StopPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ContinuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsRunningPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr, int*, HResult> HasQueuedCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadEnumPtr*, HResult> EnumerateThreadsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, CorDebugThreadPtr, HResult> SetAllThreadsDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DetachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], CorDebugErrorInfoEnumPtr*, HResult> CanCommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], CorDebugErrorInfoEnumPtr*, HResult> CommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetIDPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, void**, HResult> GetHandlePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugThreadPtr*, HResult> GetThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugObjectEnumPtr*, HResult> EnumerateObjectsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, int*, HResult> IsTransitionStubPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, int*, HResult> IsOSSuspendedPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, byte[], HResult> GetThreadContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, byte[], HResult> SetThreadContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, byte[], uint*, HResult> ReadMemoryPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, byte[], uint*, HResult> WriteMemoryPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> ClearCurrentExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> EnableLogMessagesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, HResult> ModifyLogSwitchPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainEnumPtr*, HResult> EnumerateAppDomainsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValuePtr*, HResult> GetObjectPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugThreadPtr*, HResult> ThreadForFiberCookiePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetHelperThreadIDPtr;
    }
}


unsafe record struct CorDebugBreakpointPtr(IntPtr Pointer)
{
    public CorDebugBreakpoint? Deref() => CorDebugBreakpoint.Create(this);
}

unsafe class CorDebugBreakpoint: CallableCOMWrapper
{
    ref readonly ICorDebugBreakpointVTable VTable => ref Unsafe.AsRef<ICorDebugBreakpointVTable>(_vtable);
    public static CorDebugBreakpoint? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugBreakpoint(punk) : null;
    public static CorDebugBreakpoint? Create(CorDebugBreakpointPtr p) => Create(p.Pointer);
    CorDebugBreakpoint(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugBreakpoint, punk)
    {
        SuppressRelease();
    }

    public HResult Activate(bool bActive)
        => VTable.ActivatePtr(Self, bActive);

    public HResult IsActive(int* pbActive)
        => VTable.IsActivePtr(Self, pbActive);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsActivePtr;
    }
}


unsafe record struct CorDebugStepperPtr(IntPtr Pointer)
{
    public CorDebugStepper? Deref() => CorDebugStepper.Create(this);
}

unsafe class CorDebugStepper: CallableCOMWrapper
{
    ref readonly ICorDebugStepperVTable VTable => ref Unsafe.AsRef<ICorDebugStepperVTable>(_vtable);
    public static CorDebugStepper? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugStepper(punk) : null;
    public static CorDebugStepper? Create(CorDebugStepperPtr p) => Create(p.Pointer);
    CorDebugStepper(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugStepper, punk)
    {
        SuppressRelease();
    }

    public HResult IsActive(int* pbActive)
        => VTable.IsActivePtr(Self, pbActive);

    public HResult Deactivate()
        => VTable.DeactivatePtr(Self);

    public HResult SetInterceptMask(CorDebugIntercept mask)
        => VTable.SetInterceptMaskPtr(Self, mask);

    public HResult SetUnmappedStopMask(CorDebugUnmappedStop mask)
        => VTable.SetUnmappedStopMaskPtr(Self, mask);

    public HResult Step(bool bStepIn)
        => VTable.StepPtr(Self, bStepIn);

    public HResult StepRange(bool bStepIn, COR_DEBUG_STEP_RANGE[] ranges, uint cRangeCount)
        => VTable.StepRangePtr(Self, bStepIn, ranges, cRangeCount);

    public HResult StepOut()
        => VTable.StepOutPtr(Self);

    public HResult SetRangeIL(bool bIL)
        => VTable.SetRangeILPtr(Self, bIL);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugStepperVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DeactivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugIntercept, HResult> SetInterceptMaskPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugUnmappedStop, HResult> SetUnmappedStopMaskPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> StepPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, COR_DEBUG_STEP_RANGE[], uint, HResult> StepRangePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> StepOutPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> SetRangeILPtr;
    }
}


enum CorDebugIntercept
{
    INTERCEPT_NONE = 0,
    INTERCEPT_CLASS_INIT = 1,
    INTERCEPT_EXCEPTION_FILTER = 2,
    INTERCEPT_SECURITY = 4,
    INTERCEPT_CONTEXT_POLICY = 8,
    INTERCEPT_INTERCEPTION = 16,
    INTERCEPT_ALL = 65535,
}

enum CorDebugUnmappedStop
{
    STOP_NONE = 0,
    STOP_PROLOG = 1,
    STOP_EPILOG = 2,
    STOP_NO_MAPPING_INFO = 4,
    STOP_OTHER_UNMAPPED = 8,
    STOP_UNMANAGED = 16,
    STOP_ALL = 65535,
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct COR_DEBUG_STEP_RANGE
{
    [FieldOffset(0)]
    public uint startOffset;
    [FieldOffset(32)]
    public uint endOffset;
}

unsafe record struct CorDebugThreadPtr(IntPtr Pointer)
{
    public CorDebugThread? Deref() => CorDebugThread.Create(this);
}

unsafe class CorDebugThread: CallableCOMWrapper
{
    ref readonly ICorDebugThreadVTable VTable => ref Unsafe.AsRef<ICorDebugThreadVTable>(_vtable);
    public static CorDebugThread? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugThread(punk) : null;
    public static CorDebugThread? Create(CorDebugThreadPtr p) => Create(p.Pointer);
    CorDebugThread(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugThread, punk)
    {
        SuppressRelease();
    }

    public HResult GetProcess(CorDebugProcessPtr* ppProcess)
        => VTable.GetProcessPtr(Self, ppProcess);

    public HResult GetID(uint* pdwThreadId)
        => VTable.GetIDPtr(Self, pdwThreadId);

    public HResult GetHandle(void** phThreadHandle)
        => VTable.GetHandlePtr(Self, phThreadHandle);

    public HResult GetAppDomain(CorDebugAppDomainPtr* ppAppDomain)
        => VTable.GetAppDomainPtr(Self, ppAppDomain);

    public HResult SetDebugState(CorDebugThreadState state)
        => VTable.SetDebugStatePtr(Self, state);

    public HResult GetDebugState(CorDebugThreadState* pState)
        => VTable.GetDebugStatePtr(Self, pState);

    public HResult GetUserState(CorDebugUserState* pState)
        => VTable.GetUserStatePtr(Self, pState);

    public HResult GetCurrentException(CorDebugValuePtr* ppExceptionObject)
        => VTable.GetCurrentExceptionPtr(Self, ppExceptionObject);

    public HResult ClearCurrentException()
        => VTable.ClearCurrentExceptionPtr(Self);

    public HResult CreateStepper(CorDebugStepperPtr* ppStepper)
        => VTable.CreateStepperPtr(Self, ppStepper);

    public HResult EnumerateChains(CorDebugChainEnumPtr* ppChains)
        => VTable.EnumerateChainsPtr(Self, ppChains);

    public HResult GetActiveChain(CorDebugChainPtr* ppChain)
        => VTable.GetActiveChainPtr(Self, ppChain);

    public HResult GetActiveFrame(CorDebugFramePtr* ppFrame)
        => VTable.GetActiveFramePtr(Self, ppFrame);

    public HResult GetRegisterSet(CorDebugRegisterSetPtr* ppRegisters)
        => VTable.GetRegisterSetPtr(Self, ppRegisters);

    public HResult CreateEval(CorDebugEvalPtr* ppEval)
        => VTable.CreateEvalPtr(Self, ppEval);

    public HResult GetObject(CorDebugValuePtr* ppObject)
        => VTable.GetObjectPtr(Self, ppObject);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugThreadVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr*, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetIDPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, void**, HResult> GetHandlePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr*, HResult> GetAppDomainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, HResult> SetDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState*, HResult> GetDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugUserState*, HResult> GetUserStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValuePtr*, HResult> GetCurrentExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ClearCurrentExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugStepperPtr*, HResult> CreateStepperPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainEnumPtr*, HResult> EnumerateChainsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainPtr*, HResult> GetActiveChainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFramePtr*, HResult> GetActiveFramePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugRegisterSetPtr*, HResult> GetRegisterSetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEvalPtr*, HResult> CreateEvalPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValuePtr*, HResult> GetObjectPtr;
    }
}


enum CorDebugUserState
{
    USER_STOP_REQUESTED = 1,
    USER_SUSPEND_REQUESTED = 2,
    USER_BACKGROUND = 4,
    USER_UNSTARTED = 8,
    USER_STOPPED = 16,
    USER_WAIT_SLEEP_JOIN = 32,
    USER_SUSPENDED = 64,
    USER_UNSAFE_POINT = 128,
    USER_THREADPOOL = 256,
}

unsafe record struct CorDebugChainPtr(IntPtr Pointer)
{
    public CorDebugChain? Deref() => CorDebugChain.Create(this);
}

unsafe class CorDebugChain: CallableCOMWrapper
{
    ref readonly ICorDebugChainVTable VTable => ref Unsafe.AsRef<ICorDebugChainVTable>(_vtable);
    public static CorDebugChain? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugChain(punk) : null;
    public static CorDebugChain? Create(CorDebugChainPtr p) => Create(p.Pointer);
    CorDebugChain(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugChain, punk)
    {
        SuppressRelease();
    }

    public HResult GetThread(CorDebugThreadPtr* ppThread)
        => VTable.GetThreadPtr(Self, ppThread);

    public HResult GetStackRange(ulong* pStart, ulong* pEnd)
        => VTable.GetStackRangePtr(Self, pStart, pEnd);

    public HResult GetContext(CorDebugContextPtr* ppContext)
        => VTable.GetContextPtr(Self, ppContext);

    public HResult GetCaller(CorDebugChainPtr* ppChain)
        => VTable.GetCallerPtr(Self, ppChain);

    public HResult GetCallee(CorDebugChainPtr* ppChain)
        => VTable.GetCalleePtr(Self, ppChain);

    public HResult GetPrevious(CorDebugChainPtr* ppChain)
        => VTable.GetPreviousPtr(Self, ppChain);

    public HResult GetNext(CorDebugChainPtr* ppChain)
        => VTable.GetNextPtr(Self, ppChain);

    public HResult IsManaged(int* pManaged)
        => VTable.IsManagedPtr(Self, pManaged);

    public HResult EnumerateFrames(CorDebugFrameEnumPtr* ppFrames)
        => VTable.EnumerateFramesPtr(Self, ppFrames);

    public HResult GetActiveFrame(CorDebugFramePtr* ppFrame)
        => VTable.GetActiveFramePtr(Self, ppFrame);

    public HResult GetRegisterSet(CorDebugRegisterSetPtr* ppRegisters)
        => VTable.GetRegisterSetPtr(Self, ppRegisters);

    public HResult GetReason(CorDebugChainReason* pReason)
        => VTable.GetReasonPtr(Self, pReason);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugChainVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr*, HResult> GetThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, ulong*, HResult> GetStackRangePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugContextPtr*, HResult> GetContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainPtr*, HResult> GetCallerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainPtr*, HResult> GetCalleePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainPtr*, HResult> GetPreviousPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainPtr*, HResult> GetNextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsManagedPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFrameEnumPtr*, HResult> EnumerateFramesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFramePtr*, HResult> GetActiveFramePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugRegisterSetPtr*, HResult> GetRegisterSetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainReason*, HResult> GetReasonPtr;
    }
}


enum CorDebugChainReason
{
    CHAIN_NONE = 0,
    CHAIN_CLASS_INIT = 1,
    CHAIN_EXCEPTION_FILTER = 2,
    CHAIN_SECURITY = 4,
    CHAIN_CONTEXT_POLICY = 8,
    CHAIN_INTERCEPTION = 16,
    CHAIN_PROCESS_START = 32,
    CHAIN_THREAD_START = 64,
    CHAIN_ENTER_MANAGED = 128,
    CHAIN_ENTER_UNMANAGED = 256,
    CHAIN_DEBUGGER_EVAL = 512,
    CHAIN_CONTEXT_SWITCH = 1024,
    CHAIN_FUNC_EVAL = 2048,
}

unsafe record struct CorDebugFramePtr(IntPtr Pointer)
{
    public CorDebugFrame? Deref() => CorDebugFrame.Create(this);
}

unsafe class CorDebugFrame: CallableCOMWrapper
{
    ref readonly ICorDebugFrameVTable VTable => ref Unsafe.AsRef<ICorDebugFrameVTable>(_vtable);
    public static CorDebugFrame? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugFrame(punk) : null;
    public static CorDebugFrame? Create(CorDebugFramePtr p) => Create(p.Pointer);
    CorDebugFrame(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugFrame, punk)
    {
        SuppressRelease();
    }

    public HResult GetChain(CorDebugChainPtr* ppChain)
        => VTable.GetChainPtr(Self, ppChain);

    public HResult GetCode(CorDebugCodePtr* ppCode)
        => VTable.GetCodePtr(Self, ppCode);

    public HResult GetFunction(CorDebugFunctionPtr* ppFunction)
        => VTable.GetFunctionPtr(Self, ppFunction);

    public HResult GetFunctionToken(int* pToken)
        => VTable.GetFunctionTokenPtr(Self, pToken);

    public HResult GetStackRange(ulong* pStart, ulong* pEnd)
        => VTable.GetStackRangePtr(Self, pStart, pEnd);

    public HResult GetCaller(CorDebugFramePtr* ppFrame)
        => VTable.GetCallerPtr(Self, ppFrame);

    public HResult GetCallee(CorDebugFramePtr* ppFrame)
        => VTable.GetCalleePtr(Self, ppFrame);

    public HResult CreateStepper(CorDebugStepperPtr* ppStepper)
        => VTable.CreateStepperPtr(Self, ppStepper);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFrameVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugChainPtr*, HResult> GetChainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugCodePtr*, HResult> GetCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr*, HResult> GetFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetFunctionTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, ulong*, HResult> GetStackRangePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFramePtr*, HResult> GetCallerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFramePtr*, HResult> GetCalleePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugStepperPtr*, HResult> CreateStepperPtr;
    }
}


unsafe record struct CorDebugModulePtr(IntPtr Pointer)
{
    public CorDebugModule? Deref() => CorDebugModule.Create(this);
}

unsafe class CorDebugModule: CallableCOMWrapper
{
    ref readonly ICorDebugModuleVTable VTable => ref Unsafe.AsRef<ICorDebugModuleVTable>(_vtable);
    public static CorDebugModule? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugModule(punk) : null;
    public static CorDebugModule? Create(CorDebugModulePtr p) => Create(p.Pointer);
    CorDebugModule(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugModule, punk)
    {
        SuppressRelease();
    }

    public HResult GetProcess(CorDebugProcessPtr* ppProcess)
        => VTable.GetProcessPtr(Self, ppProcess);

    public HResult GetBaseAddress(ulong* pAddress)
        => VTable.GetBaseAddressPtr(Self, pAddress);

    public HResult GetAssembly(CorDebugAssemblyPtr* ppAssembly)
        => VTable.GetAssemblyPtr(Self, ppAssembly);

    public HResult GetName(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetNamePtr(Self, cchName, pcchName, szName);

    public HResult EnableJITDebugging(bool bTrackJITInfo, bool bAllowJitOpts)
        => VTable.EnableJITDebuggingPtr(Self, bTrackJITInfo, bAllowJitOpts);

    public HResult EnableClassLoadCallbacks(bool bClassLoadCallbacks)
        => VTable.EnableClassLoadCallbacksPtr(Self, bClassLoadCallbacks);

    public HResult GetFunctionFromToken(int methodDef, CorDebugFunctionPtr* ppFunction)
        => VTable.GetFunctionFromTokenPtr(Self, methodDef, ppFunction);

    public HResult GetFunctionFromRVA(ulong rva, CorDebugFunctionPtr* ppFunction)
        => VTable.GetFunctionFromRVAPtr(Self, rva, ppFunction);

    public HResult GetClassFromToken(int typeDef, CorDebugClassPtr* ppClass)
        => VTable.GetClassFromTokenPtr(Self, typeDef, ppClass);

    public HResult CreateBreakpoint(CorDebugModuleBreakpointPtr* ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ppBreakpoint);

    public HResult GetEditAndContinueSnapshot(CorDebugEditAndContinueSnapshotPtr* ppEditAndContinueSnapshot)
        => VTable.GetEditAndContinueSnapshotPtr(Self, ppEditAndContinueSnapshot);

    public HResult GetMetaDataInterface(Guid* riid, IntPtr* ppObj)
        => VTable.GetMetaDataInterfacePtr(Self, riid, ppObj);

    public HResult GetToken(int* pToken)
        => VTable.GetTokenPtr(Self, pToken);

    public HResult IsDynamic(int* pDynamic)
        => VTable.IsDynamicPtr(Self, pDynamic);

    public HResult GetGlobalVariableValue(int fieldDef, CorDebugValuePtr* ppValue)
        => VTable.GetGlobalVariableValuePtr(Self, fieldDef, ppValue);

    public HResult GetSize(uint* pcBytes)
        => VTable.GetSizePtr(Self, pcBytes);

    public HResult IsInMemory(int* pInMemory)
        => VTable.IsInMemoryPtr(Self, pInMemory);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugModuleVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr*, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, HResult> GetBaseAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAssemblyPtr*, HResult> GetAssemblyPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, bool, HResult> EnableJITDebuggingPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> EnableClassLoadCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugFunctionPtr*, HResult> GetFunctionFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, CorDebugFunctionPtr*, HResult> GetFunctionFromRVAPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugClassPtr*, HResult> GetClassFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugModuleBreakpointPtr*, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEditAndContinueSnapshotPtr*, HResult> GetEditAndContinueSnapshotPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, HResult> GetMetaDataInterfacePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsDynamicPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugValuePtr*, HResult> GetGlobalVariableValuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsInMemoryPtr;
    }
}


unsafe record struct CorDebugFunctionPtr(IntPtr Pointer)
{
    public CorDebugFunction? Deref() => CorDebugFunction.Create(this);
}

unsafe class CorDebugFunction: CallableCOMWrapper
{
    ref readonly ICorDebugFunctionVTable VTable => ref Unsafe.AsRef<ICorDebugFunctionVTable>(_vtable);
    public static CorDebugFunction? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugFunction(punk) : null;
    public static CorDebugFunction? Create(CorDebugFunctionPtr p) => Create(p.Pointer);
    CorDebugFunction(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugFunction, punk)
    {
        SuppressRelease();
    }

    public HResult GetModule(CorDebugModulePtr* ppModule)
        => VTable.GetModulePtr(Self, ppModule);

    public HResult GetClass(CorDebugClassPtr* ppClass)
        => VTable.GetClassPtr(Self, ppClass);

    public HResult GetToken(int* pMethodDef)
        => VTable.GetTokenPtr(Self, pMethodDef);

    public HResult GetILCode(CorDebugCodePtr* ppCode)
        => VTable.GetILCodePtr(Self, ppCode);

    public HResult GetNativeCode(CorDebugCodePtr* ppCode)
        => VTable.GetNativeCodePtr(Self, ppCode);

    public HResult CreateBreakpoint(CorDebugFunctionBreakpointPtr* ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ppBreakpoint);

    public HResult GetLocalVarSigToken(int* pmdSig)
        => VTable.GetLocalVarSigTokenPtr(Self, pmdSig);

    public HResult GetCurrentVersionNumber(uint* pnCurrentVersion)
        => VTable.GetCurrentVersionNumberPtr(Self, pnCurrentVersion);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFunctionVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugModulePtr*, HResult> GetModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugClassPtr*, HResult> GetClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugCodePtr*, HResult> GetILCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugCodePtr*, HResult> GetNativeCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionBreakpointPtr*, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetLocalVarSigTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCurrentVersionNumberPtr;
    }
}


unsafe record struct CorDebugCodePtr(IntPtr Pointer)
{
    public CorDebugCode? Deref() => CorDebugCode.Create(this);
}

unsafe class CorDebugCode: CallableCOMWrapper
{
    ref readonly ICorDebugCodeVTable VTable => ref Unsafe.AsRef<ICorDebugCodeVTable>(_vtable);
    public static CorDebugCode? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugCode(punk) : null;
    public static CorDebugCode? Create(CorDebugCodePtr p) => Create(p.Pointer);
    CorDebugCode(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugCode, punk)
    {
        SuppressRelease();
    }

    public HResult IsIL(int* pbIL)
        => VTable.IsILPtr(Self, pbIL);

    public HResult GetFunction(CorDebugFunctionPtr* ppFunction)
        => VTable.GetFunctionPtr(Self, ppFunction);

    public HResult GetAddress(ulong* pStart)
        => VTable.GetAddressPtr(Self, pStart);

    public HResult GetSize(uint* pcBytes)
        => VTable.GetSizePtr(Self, pcBytes);

    public HResult CreateBreakpoint(uint offset, CorDebugFunctionBreakpointPtr* ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, offset, ppBreakpoint);

    public HResult GetCode(uint startOffset, uint endOffset, uint cBufferAlloc, byte[] buffer, uint* pcBufferSize)
        => VTable.GetCodePtr(Self, startOffset, endOffset, cBufferAlloc, buffer, pcBufferSize);

    public HResult GetVersionNumber(uint* nVersion)
        => VTable.GetVersionNumberPtr(Self, nVersion);

    public HResult GetILToNativeMapping(uint cMap, uint* pcMap, COR_DEBUG_IL_TO_NATIVE_MAP[] map)
        => VTable.GetILToNativeMappingPtr(Self, cMap, pcMap, map);

    public HResult GetEnCRemapSequencePoints(uint cMap, uint* pcMap, uint[] offsets)
        => VTable.GetEnCRemapSequencePointsPtr(Self, cMap, pcMap, offsets);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugCodeVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsILPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr*, HResult> GetFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, HResult> GetAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugFunctionBreakpointPtr*, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, uint, byte[], uint*, HResult> GetCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetVersionNumberPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, COR_DEBUG_IL_TO_NATIVE_MAP[], HResult> GetILToNativeMappingPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, uint[], HResult> GetEnCRemapSequencePointsPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct COR_DEBUG_IL_TO_NATIVE_MAP
{
    [FieldOffset(0)]
    public uint ilOffset;
    [FieldOffset(32)]
    public uint nativeStartOffset;
    [FieldOffset(64)]
    public uint nativeEndOffset;
}

unsafe record struct CorDebugClassPtr(IntPtr Pointer)
{
    public CorDebugClass? Deref() => CorDebugClass.Create(this);
}

unsafe class CorDebugClass: CallableCOMWrapper
{
    ref readonly ICorDebugClassVTable VTable => ref Unsafe.AsRef<ICorDebugClassVTable>(_vtable);
    public static CorDebugClass? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugClass(punk) : null;
    public static CorDebugClass? Create(CorDebugClassPtr p) => Create(p.Pointer);
    CorDebugClass(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugClass, punk)
    {
        SuppressRelease();
    }

    public HResult GetModule(CorDebugModulePtr* pModule)
        => VTable.GetModulePtr(Self, pModule);

    public HResult GetToken(int* pTypeDef)
        => VTable.GetTokenPtr(Self, pTypeDef);

    public HResult GetStaticFieldValue(int fieldDef, CorDebugFramePtr pFrame, CorDebugValuePtr* ppValue)
        => VTable.GetStaticFieldValuePtr(Self, fieldDef, pFrame, ppValue);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugClassVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugModulePtr*, HResult> GetModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugFramePtr, CorDebugValuePtr*, HResult> GetStaticFieldValuePtr;
    }
}


unsafe record struct CorDebugEvalPtr(IntPtr Pointer)
{
    public CorDebugEval? Deref() => CorDebugEval.Create(this);
}

unsafe class CorDebugEval: CallableCOMWrapper
{
    ref readonly ICorDebugEvalVTable VTable => ref Unsafe.AsRef<ICorDebugEvalVTable>(_vtable);
    public static CorDebugEval? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugEval(punk) : null;
    public static CorDebugEval? Create(CorDebugEvalPtr p) => Create(p.Pointer);
    CorDebugEval(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugEval, punk)
    {
        SuppressRelease();
    }

    public HResult CallFunction(CorDebugFunctionPtr pFunction, uint nArgs, CorDebugValuePtr[] ppArgs)
        => VTable.CallFunctionPtr(Self, pFunction, nArgs, ppArgs);

    public HResult NewObject(CorDebugFunctionPtr pConstructor, uint nArgs, CorDebugValuePtr[] ppArgs)
        => VTable.NewObjectPtr(Self, pConstructor, nArgs, ppArgs);

    public HResult NewObjectNoConstructor(CorDebugClassPtr pClass)
        => VTable.NewObjectNoConstructorPtr(Self, pClass);

    public HResult NewString(int* @string)
        => VTable.NewStringPtr(Self, @string);

    public HResult NewArray(int elementType, CorDebugClassPtr pElementClass, uint rank, uint[] dims, uint[] lowBounds)
        => VTable.NewArrayPtr(Self, elementType, pElementClass, rank, dims, lowBounds);

    public HResult IsActive(int* pbActive)
        => VTable.IsActivePtr(Self, pbActive);

    public HResult Abort()
        => VTable.AbortPtr(Self);

    public HResult GetResult(CorDebugValuePtr* ppResult)
        => VTable.GetResultPtr(Self, ppResult);

    public HResult GetThread(CorDebugThreadPtr* ppThread)
        => VTable.GetThreadPtr(Self, ppThread);

    public HResult CreateValue(int elementType, CorDebugClassPtr pElementClass, CorDebugValuePtr* ppValue)
        => VTable.CreateValuePtr(Self, elementType, pElementClass, ppValue);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEvalVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr, uint, CorDebugValuePtr[], HResult> CallFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr, uint, CorDebugValuePtr[], HResult> NewObjectPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugClassPtr, HResult> NewObjectNoConstructorPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> NewStringPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugClassPtr, uint, uint[], uint[], HResult> NewArrayPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> AbortPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValuePtr*, HResult> GetResultPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr*, HResult> GetThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugClassPtr, CorDebugValuePtr*, HResult> CreateValuePtr;
    }
}


unsafe record struct CorDebugValuePtr(IntPtr Pointer)
{
    public CorDebugValue? Deref() => CorDebugValue.Create(this);
}

unsafe class CorDebugValue: CallableCOMWrapper
{
    ref readonly ICorDebugValueVTable VTable => ref Unsafe.AsRef<ICorDebugValueVTable>(_vtable);
    public static CorDebugValue? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugValue(punk) : null;
    public static CorDebugValue? Create(CorDebugValuePtr p) => Create(p.Pointer);
    CorDebugValue(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugValue, punk)
    {
        SuppressRelease();
    }

    public HResult GetType(int* pType)
        => VTable.GetTypePtr(Self, pType);

    public HResult GetSize(uint* pSize)
        => VTable.GetSizePtr(Self, pSize);

    public HResult GetAddress(ulong* pAddress)
        => VTable.GetAddressPtr(Self, pAddress);

    public HResult CreateBreakpoint(CorDebugValueBreakpointPtr* ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ppBreakpoint);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugValueVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetTypePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, HResult> GetAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValueBreakpointPtr*, HResult> CreateBreakpointPtr;
    }
}


unsafe record struct CorDebugContextPtr(IntPtr Pointer)
{
    public CorDebugContext? Deref() => CorDebugContext.Create(this);
}

unsafe class CorDebugContext: CallableCOMWrapper
{
    ref readonly ICorDebugContextVTable VTable => ref Unsafe.AsRef<ICorDebugContextVTable>(_vtable);
    public static CorDebugContext? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugContext(punk) : null;
    public static CorDebugContext? Create(CorDebugContextPtr p) => Create(p.Pointer);
    CorDebugContext(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugContext, punk)
    {
        SuppressRelease();
    }

    public HResult GetType(int* pType)
        => VTable.GetTypePtr(Self, pType);

    public HResult GetSize(uint* pSize)
        => VTable.GetSizePtr(Self, pSize);

    public HResult GetAddress(ulong* pAddress)
        => VTable.GetAddressPtr(Self, pAddress);

    public HResult CreateBreakpoint(CorDebugValueBreakpointPtr* ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ppBreakpoint);

    public HResult GetClass(CorDebugClassPtr* ppClass)
        => VTable.GetClassPtr(Self, ppClass);

    public HResult GetFieldValue(CorDebugClassPtr pClass, int fieldDef, CorDebugValuePtr* ppValue)
        => VTable.GetFieldValuePtr(Self, pClass, fieldDef, ppValue);

    public HResult GetVirtualMethod(int memberRef, CorDebugFunctionPtr* ppFunction)
        => VTable.GetVirtualMethodPtr(Self, memberRef, ppFunction);

    public HResult GetContext(CorDebugContextPtr* ppContext)
        => VTable.GetContextPtr(Self, ppContext);

    public HResult IsValueClass(int* pbIsValueClass)
        => VTable.IsValueClassPtr(Self, pbIsValueClass);

    public HResult GetManagedCopy(IntPtr* ppObject)
        => VTable.GetManagedCopyPtr(Self, ppObject);

    public HResult SetFromManagedCopy(IntPtr pObject)
        => VTable.SetFromManagedCopyPtr(Self, pObject);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugContextVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetTypePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, HResult> GetAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValueBreakpointPtr*, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugClassPtr*, HResult> GetClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugClassPtr, int, CorDebugValuePtr*, HResult> GetFieldValuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugFunctionPtr*, HResult> GetVirtualMethodPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugContextPtr*, HResult> GetContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsValueClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, HResult> GetManagedCopyPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, HResult> SetFromManagedCopyPtr;
    }
}


unsafe record struct CorDebugObjectEnumPtr(IntPtr Pointer)
{
    public CorDebugObjectEnum? Deref() => CorDebugObjectEnum.Create(this);
}

unsafe class CorDebugObjectEnum: CallableCOMWrapper
{
    ref readonly ICorDebugObjectEnumVTable VTable => ref Unsafe.AsRef<ICorDebugObjectEnumVTable>(_vtable);
    public static CorDebugObjectEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugObjectEnum(punk) : null;
    public static CorDebugObjectEnum? Create(CorDebugObjectEnumPtr p) => Create(p.Pointer);
    CorDebugObjectEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugObjectEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, ulong[] objects, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, objects, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugObjectEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ulong[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugBreakpointEnumPtr(IntPtr Pointer)
{
    public CorDebugBreakpointEnum? Deref() => CorDebugBreakpointEnum.Create(this);
}

unsafe class CorDebugBreakpointEnum: CallableCOMWrapper
{
    ref readonly ICorDebugBreakpointEnumVTable VTable => ref Unsafe.AsRef<ICorDebugBreakpointEnumVTable>(_vtable);
    public static CorDebugBreakpointEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugBreakpointEnum(punk) : null;
    public static CorDebugBreakpointEnum? Create(CorDebugBreakpointEnumPtr p) => Create(p.Pointer);
    CorDebugBreakpointEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugBreakpointEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugBreakpointPtr[] breakpoints, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, breakpoints, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugBreakpointEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugBreakpointPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugStepperEnumPtr(IntPtr Pointer)
{
    public CorDebugStepperEnum? Deref() => CorDebugStepperEnum.Create(this);
}

unsafe class CorDebugStepperEnum: CallableCOMWrapper
{
    ref readonly ICorDebugStepperEnumVTable VTable => ref Unsafe.AsRef<ICorDebugStepperEnumVTable>(_vtable);
    public static CorDebugStepperEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugStepperEnum(punk) : null;
    public static CorDebugStepperEnum? Create(CorDebugStepperEnumPtr p) => Create(p.Pointer);
    CorDebugStepperEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugStepperEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugStepperPtr[] steppers, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, steppers, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugStepperEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugStepperPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugProcessEnumPtr(IntPtr Pointer)
{
    public CorDebugProcessEnum? Deref() => CorDebugProcessEnum.Create(this);
}

unsafe class CorDebugProcessEnum: CallableCOMWrapper
{
    ref readonly ICorDebugProcessEnumVTable VTable => ref Unsafe.AsRef<ICorDebugProcessEnumVTable>(_vtable);
    public static CorDebugProcessEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugProcessEnum(punk) : null;
    public static CorDebugProcessEnum? Create(CorDebugProcessEnumPtr p) => Create(p.Pointer);
    CorDebugProcessEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugProcessEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugProcessPtr[] processes, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, processes, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugProcessEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugProcessPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugThreadEnumPtr(IntPtr Pointer)
{
    public CorDebugThreadEnum? Deref() => CorDebugThreadEnum.Create(this);
}

unsafe class CorDebugThreadEnum: CallableCOMWrapper
{
    ref readonly ICorDebugThreadEnumVTable VTable => ref Unsafe.AsRef<ICorDebugThreadEnumVTable>(_vtable);
    public static CorDebugThreadEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugThreadEnum(punk) : null;
    public static CorDebugThreadEnum? Create(CorDebugThreadEnumPtr p) => Create(p.Pointer);
    CorDebugThreadEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugThreadEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugThreadPtr[] threads, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, threads, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugThreadEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugThreadPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugFrameEnumPtr(IntPtr Pointer)
{
    public CorDebugFrameEnum? Deref() => CorDebugFrameEnum.Create(this);
}

unsafe class CorDebugFrameEnum: CallableCOMWrapper
{
    ref readonly ICorDebugFrameEnumVTable VTable => ref Unsafe.AsRef<ICorDebugFrameEnumVTable>(_vtable);
    public static CorDebugFrameEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugFrameEnum(punk) : null;
    public static CorDebugFrameEnum? Create(CorDebugFrameEnumPtr p) => Create(p.Pointer);
    CorDebugFrameEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugFrameEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugFramePtr[] frames, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, frames, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFrameEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugFramePtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugChainEnumPtr(IntPtr Pointer)
{
    public CorDebugChainEnum? Deref() => CorDebugChainEnum.Create(this);
}

unsafe class CorDebugChainEnum: CallableCOMWrapper
{
    ref readonly ICorDebugChainEnumVTable VTable => ref Unsafe.AsRef<ICorDebugChainEnumVTable>(_vtable);
    public static CorDebugChainEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugChainEnum(punk) : null;
    public static CorDebugChainEnum? Create(CorDebugChainEnumPtr p) => Create(p.Pointer);
    CorDebugChainEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugChainEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugChainPtr[] chains, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, chains, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugChainEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugChainPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugModuleEnumPtr(IntPtr Pointer)
{
    public CorDebugModuleEnum? Deref() => CorDebugModuleEnum.Create(this);
}

unsafe class CorDebugModuleEnum: CallableCOMWrapper
{
    ref readonly ICorDebugModuleEnumVTable VTable => ref Unsafe.AsRef<ICorDebugModuleEnumVTable>(_vtable);
    public static CorDebugModuleEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugModuleEnum(punk) : null;
    public static CorDebugModuleEnum? Create(CorDebugModuleEnumPtr p) => Create(p.Pointer);
    CorDebugModuleEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugModuleEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugModulePtr[] modules, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, modules, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugModuleEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugModulePtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugErrorInfoEnumPtr(IntPtr Pointer)
{
    public CorDebugErrorInfoEnum? Deref() => CorDebugErrorInfoEnum.Create(this);
}

unsafe class CorDebugErrorInfoEnum: CallableCOMWrapper
{
    ref readonly ICorDebugErrorInfoEnumVTable VTable => ref Unsafe.AsRef<ICorDebugErrorInfoEnumVTable>(_vtable);
    public static CorDebugErrorInfoEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugErrorInfoEnum(punk) : null;
    public static CorDebugErrorInfoEnum? Create(CorDebugErrorInfoEnumPtr p) => Create(p.Pointer);
    CorDebugErrorInfoEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugErrorInfoEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugEditAndContinueErrorInfoPtr[] errors, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, errors, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugErrorInfoEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueErrorInfoPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugAppDomainEnumPtr(IntPtr Pointer)
{
    public CorDebugAppDomainEnum? Deref() => CorDebugAppDomainEnum.Create(this);
}

unsafe class CorDebugAppDomainEnum: CallableCOMWrapper
{
    ref readonly ICorDebugAppDomainEnumVTable VTable => ref Unsafe.AsRef<ICorDebugAppDomainEnumVTable>(_vtable);
    public static CorDebugAppDomainEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugAppDomainEnum(punk) : null;
    public static CorDebugAppDomainEnum? Create(CorDebugAppDomainEnumPtr p) => Create(p.Pointer);
    CorDebugAppDomainEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugAppDomainEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugAppDomainPtr[] values, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, values, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAppDomainEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugAppDomainPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugAssemblyEnumPtr(IntPtr Pointer)
{
    public CorDebugAssemblyEnum? Deref() => CorDebugAssemblyEnum.Create(this);
}

unsafe class CorDebugAssemblyEnum: CallableCOMWrapper
{
    ref readonly ICorDebugAssemblyEnumVTable VTable => ref Unsafe.AsRef<ICorDebugAssemblyEnumVTable>(_vtable);
    public static CorDebugAssemblyEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugAssemblyEnum(punk) : null;
    public static CorDebugAssemblyEnum? Create(CorDebugAssemblyEnumPtr p) => Create(p.Pointer);
    CorDebugAssemblyEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugAssemblyEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    public HResult Next(uint celt, CorDebugAssemblyPtr[] values, uint* pceltFetched)
        => VTable.NextPtr(Self, celt, values, pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAssemblyEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugAssemblyPtr[], uint*, HResult> NextPtr;
    }
}


unsafe record struct CorDebugMDAPtr(IntPtr Pointer)
{
    public CorDebugMDA? Deref() => CorDebugMDA.Create(this);
}

unsafe class CorDebugMDA: CallableCOMWrapper
{
    ref readonly ICorDebugMDAVTable VTable => ref Unsafe.AsRef<ICorDebugMDAVTable>(_vtable);
    public static CorDebugMDA? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugMDA(punk) : null;
    public static CorDebugMDA? Create(CorDebugMDAPtr p) => Create(p.Pointer);
    CorDebugMDA(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugMDA, punk)
    {
        SuppressRelease();
    }

    public HResult GetName(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetNamePtr(Self, cchName, pcchName, szName);

    public HResult GetDescription(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetDescriptionPtr(Self, cchName, pcchName, szName);

    public HResult GetXML(uint cchName, uint* pcchName, int[] szName)
        => VTable.GetXMLPtr(Self, cchName, pcchName, szName);

    public HResult GetFlags(CorDebugMDAFlags* pFlags)
        => VTable.GetFlagsPtr(Self, pFlags);

    public HResult GetOSThreadId(uint* pOsTid)
        => VTable.GetOSThreadIdPtr(Self, pOsTid);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugMDAVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetDescriptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetXMLPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugMDAFlags*, HResult> GetFlagsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetOSThreadIdPtr;
    }
}


enum CorDebugMDAFlags
{
    MDA_FLAG_SLIP = 2,
}

unsafe record struct CorDebugEditAndContinueErrorInfoPtr(IntPtr Pointer)
{
    public CorDebugEditAndContinueErrorInfo? Deref() => CorDebugEditAndContinueErrorInfo.Create(this);
}

unsafe class CorDebugEditAndContinueErrorInfo: CallableCOMWrapper
{
    ref readonly ICorDebugEditAndContinueErrorInfoVTable VTable => ref Unsafe.AsRef<ICorDebugEditAndContinueErrorInfoVTable>(_vtable);
    public static CorDebugEditAndContinueErrorInfo? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugEditAndContinueErrorInfo(punk) : null;
    public static CorDebugEditAndContinueErrorInfo? Create(CorDebugEditAndContinueErrorInfoPtr p) => Create(p.Pointer);
    CorDebugEditAndContinueErrorInfo(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugEditAndContinueErrorInfo, punk)
    {
        SuppressRelease();
    }

    public HResult GetModule(CorDebugModulePtr* ppModule)
        => VTable.GetModulePtr(Self, ppModule);

    public HResult GetToken(int* pToken)
        => VTable.GetTokenPtr(Self, pToken);

    public HResult GetErrorCode(int* pHr)
        => VTable.GetErrorCodePtr(Self, pHr);

    public HResult GetString(uint cchString, uint* pcchString, int[] szString)
        => VTable.GetStringPtr(Self, cchString, pcchString, szString);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEditAndContinueErrorInfoVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugModulePtr*, HResult> GetModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> GetErrorCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint*, int[], HResult> GetStringPtr;
    }
}


unsafe record struct CorDebugEditAndContinueSnapshotPtr(IntPtr Pointer)
{
    public CorDebugEditAndContinueSnapshot? Deref() => CorDebugEditAndContinueSnapshot.Create(this);
}

unsafe class CorDebugEditAndContinueSnapshot: CallableCOMWrapper
{
    ref readonly ICorDebugEditAndContinueSnapshotVTable VTable => ref Unsafe.AsRef<ICorDebugEditAndContinueSnapshotVTable>(_vtable);
    public static CorDebugEditAndContinueSnapshot? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugEditAndContinueSnapshot(punk) : null;
    public static CorDebugEditAndContinueSnapshot? Create(CorDebugEditAndContinueSnapshotPtr p) => Create(p.Pointer);
    CorDebugEditAndContinueSnapshot(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugEditAndContinueSnapshot, punk)
    {
        SuppressRelease();
    }

    public HResult CopyMetaData(IntPtr pIStream, Guid* pMvid)
        => VTable.CopyMetaDataPtr(Self, pIStream, pMvid);

    public HResult GetMvid(Guid* pMvid)
        => VTable.GetMvidPtr(Self, pMvid);

    public HResult GetRoDataRVA(uint* pRoDataRVA)
        => VTable.GetRoDataRVAPtr(Self, pRoDataRVA);

    public HResult GetRwDataRVA(uint* pRwDataRVA)
        => VTable.GetRwDataRVAPtr(Self, pRwDataRVA);

    public HResult SetPEBytes(IntPtr pIStream)
        => VTable.SetPEBytesPtr(Self, pIStream);

    public HResult SetILMap(int mdFunction, uint cMapSize, COR_IL_MAP[] map)
        => VTable.SetILMapPtr(Self, mdFunction, cMapSize, map);

    public HResult SetPESymbolBytes(IntPtr pIStream)
        => VTable.SetPESymbolBytesPtr(Self, pIStream);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEditAndContinueSnapshotVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, Guid*, HResult> CopyMetaDataPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, Guid*, HResult> GetMvidPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetRoDataRVAPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetRwDataRVAPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, HResult> SetPEBytesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, uint, COR_IL_MAP[], HResult> SetILMapPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, HResult> SetPESymbolBytesPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct COR_IL_MAP
{
    [FieldOffset(0)]
    public uint oldOffset;
    [FieldOffset(32)]
    public uint newOffset;
    [FieldOffset(64)]
    public bool fAccurate;
}

unsafe record struct CorDebugUnmanagedCallbackPtr(IntPtr Pointer)
{
    public CorDebugUnmanagedCallback? Deref() => CorDebugUnmanagedCallback.Create(this);
}

unsafe class CorDebugUnmanagedCallback: CallableCOMWrapper
{
    ref readonly ICorDebugUnmanagedCallbackVTable VTable => ref Unsafe.AsRef<ICorDebugUnmanagedCallbackVTable>(_vtable);
    public static CorDebugUnmanagedCallback? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugUnmanagedCallback(punk) : null;
    public static CorDebugUnmanagedCallback? Create(CorDebugUnmanagedCallbackPtr p) => Create(p.Pointer);
    CorDebugUnmanagedCallback(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugUnmanagedCallback, punk)
    {
        SuppressRelease();
    }

    public HResult DebugEvent(_DEBUG_EVENT* pDebugEvent, bool fOutOfBand)
        => VTable.DebugEventPtr(Self, pDebugEvent, fOutOfBand);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugUnmanagedCallbackVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, _DEBUG_EVENT*, bool, HResult> DebugEventPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct _DEBUG_EVENT
{
    [FieldOffset(0)]
    public uint dwDebugEventCode;
    [FieldOffset(32)]
    public uint dwProcessId;
    [FieldOffset(64)]
    public uint dwThreadId;
    [FieldOffset(128)]
    public _EXCEPTION_DEBUG_INFO Exception;
    [FieldOffset(128)]
    public _CREATE_THREAD_DEBUG_INFO CreateThread;
    [FieldOffset(128)]
    public _CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    [FieldOffset(128)]
    public _EXIT_THREAD_DEBUG_INFO ExitThread;
    [FieldOffset(128)]
    public _EXIT_PROCESS_DEBUG_INFO ExitProcess;
    [FieldOffset(128)]
    public _LOAD_DLL_DEBUG_INFO LoadDll;
    [FieldOffset(128)]
    public _UNLOAD_DLL_DEBUG_INFO UnloadDll;
    [FieldOffset(128)]
    public _OUTPUT_DEBUG_STRING_INFO DebugString;
    [FieldOffset(128)]
    public _RIP_INFO RipInfo;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _EXCEPTION_DEBUG_INFO
{
    [FieldOffset(0)]
    public _EXCEPTION_RECORD ExceptionRecord;
    [FieldOffset(704)]
    public uint dwFirstChance;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _EXCEPTION_RECORD
{
    [FieldOffset(0)]
    public uint ExceptionCode;
    [FieldOffset(32)]
    public uint ExceptionFlags;
    [FieldOffset(64)]
    public _EXCEPTION_RECORD* ExceptionRecord;
    [FieldOffset(128)]
    public void* ExceptionAddress;
    [FieldOffset(192)]
    public uint NumberParameters;
    [FieldOffset(224)]
    fixed uint ExceptionInformation[15];
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _CREATE_THREAD_DEBUG_INFO
{
    [FieldOffset(0)]
    public void* hThread;
    [FieldOffset(64)]
    public void* lpThreadLocalBase;
    [FieldOffset(128)]
    public void* lpStartAddress;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _CREATE_PROCESS_DEBUG_INFO
{
    [FieldOffset(0)]
    public void* hFile;
    [FieldOffset(64)]
    public void* hProcess;
    [FieldOffset(128)]
    public void* hThread;
    [FieldOffset(192)]
    public void* lpBaseOfImage;
    [FieldOffset(256)]
    public uint dwDebugInfoFileOffset;
    [FieldOffset(288)]
    public uint nDebugInfoSize;
    [FieldOffset(320)]
    public void* lpThreadLocalBase;
    [FieldOffset(384)]
    public void* lpStartAddress;
    [FieldOffset(448)]
    public void* lpImageName;
    [FieldOffset(512)]
    public ushort fUnicode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _EXIT_THREAD_DEBUG_INFO
{
    [FieldOffset(0)]
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _EXIT_PROCESS_DEBUG_INFO
{
    [FieldOffset(0)]
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _LOAD_DLL_DEBUG_INFO
{
    [FieldOffset(0)]
    public void* hFile;
    [FieldOffset(64)]
    public void* lpBaseOfDll;
    [FieldOffset(128)]
    public uint dwDebugInfoFileOffset;
    [FieldOffset(160)]
    public uint nDebugInfoSize;
    [FieldOffset(192)]
    public void* lpImageName;
    [FieldOffset(256)]
    public ushort fUnicode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _UNLOAD_DLL_DEBUG_INFO
{
    [FieldOffset(0)]
    public void* lpBaseOfDll;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _OUTPUT_DEBUG_STRING_INFO
{
    [FieldOffset(0)]
    public char* lpDebugStringData;
    [FieldOffset(64)]
    public ushort fUnicode;
    [FieldOffset(80)]
    public ushort nDebugStringLength;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct _RIP_INFO
{
    [FieldOffset(0)]
    public uint dwError;
    [FieldOffset(32)]
    public uint dwType;
}

unsafe record struct CorDebugEnumPtr(IntPtr Pointer)
{
    public CorDebugEnum? Deref() => CorDebugEnum.Create(this);
}

unsafe class CorDebugEnum: CallableCOMWrapper
{
    ref readonly ICorDebugEnumVTable VTable => ref Unsafe.AsRef<ICorDebugEnumVTable>(_vtable);
    public static CorDebugEnum? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugEnum(punk) : null;
    public static CorDebugEnum? Create(CorDebugEnumPtr p) => Create(p.Pointer);
    CorDebugEnum(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugEnum, punk)
    {
        SuppressRelease();
    }

    public HResult Skip(uint celt)
        => VTable.SkipPtr(Self, celt);

    public HResult Reset()
        => VTable.ResetPtr(Self);

    public HResult Clone(CorDebugEnumPtr* ppEnum)
        => VTable.ClonePtr(Self, ppEnum);

    public HResult GetCount(uint* pcelt)
        => VTable.GetCountPtr(Self, pcelt);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugEnumPtr*, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetCountPtr;
    }
}


unsafe record struct CorDebugFunctionBreakpointPtr(IntPtr Pointer)
{
    public CorDebugFunctionBreakpoint? Deref() => CorDebugFunctionBreakpoint.Create(this);
}

unsafe class CorDebugFunctionBreakpoint: CallableCOMWrapper
{
    ref readonly ICorDebugFunctionBreakpointVTable VTable => ref Unsafe.AsRef<ICorDebugFunctionBreakpointVTable>(_vtable);
    public static CorDebugFunctionBreakpoint? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugFunctionBreakpoint(punk) : null;
    public static CorDebugFunctionBreakpoint? Create(CorDebugFunctionBreakpointPtr p) => Create(p.Pointer);
    CorDebugFunctionBreakpoint(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugFunctionBreakpoint, punk)
    {
        SuppressRelease();
    }

    public HResult Activate(bool bActive)
        => VTable.ActivatePtr(Self, bActive);

    public HResult IsActive(int* pbActive)
        => VTable.IsActivePtr(Self, pbActive);

    public HResult GetFunction(CorDebugFunctionPtr* ppFunction)
        => VTable.GetFunctionPtr(Self, ppFunction);

    public HResult GetOffset(uint* pnOffset)
        => VTable.GetOffsetPtr(Self, pnOffset);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFunctionBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr*, HResult> GetFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint*, HResult> GetOffsetPtr;
    }
}


unsafe record struct CorDebugModuleBreakpointPtr(IntPtr Pointer)
{
    public CorDebugModuleBreakpoint? Deref() => CorDebugModuleBreakpoint.Create(this);
}

unsafe class CorDebugModuleBreakpoint: CallableCOMWrapper
{
    ref readonly ICorDebugModuleBreakpointVTable VTable => ref Unsafe.AsRef<ICorDebugModuleBreakpointVTable>(_vtable);
    public static CorDebugModuleBreakpoint? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugModuleBreakpoint(punk) : null;
    public static CorDebugModuleBreakpoint? Create(CorDebugModuleBreakpointPtr p) => Create(p.Pointer);
    CorDebugModuleBreakpoint(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugModuleBreakpoint, punk)
    {
        SuppressRelease();
    }

    public HResult Activate(bool bActive)
        => VTable.ActivatePtr(Self, bActive);

    public HResult IsActive(int* pbActive)
        => VTable.IsActivePtr(Self, pbActive);

    public HResult GetModule(CorDebugModulePtr* ppModule)
        => VTable.GetModulePtr(Self, ppModule);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugModuleBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugModulePtr*, HResult> GetModulePtr;
    }
}


unsafe record struct CorDebugValueBreakpointPtr(IntPtr Pointer)
{
    public CorDebugValueBreakpoint? Deref() => CorDebugValueBreakpoint.Create(this);
}

unsafe class CorDebugValueBreakpoint: CallableCOMWrapper
{
    ref readonly ICorDebugValueBreakpointVTable VTable => ref Unsafe.AsRef<ICorDebugValueBreakpointVTable>(_vtable);
    public static CorDebugValueBreakpoint? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugValueBreakpoint(punk) : null;
    public static CorDebugValueBreakpoint? Create(CorDebugValueBreakpointPtr p) => Create(p.Pointer);
    CorDebugValueBreakpoint(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugValueBreakpoint, punk)
    {
        SuppressRelease();
    }

    public HResult Activate(bool bActive)
        => VTable.ActivatePtr(Self, bActive);

    public HResult IsActive(int* pbActive)
        => VTable.IsActivePtr(Self, pbActive);

    public HResult GetValue(CorDebugValuePtr* ppValue)
        => VTable.GetValuePtr(Self, ppValue);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugValueBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int*, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugValuePtr*, HResult> GetValuePtr;
    }
}


unsafe record struct CorDebugRegisterSetPtr(IntPtr Pointer)
{
    public CorDebugRegisterSet? Deref() => CorDebugRegisterSet.Create(this);
}

unsafe class CorDebugRegisterSet: CallableCOMWrapper
{
    ref readonly ICorDebugRegisterSetVTable VTable => ref Unsafe.AsRef<ICorDebugRegisterSetVTable>(_vtable);
    public static CorDebugRegisterSet? Create(IntPtr punk) => punk != IntPtr.Zero ? new CorDebugRegisterSet(punk) : null;
    public static CorDebugRegisterSet? Create(CorDebugRegisterSetPtr p) => Create(p.Pointer);
    CorDebugRegisterSet(IntPtr punk): base(new RefCountedFreeLibrary(IntPtr.Zero), InterfaceIds.ICorDebugRegisterSet, punk)
    {
        SuppressRelease();
    }

    public HResult GetRegistersAvailable(ulong* pAvailable)
        => VTable.GetRegistersAvailablePtr(Self, pAvailable);

    public HResult GetRegisters(ulong mask, uint regCount, ulong[] regBuffer)
        => VTable.GetRegistersPtr(Self, mask, regCount, regBuffer);

    public HResult SetRegisters(ulong mask, uint regCount, ulong[] regBuffer)
        => VTable.SetRegistersPtr(Self, mask, regCount, regBuffer);

    public HResult GetThreadContext(uint contextSize, byte[] context)
        => VTable.GetThreadContextPtr(Self, contextSize, context);

    public HResult SetThreadContext(uint contextSize, byte[] context)
        => VTable.SetThreadContextPtr(Self, contextSize, context);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugRegisterSetVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong*, HResult> GetRegistersAvailablePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, ulong[], HResult> GetRegistersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, ulong[], HResult> SetRegistersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, byte[], HResult> GetThreadContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, byte[], HResult> SetThreadContextPtr;
    }
}


unsafe abstract class CorDebugManagedCallbackBase: COMCallableIUnknown
{
    public CorDebugManagedCallbackPtr ICorDebugManagedCallback { get; }
    public CorDebugManagedCallback2Ptr ICorDebugManagedCallback2 { get; }

    public CorDebugManagedCallbackBase()
    {
        ICorDebugManagedCallback = DefineICorDebugManagedCallback(this, InterfaceIds.ICorDebugManagedCallback);
        ICorDebugManagedCallback2 = DefineICorDebugManagedCallback2(this, InterfaceIds.ICorDebugManagedCallback2);
    }

    protected virtual HResult Breakpoint(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult StepComplete(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugStepperPtr pStepper, CorDebugStepReason reason)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult Break(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult Exception(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, bool unhandled)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult EvalComplete(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult EvalException(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult CreateProcessW(CorDebugProcessPtr pProcess)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult ExitProcess(CorDebugProcessPtr pProcess)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult CreateThread(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult ExitThread(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult LoadModule(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult UnloadModule(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult LoadClass(CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult UnloadClass(CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult DebuggerError(CorDebugProcessPtr pProcess, HResult errorHR, uint errorCode)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult LogMessage(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, int* pLogSwitchName, int* pMessage)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult LogSwitch(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, int* pLogSwitchName, int* pParentName)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult CreateAppDomain(CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult ExitAppDomain(CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult LoadAssembly(CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult UnloadAssembly(CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult ControlCTrap(CorDebugProcessPtr pProcess)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult NameChange(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult UpdateModuleSymbols(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule, IntPtr pSymbolStream)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult EditAndContinueRemap(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction, bool fAccurate)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult BreakpointSetError(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint, uint dwError)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult FunctionRemapOpportunity(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pOldFunction, CorDebugFunctionPtr pNewFunction, uint oldILOffset)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult CreateConnection(CorDebugProcessPtr pProcess, uint dwConnectionId, int* pConnName)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult ChangeConnection(CorDebugProcessPtr pProcess, uint dwConnectionId)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult DestroyConnection(CorDebugProcessPtr pProcess, uint dwConnectionId)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult Exception(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFramePtr pFrame, uint nOffset, CorDebugExceptionCallbackType dwEventType, uint dwFlags)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult ExceptionUnwind(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugExceptionUnwindCallbackType dwEventType, uint dwFlags)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult FunctionRemapComplete(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult MDANotification(CorDebugControllerPtr pController, CorDebugThreadPtr pThread, CorDebugMDAPtr pMDA)
    {
        return HResult.E_NOTIMPL;
    }

    static CorDebugManagedCallbackPtr DefineICorDebugManagedCallback(CorDebugManagedCallbackBase self, Guid iid)
    {
        var builder = self.AddInterface(iid, validate: false);
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.BreakpointDelegate((_, pAppDomain, pThread, pBreakpoint) => self.Breakpoint(pAppDomain, pThread, pBreakpoint)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.StepCompleteDelegate((_, pAppDomain, pThread, pStepper, reason) => self.StepComplete(pAppDomain, pThread, pStepper, reason)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.BreakDelegate((_, pAppDomain, thread) => self.Break(pAppDomain, thread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExceptionDelegate((_, pAppDomain, pThread, unhandled) => self.Exception(pAppDomain, pThread, unhandled)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.EvalCompleteDelegate((_, pAppDomain, pThread, pEval) => self.EvalComplete(pAppDomain, pThread, pEval)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.EvalExceptionDelegate((_, pAppDomain, pThread, pEval) => self.EvalException(pAppDomain, pThread, pEval)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.CreateProcessWDelegate((_, pProcess) => self.CreateProcessW(pProcess)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExitProcessDelegate((_, pProcess) => self.ExitProcess(pProcess)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.CreateThreadDelegate((_, pAppDomain, thread) => self.CreateThread(pAppDomain, thread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExitThreadDelegate((_, pAppDomain, thread) => self.ExitThread(pAppDomain, thread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LoadModuleDelegate((_, pAppDomain, pModule) => self.LoadModule(pAppDomain, pModule)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UnloadModuleDelegate((_, pAppDomain, pModule) => self.UnloadModule(pAppDomain, pModule)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LoadClassDelegate((_, pAppDomain, c) => self.LoadClass(pAppDomain, c)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UnloadClassDelegate((_, pAppDomain, c) => self.UnloadClass(pAppDomain, c)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.DebuggerErrorDelegate((_, pProcess, errorHR, errorCode) => self.DebuggerError(pProcess, errorHR, errorCode)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LogMessageDelegate((_, pAppDomain, pThread, lLevel, pLogSwitchName, pMessage) => self.LogMessage(pAppDomain, pThread, lLevel, pLogSwitchName, pMessage)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LogSwitchDelegate((_, pAppDomain, pThread, lLevel, ulReason, pLogSwitchName, pParentName) => self.LogSwitch(pAppDomain, pThread, lLevel, ulReason, pLogSwitchName, pParentName)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.CreateAppDomainDelegate((_, pProcess, pAppDomain) => self.CreateAppDomain(pProcess, pAppDomain)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExitAppDomainDelegate((_, pProcess, pAppDomain) => self.ExitAppDomain(pProcess, pAppDomain)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LoadAssemblyDelegate((_, pAppDomain, pAssembly) => self.LoadAssembly(pAppDomain, pAssembly)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UnloadAssemblyDelegate((_, pAppDomain, pAssembly) => self.UnloadAssembly(pAppDomain, pAssembly)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ControlCTrapDelegate((_, pProcess) => self.ControlCTrap(pProcess)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.NameChangeDelegate((_, pAppDomain, pThread) => self.NameChange(pAppDomain, pThread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UpdateModuleSymbolsDelegate((_, pAppDomain, pModule, pSymbolStream) => self.UpdateModuleSymbols(pAppDomain, pModule, pSymbolStream)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.EditAndContinueRemapDelegate((_, pAppDomain, pThread, pFunction, fAccurate) => self.EditAndContinueRemap(pAppDomain, pThread, pFunction, fAccurate)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.BreakpointSetErrorDelegate((_, pAppDomain, pThread, pBreakpoint, dwError) => self.BreakpointSetError(pAppDomain, pThread, pBreakpoint, dwError)));
        return new CorDebugManagedCallbackPtr(builder.Complete());
    }

    static CorDebugManagedCallback2Ptr DefineICorDebugManagedCallback2(CorDebugManagedCallbackBase self, Guid iid)
    {
        var builder = self.AddInterface(iid, validate: false);
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.FunctionRemapOpportunityDelegate((_, pAppDomain, pThread, pOldFunction, pNewFunction, oldILOffset) => self.FunctionRemapOpportunity(pAppDomain, pThread, pOldFunction, pNewFunction, oldILOffset)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.CreateConnectionDelegate((_, pProcess, dwConnectionId, pConnName) => self.CreateConnection(pProcess, dwConnectionId, pConnName)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.ChangeConnectionDelegate((_, pProcess, dwConnectionId) => self.ChangeConnection(pProcess, dwConnectionId)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.DestroyConnectionDelegate((_, pProcess, dwConnectionId) => self.DestroyConnection(pProcess, dwConnectionId)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.ExceptionDelegate((_, pAppDomain, pThread, pFrame, nOffset, dwEventType, dwFlags) => self.Exception(pAppDomain, pThread, pFrame, nOffset, dwEventType, dwFlags)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.ExceptionUnwindDelegate((_, pAppDomain, pThread, dwEventType, dwFlags) => self.ExceptionUnwind(pAppDomain, pThread, dwEventType, dwFlags)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.FunctionRemapCompleteDelegate((_, pAppDomain, pThread, pFunction) => self.FunctionRemapComplete(pAppDomain, pThread, pFunction)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.MDANotificationDelegate((_, pController, pThread, pMDA) => self.MDANotification(pController, pThread, pMDA)));
        return new CorDebugManagedCallback2Ptr(builder.Complete());
    }

    static class ICorDebugManagedCallbackDelegates
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult BreakpointDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult StepCompleteDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugStepperPtr pStepper, CorDebugStepReason reason);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult BreakDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ExceptionDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, bool unhandled);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult EvalCompleteDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult EvalExceptionDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult CreateProcessWDelegate(IntPtr self, CorDebugProcessPtr pProcess);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ExitProcessDelegate(IntPtr self, CorDebugProcessPtr pProcess);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult CreateThreadDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ExitThreadDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult LoadModuleDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult UnloadModuleDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult LoadClassDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult UnloadClassDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult DebuggerErrorDelegate(IntPtr self, CorDebugProcessPtr pProcess, HResult errorHR, uint errorCode);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult LogMessageDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, int* pLogSwitchName, int* pMessage);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult LogSwitchDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, int* pLogSwitchName, int* pParentName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult CreateAppDomainDelegate(IntPtr self, CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ExitAppDomainDelegate(IntPtr self, CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult LoadAssemblyDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult UnloadAssemblyDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ControlCTrapDelegate(IntPtr self, CorDebugProcessPtr pProcess);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult NameChangeDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult UpdateModuleSymbolsDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule, IntPtr pSymbolStream);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult EditAndContinueRemapDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction, bool fAccurate);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult BreakpointSetErrorDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint, uint dwError);

    }

    static class ICorDebugManagedCallback2Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult FunctionRemapOpportunityDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pOldFunction, CorDebugFunctionPtr pNewFunction, uint oldILOffset);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult CreateConnectionDelegate(IntPtr self, CorDebugProcessPtr pProcess, uint dwConnectionId, int* pConnName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ChangeConnectionDelegate(IntPtr self, CorDebugProcessPtr pProcess, uint dwConnectionId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult DestroyConnectionDelegate(IntPtr self, CorDebugProcessPtr pProcess, uint dwConnectionId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ExceptionDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFramePtr pFrame, uint nOffset, CorDebugExceptionCallbackType dwEventType, uint dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult ExceptionUnwindDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugExceptionUnwindCallbackType dwEventType, uint dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult FunctionRemapCompleteDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult MDANotificationDelegate(IntPtr self, CorDebugControllerPtr pController, CorDebugThreadPtr pThread, CorDebugMDAPtr pMDA);

    }

}

