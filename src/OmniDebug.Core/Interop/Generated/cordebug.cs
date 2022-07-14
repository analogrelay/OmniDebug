// ReSharper disable All
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

unsafe record struct CorDebugManagedCallbackPtr(IntPtr Pointer)
{
    public CorDebugManagedCallback? DerefOrDefault() => CorDebugManagedCallback.Create(this);
    public CorDebugManagedCallback Deref() => CorDebugManagedCallback.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult LogMessage(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, ref ushort pLogSwitchName, ref ushort pMessage)
        => VTable.LogMessagePtr(Self, pAppDomain, pThread, lLevel, ref pLogSwitchName, ref pMessage);

    public HResult LogSwitch(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, ref ushort pLogSwitchName, ref ushort pParentName)
        => VTable.LogSwitchPtr(Self, pAppDomain, pThread, lLevel, ulReason, ref pLogSwitchName, ref pParentName);

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
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, int, ref ushort, ref ushort, HResult> LogMessagePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugAppDomainPtr, CorDebugThreadPtr, int, uint, ref ushort, ref ushort, HResult> LogSwitchPtr;
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
    public CorDebugManagedCallback2? DerefOrDefault() => CorDebugManagedCallback2.Create(this);
    public CorDebugManagedCallback2 Deref() => CorDebugManagedCallback2.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult CreateConnection(CorDebugProcessPtr pProcess, uint dwConnectionId, ref ushort pConnName)
        => VTable.CreateConnectionPtr(Self, pProcess, dwConnectionId, ref pConnName);

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
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugProcessPtr, uint, ref ushort, HResult> CreateConnectionPtr;
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
    public CorDebug? DerefOrDefault() => CorDebug.Create(this);
    public CorDebug Deref() => CorDebug.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult CreateProcessW(ref ushort lpApplicationName, char* lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, ref ushort lpCurrentDirectory, ref STARTUPINFOW lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation, CorDebugCreateProcessFlags debuggingFlags, ref CorDebugProcessPtr ppProcess)
        => VTable.CreateProcessWPtr(Self, ref lpApplicationName, lpCommandLine, ref lpProcessAttributes, ref lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, ref lpCurrentDirectory, ref lpStartupInfo, ref lpProcessInformation, debuggingFlags, ref ppProcess);

    public HResult DebugActiveProcess(uint id, bool win32Attach, ref CorDebugProcessPtr ppProcess)
        => VTable.DebugActiveProcessPtr(Self, id, win32Attach, ref ppProcess);

    public HResult EnumerateProcesses(ref CorDebugProcessEnumPtr ppProcess)
        => VTable.EnumerateProcessesPtr(Self, ref ppProcess);

    public HResult GetProcess(uint dwProcessId, ref CorDebugProcessPtr ppProcess)
        => VTable.GetProcessPtr(Self, dwProcessId, ref ppProcess);

    public HResult CanLaunchOrAttach(uint dwProcessId, bool win32DebuggingEnabled)
        => VTable.CanLaunchOrAttachPtr(Self, dwProcessId, win32DebuggingEnabled);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> InitializePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugManagedCallbackPtr, HResult> SetManagedHandlerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugUnmanagedCallbackPtr, HResult> SetUnmanagedHandlerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ushort, char*, ref SECURITY_ATTRIBUTES, ref SECURITY_ATTRIBUTES, bool, uint, IntPtr, ref ushort, ref STARTUPINFOW, ref PROCESS_INFORMATION, CorDebugCreateProcessFlags, ref CorDebugProcessPtr, HResult> CreateProcessWPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, bool, ref CorDebugProcessPtr, HResult> DebugActiveProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugProcessEnumPtr, HResult> EnumerateProcessesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref CorDebugProcessPtr, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, bool, HResult> CanLaunchOrAttachPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct SECURITY_ATTRIBUTES
{
    [FieldOffset(0)]
    public uint nLength;
    [FieldOffset(64)]
    public IntPtr lpSecurityDescriptor;
    [FieldOffset(128)]
    public bool bInheritHandle;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct STARTUPINFOW
{
    [FieldOffset(0)]
    public uint cb;
    [FieldOffset(64)]
    public char* lpReserved_PAL_Undefined;
    [FieldOffset(128)]
    public char* lpDesktop_PAL_Undefined;
    [FieldOffset(192)]
    public char* lpTitle_PAL_Undefined;
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
    public IntPtr hStdInput;
    [FieldOffset(704)]
    public IntPtr hStdOutput;
    [FieldOffset(768)]
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct PROCESS_INFORMATION
{
    [FieldOffset(0)]
    public IntPtr hProcess;
    [FieldOffset(64)]
    public IntPtr hThread;
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
    public CorDebugController? DerefOrDefault() => CorDebugController.Create(this);
    public CorDebugController Deref() => CorDebugController.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsRunning(ref bool pbRunning)
        => VTable.IsRunningPtr(Self, ref pbRunning);

    public HResult HasQueuedCallbacks(CorDebugThreadPtr pThread, ref bool pbQueued)
        => VTable.HasQueuedCallbacksPtr(Self, pThread, ref pbQueued);

    public HResult EnumerateThreads(ref CorDebugThreadEnumPtr ppThreads)
        => VTable.EnumerateThreadsPtr(Self, ref ppThreads);

    public HResult SetAllThreadsDebugState(CorDebugThreadState state, CorDebugThreadPtr pExceptThisThread)
        => VTable.SetAllThreadsDebugStatePtr(Self, state, pExceptThisThread);

    public HResult Detach()
        => VTable.DetachPtr(Self);

    public HResult Terminate(uint exitCode)
        => VTable.TerminatePtr(Self, exitCode);

    public HResult CanCommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, ref CorDebugErrorInfoEnumPtr pError)
        => VTable.CanCommitChangesPtr(Self, cSnapshots, pSnapshots, ref pError);

    public HResult CommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, ref CorDebugErrorInfoEnumPtr pError)
        => VTable.CommitChangesPtr(Self, cSnapshots, pSnapshots, ref pError);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugControllerVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> StopPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ContinuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsRunningPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr, ref bool, HResult> HasQueuedCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugThreadEnumPtr, HResult> EnumerateThreadsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, CorDebugThreadPtr, HResult> SetAllThreadsDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DetachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], ref CorDebugErrorInfoEnumPtr, HResult> CanCommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], ref CorDebugErrorInfoEnumPtr, HResult> CommitChangesPtr;
    }
}


enum CorDebugThreadState
{
    THREAD_RUN = 0,
    THREAD_SUSPEND = 1,
}

unsafe record struct CorDebugAppDomainPtr(IntPtr Pointer)
{
    public CorDebugAppDomain? DerefOrDefault() => CorDebugAppDomain.Create(this);
    public CorDebugAppDomain Deref() => CorDebugAppDomain.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsRunning(ref bool pbRunning)
        => VTable.IsRunningPtr(Self, ref pbRunning);

    public HResult HasQueuedCallbacks(CorDebugThreadPtr pThread, ref bool pbQueued)
        => VTable.HasQueuedCallbacksPtr(Self, pThread, ref pbQueued);

    public HResult EnumerateThreads(ref CorDebugThreadEnumPtr ppThreads)
        => VTable.EnumerateThreadsPtr(Self, ref ppThreads);

    public HResult SetAllThreadsDebugState(CorDebugThreadState state, CorDebugThreadPtr pExceptThisThread)
        => VTable.SetAllThreadsDebugStatePtr(Self, state, pExceptThisThread);

    public HResult Detach()
        => VTable.DetachPtr(Self);

    public HResult Terminate(uint exitCode)
        => VTable.TerminatePtr(Self, exitCode);

    public HResult CanCommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, ref CorDebugErrorInfoEnumPtr pError)
        => VTable.CanCommitChangesPtr(Self, cSnapshots, pSnapshots, ref pError);

    public HResult CommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, ref CorDebugErrorInfoEnumPtr pError)
        => VTable.CommitChangesPtr(Self, cSnapshots, pSnapshots, ref pError);

    public HResult GetProcess(ref CorDebugProcessPtr ppProcess)
        => VTable.GetProcessPtr(Self, ref ppProcess);

    public HResult EnumerateAssemblies(ref CorDebugAssemblyEnumPtr ppAssemblies)
        => VTable.EnumerateAssembliesPtr(Self, ref ppAssemblies);

    public HResult GetModuleFromMetaDataInterface(IntPtr pIMetaData, ref CorDebugModulePtr ppModule)
        => VTable.GetModuleFromMetaDataInterfacePtr(Self, pIMetaData, ref ppModule);

    public HResult EnumerateBreakpoints(ref CorDebugBreakpointEnumPtr ppBreakpoints)
        => VTable.EnumerateBreakpointsPtr(Self, ref ppBreakpoints);

    public HResult EnumerateSteppers(ref CorDebugStepperEnumPtr ppSteppers)
        => VTable.EnumerateSteppersPtr(Self, ref ppSteppers);

    public HResult IsAttached(ref bool pbAttached)
        => VTable.IsAttachedPtr(Self, ref pbAttached);

    public HResult GetName(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetNamePtr(Self, cchName, ref pcchName, szName);

    public HResult GetObject(ref CorDebugValuePtr ppObject)
        => VTable.GetObjectPtr(Self, ref ppObject);

    public HResult Attach()
        => VTable.AttachPtr(Self);

    public HResult GetID(ref uint pId)
        => VTable.GetIDPtr(Self, ref pId);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAppDomainVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> StopPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ContinuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsRunningPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr, ref bool, HResult> HasQueuedCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugThreadEnumPtr, HResult> EnumerateThreadsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, CorDebugThreadPtr, HResult> SetAllThreadsDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DetachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], ref CorDebugErrorInfoEnumPtr, HResult> CanCommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], ref CorDebugErrorInfoEnumPtr, HResult> CommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugProcessPtr, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugAssemblyEnumPtr, HResult> EnumerateAssembliesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, ref CorDebugModulePtr, HResult> GetModuleFromMetaDataInterfacePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugBreakpointEnumPtr, HResult> EnumerateBreakpointsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugStepperEnumPtr, HResult> EnumerateSteppersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsAttachedPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValuePtr, HResult> GetObjectPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> AttachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetIDPtr;
    }
}


unsafe record struct CorDebugAssemblyPtr(IntPtr Pointer)
{
    public CorDebugAssembly? DerefOrDefault() => CorDebugAssembly.Create(this);
    public CorDebugAssembly Deref() => CorDebugAssembly.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetProcess(ref CorDebugProcessPtr ppProcess)
        => VTable.GetProcessPtr(Self, ref ppProcess);

    public HResult GetAppDomain(ref CorDebugAppDomainPtr ppAppDomain)
        => VTable.GetAppDomainPtr(Self, ref ppAppDomain);

    public HResult EnumerateModules(ref CorDebugModuleEnumPtr ppModules)
        => VTable.EnumerateModulesPtr(Self, ref ppModules);

    public HResult GetCodeBase(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetCodeBasePtr(Self, cchName, ref pcchName, szName);

    public HResult GetName(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetNamePtr(Self, cchName, ref pcchName, szName);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAssemblyVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugProcessPtr, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugAppDomainPtr, HResult> GetAppDomainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugModuleEnumPtr, HResult> EnumerateModulesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetCodeBasePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetNamePtr;
    }
}


unsafe record struct CorDebugProcessPtr(IntPtr Pointer)
{
    public CorDebugProcess? DerefOrDefault() => CorDebugProcess.Create(this);
    public CorDebugProcess Deref() => CorDebugProcess.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsRunning(ref bool pbRunning)
        => VTable.IsRunningPtr(Self, ref pbRunning);

    public HResult HasQueuedCallbacks(CorDebugThreadPtr pThread, ref bool pbQueued)
        => VTable.HasQueuedCallbacksPtr(Self, pThread, ref pbQueued);

    public HResult EnumerateThreads(ref CorDebugThreadEnumPtr ppThreads)
        => VTable.EnumerateThreadsPtr(Self, ref ppThreads);

    public HResult SetAllThreadsDebugState(CorDebugThreadState state, CorDebugThreadPtr pExceptThisThread)
        => VTable.SetAllThreadsDebugStatePtr(Self, state, pExceptThisThread);

    public HResult Detach()
        => VTable.DetachPtr(Self);

    public HResult Terminate(uint exitCode)
        => VTable.TerminatePtr(Self, exitCode);

    public HResult CanCommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, ref CorDebugErrorInfoEnumPtr pError)
        => VTable.CanCommitChangesPtr(Self, cSnapshots, pSnapshots, ref pError);

    public HResult CommitChanges(uint cSnapshots, CorDebugEditAndContinueSnapshotPtr[] pSnapshots, ref CorDebugErrorInfoEnumPtr pError)
        => VTable.CommitChangesPtr(Self, cSnapshots, pSnapshots, ref pError);

    public HResult GetID(ref uint pdwProcessId)
        => VTable.GetIDPtr(Self, ref pdwProcessId);

    public HResult GetHandle(ref IntPtr phProcessHandle)
        => VTable.GetHandlePtr(Self, ref phProcessHandle);

    public HResult GetThread(uint dwThreadId, ref CorDebugThreadPtr ppThread)
        => VTable.GetThreadPtr(Self, dwThreadId, ref ppThread);

    public HResult EnumerateObjects(ref CorDebugObjectEnumPtr ppObjects)
        => VTable.EnumerateObjectsPtr(Self, ref ppObjects);

    public HResult IsTransitionStub(ulong address, ref bool pbTransitionStub)
        => VTable.IsTransitionStubPtr(Self, address, ref pbTransitionStub);

    public HResult IsOSSuspended(uint threadID, ref bool pbSuspended)
        => VTable.IsOSSuspendedPtr(Self, threadID, ref pbSuspended);

    public HResult GetThreadContext(uint threadID, uint contextSize, byte[] context)
        => VTable.GetThreadContextPtr(Self, threadID, contextSize, context);

    public HResult SetThreadContext(uint threadID, uint contextSize, byte[] context)
        => VTable.SetThreadContextPtr(Self, threadID, contextSize, context);

    public HResult ReadMemory(ulong address, uint size, byte[] buffer, ref uint read)
        => VTable.ReadMemoryPtr(Self, address, size, buffer, ref read);

    public HResult WriteMemory(ulong address, uint size, byte[] buffer, ref uint written)
        => VTable.WriteMemoryPtr(Self, address, size, buffer, ref written);

    public HResult ClearCurrentException(uint threadID)
        => VTable.ClearCurrentExceptionPtr(Self, threadID);

    public HResult EnableLogMessages(bool fOnOff)
        => VTable.EnableLogMessagesPtr(Self, fOnOff);

    public HResult ModifyLogSwitch(int WCHAR)
        => VTable.ModifyLogSwitchPtr(Self, WCHAR);

    public HResult EnumerateAppDomains(ref CorDebugAppDomainEnumPtr ppAppDomains)
        => VTable.EnumerateAppDomainsPtr(Self, ref ppAppDomains);

    public HResult GetObject(ref CorDebugValuePtr ppObject)
        => VTable.GetObjectPtr(Self, ref ppObject);

    public HResult ThreadForFiberCookie(uint fiberCookie, ref CorDebugThreadPtr ppThread)
        => VTable.ThreadForFiberCookiePtr(Self, fiberCookie, ref ppThread);

    public HResult GetHelperThreadID(ref uint pThreadID)
        => VTable.GetHelperThreadIDPtr(Self, ref pThreadID);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugProcessVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> StopPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ContinuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsRunningPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadPtr, ref bool, HResult> HasQueuedCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugThreadEnumPtr, HResult> EnumerateThreadsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, CorDebugThreadPtr, HResult> SetAllThreadsDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> DetachPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> TerminatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], ref CorDebugErrorInfoEnumPtr, HResult> CanCommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueSnapshotPtr[], ref CorDebugErrorInfoEnumPtr, HResult> CommitChangesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetIDPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, HResult> GetHandlePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref CorDebugThreadPtr, HResult> GetThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugObjectEnumPtr, HResult> EnumerateObjectsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, ref bool, HResult> IsTransitionStubPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref bool, HResult> IsOSSuspendedPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, byte[], HResult> GetThreadContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, byte[], HResult> SetThreadContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, byte[], ref uint, HResult> ReadMemoryPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, byte[], ref uint, HResult> WriteMemoryPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> ClearCurrentExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> EnableLogMessagesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, HResult> ModifyLogSwitchPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugAppDomainEnumPtr, HResult> EnumerateAppDomainsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValuePtr, HResult> GetObjectPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref CorDebugThreadPtr, HResult> ThreadForFiberCookiePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetHelperThreadIDPtr;
    }
}


unsafe record struct CorDebugBreakpointPtr(IntPtr Pointer)
{
    public CorDebugBreakpoint? DerefOrDefault() => CorDebugBreakpoint.Create(this);
    public CorDebugBreakpoint Deref() => CorDebugBreakpoint.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsActive(ref bool pbActive)
        => VTable.IsActivePtr(Self, ref pbActive);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsActivePtr;
    }
}


unsafe record struct CorDebugStepperPtr(IntPtr Pointer)
{
    public CorDebugStepper? DerefOrDefault() => CorDebugStepper.Create(this);
    public CorDebugStepper Deref() => CorDebugStepper.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsActive(ref bool pbActive)
        => VTable.IsActivePtr(Self, ref pbActive);

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
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsActivePtr;
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
    public CorDebugThread? DerefOrDefault() => CorDebugThread.Create(this);
    public CorDebugThread Deref() => CorDebugThread.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetProcess(ref CorDebugProcessPtr ppProcess)
        => VTable.GetProcessPtr(Self, ref ppProcess);

    public HResult GetID(ref uint pdwThreadId)
        => VTable.GetIDPtr(Self, ref pdwThreadId);

    public HResult GetHandle(ref IntPtr phThreadHandle)
        => VTable.GetHandlePtr(Self, ref phThreadHandle);

    public HResult GetAppDomain(ref CorDebugAppDomainPtr ppAppDomain)
        => VTable.GetAppDomainPtr(Self, ref ppAppDomain);

    public HResult SetDebugState(CorDebugThreadState state)
        => VTable.SetDebugStatePtr(Self, state);

    public HResult GetDebugState(ref CorDebugThreadState pState)
        => VTable.GetDebugStatePtr(Self, ref pState);

    public HResult GetUserState(ref CorDebugUserState pState)
        => VTable.GetUserStatePtr(Self, ref pState);

    public HResult GetCurrentException(ref CorDebugValuePtr ppExceptionObject)
        => VTable.GetCurrentExceptionPtr(Self, ref ppExceptionObject);

    public HResult ClearCurrentException()
        => VTable.ClearCurrentExceptionPtr(Self);

    public HResult CreateStepper(ref CorDebugStepperPtr ppStepper)
        => VTable.CreateStepperPtr(Self, ref ppStepper);

    public HResult EnumerateChains(ref CorDebugChainEnumPtr ppChains)
        => VTable.EnumerateChainsPtr(Self, ref ppChains);

    public HResult GetActiveChain(ref CorDebugChainPtr ppChain)
        => VTable.GetActiveChainPtr(Self, ref ppChain);

    public HResult GetActiveFrame(ref CorDebugFramePtr ppFrame)
        => VTable.GetActiveFramePtr(Self, ref ppFrame);

    public HResult GetRegisterSet(ref CorDebugRegisterSetPtr ppRegisters)
        => VTable.GetRegisterSetPtr(Self, ref ppRegisters);

    public HResult CreateEval(ref CorDebugEvalPtr ppEval)
        => VTable.CreateEvalPtr(Self, ref ppEval);

    public HResult GetObject(ref CorDebugValuePtr ppObject)
        => VTable.GetObjectPtr(Self, ref ppObject);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugThreadVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugProcessPtr, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetIDPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, HResult> GetHandlePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugAppDomainPtr, HResult> GetAppDomainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugThreadState, HResult> SetDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugThreadState, HResult> GetDebugStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugUserState, HResult> GetUserStatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValuePtr, HResult> GetCurrentExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ClearCurrentExceptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugStepperPtr, HResult> CreateStepperPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainEnumPtr, HResult> EnumerateChainsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainPtr, HResult> GetActiveChainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFramePtr, HResult> GetActiveFramePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugRegisterSetPtr, HResult> GetRegisterSetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEvalPtr, HResult> CreateEvalPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValuePtr, HResult> GetObjectPtr;
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
    public CorDebugChain? DerefOrDefault() => CorDebugChain.Create(this);
    public CorDebugChain Deref() => CorDebugChain.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetThread(ref CorDebugThreadPtr ppThread)
        => VTable.GetThreadPtr(Self, ref ppThread);

    public HResult GetStackRange(ref ulong pStart, ref ulong pEnd)
        => VTable.GetStackRangePtr(Self, ref pStart, ref pEnd);

    public HResult GetContext(ref CorDebugContextPtr ppContext)
        => VTable.GetContextPtr(Self, ref ppContext);

    public HResult GetCaller(ref CorDebugChainPtr ppChain)
        => VTable.GetCallerPtr(Self, ref ppChain);

    public HResult GetCallee(ref CorDebugChainPtr ppChain)
        => VTable.GetCalleePtr(Self, ref ppChain);

    public HResult GetPrevious(ref CorDebugChainPtr ppChain)
        => VTable.GetPreviousPtr(Self, ref ppChain);

    public HResult GetNext(ref CorDebugChainPtr ppChain)
        => VTable.GetNextPtr(Self, ref ppChain);

    public HResult IsManaged(ref bool pManaged)
        => VTable.IsManagedPtr(Self, ref pManaged);

    public HResult EnumerateFrames(ref CorDebugFrameEnumPtr ppFrames)
        => VTable.EnumerateFramesPtr(Self, ref ppFrames);

    public HResult GetActiveFrame(ref CorDebugFramePtr ppFrame)
        => VTable.GetActiveFramePtr(Self, ref ppFrame);

    public HResult GetRegisterSet(ref CorDebugRegisterSetPtr ppRegisters)
        => VTable.GetRegisterSetPtr(Self, ref ppRegisters);

    public HResult GetReason(ref CorDebugChainReason pReason)
        => VTable.GetReasonPtr(Self, ref pReason);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugChainVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugThreadPtr, HResult> GetThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, ref ulong, HResult> GetStackRangePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugContextPtr, HResult> GetContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainPtr, HResult> GetCallerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainPtr, HResult> GetCalleePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainPtr, HResult> GetPreviousPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainPtr, HResult> GetNextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsManagedPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFrameEnumPtr, HResult> EnumerateFramesPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFramePtr, HResult> GetActiveFramePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugRegisterSetPtr, HResult> GetRegisterSetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainReason, HResult> GetReasonPtr;
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
    public CorDebugFrame? DerefOrDefault() => CorDebugFrame.Create(this);
    public CorDebugFrame Deref() => CorDebugFrame.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetChain(ref CorDebugChainPtr ppChain)
        => VTable.GetChainPtr(Self, ref ppChain);

    public HResult GetCode(ref CorDebugCodePtr ppCode)
        => VTable.GetCodePtr(Self, ref ppCode);

    public HResult GetFunction(ref CorDebugFunctionPtr ppFunction)
        => VTable.GetFunctionPtr(Self, ref ppFunction);

    public HResult GetFunctionToken(ref int pToken)
        => VTable.GetFunctionTokenPtr(Self, ref pToken);

    public HResult GetStackRange(ref ulong pStart, ref ulong pEnd)
        => VTable.GetStackRangePtr(Self, ref pStart, ref pEnd);

    public HResult GetCaller(ref CorDebugFramePtr ppFrame)
        => VTable.GetCallerPtr(Self, ref ppFrame);

    public HResult GetCallee(ref CorDebugFramePtr ppFrame)
        => VTable.GetCalleePtr(Self, ref ppFrame);

    public HResult CreateStepper(ref CorDebugStepperPtr ppStepper)
        => VTable.CreateStepperPtr(Self, ref ppStepper);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFrameVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugChainPtr, HResult> GetChainPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugCodePtr, HResult> GetCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFunctionPtr, HResult> GetFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetFunctionTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, ref ulong, HResult> GetStackRangePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFramePtr, HResult> GetCallerPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFramePtr, HResult> GetCalleePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugStepperPtr, HResult> CreateStepperPtr;
    }
}


unsafe record struct CorDebugModulePtr(IntPtr Pointer)
{
    public CorDebugModule? DerefOrDefault() => CorDebugModule.Create(this);
    public CorDebugModule Deref() => CorDebugModule.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetProcess(ref CorDebugProcessPtr ppProcess)
        => VTable.GetProcessPtr(Self, ref ppProcess);

    public HResult GetBaseAddress(ref ulong pAddress)
        => VTable.GetBaseAddressPtr(Self, ref pAddress);

    public HResult GetAssembly(ref CorDebugAssemblyPtr ppAssembly)
        => VTable.GetAssemblyPtr(Self, ref ppAssembly);

    public HResult GetName(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetNamePtr(Self, cchName, ref pcchName, szName);

    public HResult EnableJITDebugging(bool bTrackJITInfo, bool bAllowJitOpts)
        => VTable.EnableJITDebuggingPtr(Self, bTrackJITInfo, bAllowJitOpts);

    public HResult EnableClassLoadCallbacks(bool bClassLoadCallbacks)
        => VTable.EnableClassLoadCallbacksPtr(Self, bClassLoadCallbacks);

    public HResult GetFunctionFromToken(int methodDef, ref CorDebugFunctionPtr ppFunction)
        => VTable.GetFunctionFromTokenPtr(Self, methodDef, ref ppFunction);

    public HResult GetFunctionFromRVA(ulong rva, ref CorDebugFunctionPtr ppFunction)
        => VTable.GetFunctionFromRVAPtr(Self, rva, ref ppFunction);

    public HResult GetClassFromToken(int typeDef, ref CorDebugClassPtr ppClass)
        => VTable.GetClassFromTokenPtr(Self, typeDef, ref ppClass);

    public HResult CreateBreakpoint(ref CorDebugModuleBreakpointPtr ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ref ppBreakpoint);

    public HResult GetEditAndContinueSnapshot(ref CorDebugEditAndContinueSnapshotPtr ppEditAndContinueSnapshot)
        => VTable.GetEditAndContinueSnapshotPtr(Self, ref ppEditAndContinueSnapshot);

    public HResult GetMetaDataInterface(ref Guid riid, ref IntPtr ppObj)
        => VTable.GetMetaDataInterfacePtr(Self, ref riid, ref ppObj);

    public HResult GetToken(ref int pToken)
        => VTable.GetTokenPtr(Self, ref pToken);

    public HResult IsDynamic(ref bool pDynamic)
        => VTable.IsDynamicPtr(Self, ref pDynamic);

    public HResult GetGlobalVariableValue(int fieldDef, ref CorDebugValuePtr ppValue)
        => VTable.GetGlobalVariableValuePtr(Self, fieldDef, ref ppValue);

    public HResult GetSize(ref uint pcBytes)
        => VTable.GetSizePtr(Self, ref pcBytes);

    public HResult IsInMemory(ref bool pInMemory)
        => VTable.IsInMemoryPtr(Self, ref pInMemory);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugModuleVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugProcessPtr, HResult> GetProcessPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, HResult> GetBaseAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugAssemblyPtr, HResult> GetAssemblyPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, bool, HResult> EnableJITDebuggingPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> EnableClassLoadCallbacksPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, ref CorDebugFunctionPtr, HResult> GetFunctionFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, ref CorDebugFunctionPtr, HResult> GetFunctionFromRVAPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, ref CorDebugClassPtr, HResult> GetClassFromTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugModuleBreakpointPtr, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEditAndContinueSnapshotPtr, HResult> GetEditAndContinueSnapshotPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref Guid, ref IntPtr, HResult> GetMetaDataInterfacePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsDynamicPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, ref CorDebugValuePtr, HResult> GetGlobalVariableValuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsInMemoryPtr;
    }
}


unsafe record struct CorDebugFunctionPtr(IntPtr Pointer)
{
    public CorDebugFunction? DerefOrDefault() => CorDebugFunction.Create(this);
    public CorDebugFunction Deref() => CorDebugFunction.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetModule(ref CorDebugModulePtr ppModule)
        => VTable.GetModulePtr(Self, ref ppModule);

    public HResult GetClass(ref CorDebugClassPtr ppClass)
        => VTable.GetClassPtr(Self, ref ppClass);

    public HResult GetToken(ref int pMethodDef)
        => VTable.GetTokenPtr(Self, ref pMethodDef);

    public HResult GetILCode(ref CorDebugCodePtr ppCode)
        => VTable.GetILCodePtr(Self, ref ppCode);

    public HResult GetNativeCode(ref CorDebugCodePtr ppCode)
        => VTable.GetNativeCodePtr(Self, ref ppCode);

    public HResult CreateBreakpoint(ref CorDebugFunctionBreakpointPtr ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ref ppBreakpoint);

    public HResult GetLocalVarSigToken(ref int pmdSig)
        => VTable.GetLocalVarSigTokenPtr(Self, ref pmdSig);

    public HResult GetCurrentVersionNumber(ref uint pnCurrentVersion)
        => VTable.GetCurrentVersionNumberPtr(Self, ref pnCurrentVersion);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFunctionVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugModulePtr, HResult> GetModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugClassPtr, HResult> GetClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugCodePtr, HResult> GetILCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugCodePtr, HResult> GetNativeCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFunctionBreakpointPtr, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetLocalVarSigTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCurrentVersionNumberPtr;
    }
}


unsafe record struct CorDebugCodePtr(IntPtr Pointer)
{
    public CorDebugCode? DerefOrDefault() => CorDebugCode.Create(this);
    public CorDebugCode Deref() => CorDebugCode.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsIL(ref bool pbIL)
        => VTable.IsILPtr(Self, ref pbIL);

    public HResult GetFunction(ref CorDebugFunctionPtr ppFunction)
        => VTable.GetFunctionPtr(Self, ref ppFunction);

    public HResult GetAddress(ref ulong pStart)
        => VTable.GetAddressPtr(Self, ref pStart);

    public HResult GetSize(ref uint pcBytes)
        => VTable.GetSizePtr(Self, ref pcBytes);

    public HResult CreateBreakpoint(uint offset, ref CorDebugFunctionBreakpointPtr ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, offset, ref ppBreakpoint);

    public HResult GetCode(uint startOffset, uint endOffset, uint cBufferAlloc, byte[] buffer, ref uint pcBufferSize)
        => VTable.GetCodePtr(Self, startOffset, endOffset, cBufferAlloc, buffer, ref pcBufferSize);

    public HResult GetVersionNumber(ref uint nVersion)
        => VTable.GetVersionNumberPtr(Self, ref nVersion);

    public HResult GetILToNativeMapping(uint cMap, ref uint pcMap, COR_DEBUG_IL_TO_NATIVE_MAP[] map)
        => VTable.GetILToNativeMappingPtr(Self, cMap, ref pcMap, map);

    public HResult GetEnCRemapSequencePoints(uint cMap, ref uint pcMap, uint[] offsets)
        => VTable.GetEnCRemapSequencePointsPtr(Self, cMap, ref pcMap, offsets);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugCodeVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsILPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFunctionPtr, HResult> GetFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, HResult> GetAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref CorDebugFunctionBreakpointPtr, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, uint, uint, byte[], ref uint, HResult> GetCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetVersionNumberPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, COR_DEBUG_IL_TO_NATIVE_MAP[], HResult> GetILToNativeMappingPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, uint[], HResult> GetEnCRemapSequencePointsPtr;
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
    public CorDebugClass? DerefOrDefault() => CorDebugClass.Create(this);
    public CorDebugClass Deref() => CorDebugClass.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetModule(ref CorDebugModulePtr pModule)
        => VTable.GetModulePtr(Self, ref pModule);

    public HResult GetToken(ref int pTypeDef)
        => VTable.GetTokenPtr(Self, ref pTypeDef);

    public HResult GetStaticFieldValue(int fieldDef, CorDebugFramePtr pFrame, ref CorDebugValuePtr ppValue)
        => VTable.GetStaticFieldValuePtr(Self, fieldDef, pFrame, ref ppValue);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugClassVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugModulePtr, HResult> GetModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugFramePtr, ref CorDebugValuePtr, HResult> GetStaticFieldValuePtr;
    }
}


unsafe record struct CorDebugEvalPtr(IntPtr Pointer)
{
    public CorDebugEval? DerefOrDefault() => CorDebugEval.Create(this);
    public CorDebugEval Deref() => CorDebugEval.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult NewString(ref ushort @string)
        => VTable.NewStringPtr(Self, ref @string);

    public HResult NewArray(int elementType, CorDebugClassPtr pElementClass, uint rank, uint[] dims, uint[] lowBounds)
        => VTable.NewArrayPtr(Self, elementType, pElementClass, rank, dims, lowBounds);

    public HResult IsActive(ref bool pbActive)
        => VTable.IsActivePtr(Self, ref pbActive);

    public HResult Abort()
        => VTable.AbortPtr(Self);

    public HResult GetResult(ref CorDebugValuePtr ppResult)
        => VTable.GetResultPtr(Self, ref ppResult);

    public HResult GetThread(ref CorDebugThreadPtr ppThread)
        => VTable.GetThreadPtr(Self, ref ppThread);

    public HResult CreateValue(int elementType, CorDebugClassPtr pElementClass, ref CorDebugValuePtr ppValue)
        => VTable.CreateValuePtr(Self, elementType, pElementClass, ref ppValue);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEvalVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr, uint, CorDebugValuePtr[], HResult> CallFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugFunctionPtr, uint, CorDebugValuePtr[], HResult> NewObjectPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugClassPtr, HResult> NewObjectNoConstructorPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ushort, HResult> NewStringPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugClassPtr, uint, uint[], uint[], HResult> NewArrayPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> AbortPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValuePtr, HResult> GetResultPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugThreadPtr, HResult> GetThreadPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, CorDebugClassPtr, ref CorDebugValuePtr, HResult> CreateValuePtr;
    }
}


unsafe record struct CorDebugValuePtr(IntPtr Pointer)
{
    public CorDebugValue? DerefOrDefault() => CorDebugValue.Create(this);
    public CorDebugValue Deref() => CorDebugValue.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetType(ref int pType)
        => VTable.GetTypePtr(Self, ref pType);

    public HResult GetSize(ref uint pSize)
        => VTable.GetSizePtr(Self, ref pSize);

    public HResult GetAddress(ref ulong pAddress)
        => VTable.GetAddressPtr(Self, ref pAddress);

    public HResult CreateBreakpoint(ref CorDebugValueBreakpointPtr ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ref ppBreakpoint);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugValueVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetTypePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, HResult> GetAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValueBreakpointPtr, HResult> CreateBreakpointPtr;
    }
}


unsafe record struct CorDebugContextPtr(IntPtr Pointer)
{
    public CorDebugContext? DerefOrDefault() => CorDebugContext.Create(this);
    public CorDebugContext Deref() => CorDebugContext.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetType(ref int pType)
        => VTable.GetTypePtr(Self, ref pType);

    public HResult GetSize(ref uint pSize)
        => VTable.GetSizePtr(Self, ref pSize);

    public HResult GetAddress(ref ulong pAddress)
        => VTable.GetAddressPtr(Self, ref pAddress);

    public HResult CreateBreakpoint(ref CorDebugValueBreakpointPtr ppBreakpoint)
        => VTable.CreateBreakpointPtr(Self, ref ppBreakpoint);

    public HResult GetClass(ref CorDebugClassPtr ppClass)
        => VTable.GetClassPtr(Self, ref ppClass);

    public HResult GetFieldValue(CorDebugClassPtr pClass, int fieldDef, ref CorDebugValuePtr ppValue)
        => VTable.GetFieldValuePtr(Self, pClass, fieldDef, ref ppValue);

    public HResult GetVirtualMethod(int memberRef, ref CorDebugFunctionPtr ppFunction)
        => VTable.GetVirtualMethodPtr(Self, memberRef, ref ppFunction);

    public HResult GetContext(ref CorDebugContextPtr ppContext)
        => VTable.GetContextPtr(Self, ref ppContext);

    public HResult IsValueClass(ref bool pbIsValueClass)
        => VTable.IsValueClassPtr(Self, ref pbIsValueClass);

    public HResult GetManagedCopy(ref IntPtr ppObject)
        => VTable.GetManagedCopyPtr(Self, ref ppObject);

    public HResult SetFromManagedCopy(IntPtr pObject)
        => VTable.SetFromManagedCopyPtr(Self, pObject);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugContextVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetTypePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetSizePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, HResult> GetAddressPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValueBreakpointPtr, HResult> CreateBreakpointPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugClassPtr, HResult> GetClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, CorDebugClassPtr, int, ref CorDebugValuePtr, HResult> GetFieldValuePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, int, ref CorDebugFunctionPtr, HResult> GetVirtualMethodPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugContextPtr, HResult> GetContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsValueClassPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref IntPtr, HResult> GetManagedCopyPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, HResult> SetFromManagedCopyPtr;
    }
}


unsafe record struct CorDebugObjectEnumPtr(IntPtr Pointer)
{
    public CorDebugObjectEnum? DerefOrDefault() => CorDebugObjectEnum.Create(this);
    public CorDebugObjectEnum Deref() => CorDebugObjectEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, ulong[] objects, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, objects, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugObjectEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ulong[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugBreakpointEnumPtr(IntPtr Pointer)
{
    public CorDebugBreakpointEnum? DerefOrDefault() => CorDebugBreakpointEnum.Create(this);
    public CorDebugBreakpointEnum Deref() => CorDebugBreakpointEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugBreakpointPtr[] breakpoints, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, breakpoints, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugBreakpointEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugBreakpointPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugStepperEnumPtr(IntPtr Pointer)
{
    public CorDebugStepperEnum? DerefOrDefault() => CorDebugStepperEnum.Create(this);
    public CorDebugStepperEnum Deref() => CorDebugStepperEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugStepperPtr[] steppers, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, steppers, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugStepperEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugStepperPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugProcessEnumPtr(IntPtr Pointer)
{
    public CorDebugProcessEnum? DerefOrDefault() => CorDebugProcessEnum.Create(this);
    public CorDebugProcessEnum Deref() => CorDebugProcessEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugProcessPtr[] processes, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, processes, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugProcessEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugProcessPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugThreadEnumPtr(IntPtr Pointer)
{
    public CorDebugThreadEnum? DerefOrDefault() => CorDebugThreadEnum.Create(this);
    public CorDebugThreadEnum Deref() => CorDebugThreadEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugThreadPtr[] threads, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, threads, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugThreadEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugThreadPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugFrameEnumPtr(IntPtr Pointer)
{
    public CorDebugFrameEnum? DerefOrDefault() => CorDebugFrameEnum.Create(this);
    public CorDebugFrameEnum Deref() => CorDebugFrameEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugFramePtr[] frames, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, frames, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFrameEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugFramePtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugChainEnumPtr(IntPtr Pointer)
{
    public CorDebugChainEnum? DerefOrDefault() => CorDebugChainEnum.Create(this);
    public CorDebugChainEnum Deref() => CorDebugChainEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugChainPtr[] chains, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, chains, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugChainEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugChainPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugModuleEnumPtr(IntPtr Pointer)
{
    public CorDebugModuleEnum? DerefOrDefault() => CorDebugModuleEnum.Create(this);
    public CorDebugModuleEnum Deref() => CorDebugModuleEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugModulePtr[] modules, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, modules, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugModuleEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugModulePtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugErrorInfoEnumPtr(IntPtr Pointer)
{
    public CorDebugErrorInfoEnum? DerefOrDefault() => CorDebugErrorInfoEnum.Create(this);
    public CorDebugErrorInfoEnum Deref() => CorDebugErrorInfoEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugEditAndContinueErrorInfoPtr[] errors, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, errors, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugErrorInfoEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugEditAndContinueErrorInfoPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugAppDomainEnumPtr(IntPtr Pointer)
{
    public CorDebugAppDomainEnum? DerefOrDefault() => CorDebugAppDomainEnum.Create(this);
    public CorDebugAppDomainEnum Deref() => CorDebugAppDomainEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugAppDomainPtr[] values, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, values, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAppDomainEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugAppDomainPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugAssemblyEnumPtr(IntPtr Pointer)
{
    public CorDebugAssemblyEnum? DerefOrDefault() => CorDebugAssemblyEnum.Create(this);
    public CorDebugAssemblyEnum Deref() => CorDebugAssemblyEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    public HResult Next(uint celt, CorDebugAssemblyPtr[] values, ref uint pceltFetched)
        => VTable.NextPtr(Self, celt, values, ref pceltFetched);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugAssemblyEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, CorDebugAssemblyPtr[], ref uint, HResult> NextPtr;
    }
}


unsafe record struct CorDebugMDAPtr(IntPtr Pointer)
{
    public CorDebugMDA? DerefOrDefault() => CorDebugMDA.Create(this);
    public CorDebugMDA Deref() => CorDebugMDA.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetName(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetNamePtr(Self, cchName, ref pcchName, szName);

    public HResult GetDescription(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetDescriptionPtr(Self, cchName, ref pcchName, szName);

    public HResult GetXML(uint cchName, ref uint pcchName, ushort[] szName)
        => VTable.GetXMLPtr(Self, cchName, ref pcchName, szName);

    public HResult GetFlags(ref CorDebugMDAFlags pFlags)
        => VTable.GetFlagsPtr(Self, ref pFlags);

    public HResult GetOSThreadId(ref uint pOsTid)
        => VTable.GetOSThreadIdPtr(Self, ref pOsTid);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugMDAVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetNamePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetDescriptionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetXMLPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugMDAFlags, HResult> GetFlagsPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetOSThreadIdPtr;
    }
}


enum CorDebugMDAFlags
{
    MDA_FLAG_SLIP = 2,
}

unsafe record struct CorDebugEditAndContinueErrorInfoPtr(IntPtr Pointer)
{
    public CorDebugEditAndContinueErrorInfo? DerefOrDefault() => CorDebugEditAndContinueErrorInfo.Create(this);
    public CorDebugEditAndContinueErrorInfo Deref() => CorDebugEditAndContinueErrorInfo.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetModule(ref CorDebugModulePtr ppModule)
        => VTable.GetModulePtr(Self, ref ppModule);

    public HResult GetToken(ref int pToken)
        => VTable.GetTokenPtr(Self, ref pToken);

    public HResult GetErrorCode(ref HResult pHr)
        => VTable.GetErrorCodePtr(Self, ref pHr);

    public HResult GetString(uint cchString, ref uint pcchString, ushort[] szString)
        => VTable.GetStringPtr(Self, cchString, ref pcchString, szString);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEditAndContinueErrorInfoVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugModulePtr, HResult> GetModulePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref int, HResult> GetTokenPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref HResult, HResult> GetErrorCodePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, ref uint, ushort[], HResult> GetStringPtr;
    }
}


unsafe record struct CorDebugEditAndContinueSnapshotPtr(IntPtr Pointer)
{
    public CorDebugEditAndContinueSnapshot? DerefOrDefault() => CorDebugEditAndContinueSnapshot.Create(this);
    public CorDebugEditAndContinueSnapshot Deref() => CorDebugEditAndContinueSnapshot.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult CopyMetaData(IntPtr pIStream, ref Guid pMvid)
        => VTable.CopyMetaDataPtr(Self, pIStream, ref pMvid);

    public HResult GetMvid(ref Guid pMvid)
        => VTable.GetMvidPtr(Self, ref pMvid);

    public HResult GetRoDataRVA(ref uint pRoDataRVA)
        => VTable.GetRoDataRVAPtr(Self, ref pRoDataRVA);

    public HResult GetRwDataRVA(ref uint pRwDataRVA)
        => VTable.GetRwDataRVAPtr(Self, ref pRwDataRVA);

    public HResult SetPEBytes(IntPtr pIStream)
        => VTable.SetPEBytesPtr(Self, pIStream);

    public HResult SetILMap(int mdFunction, uint cMapSize, COR_IL_MAP[] map)
        => VTable.SetILMapPtr(Self, mdFunction, cMapSize, map);

    public HResult SetPESymbolBytes(IntPtr pIStream)
        => VTable.SetPESymbolBytesPtr(Self, pIStream);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEditAndContinueSnapshotVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, IntPtr, ref Guid, HResult> CopyMetaDataPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref Guid, HResult> GetMvidPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetRoDataRVAPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetRwDataRVAPtr;
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
    public CorDebugUnmanagedCallback? DerefOrDefault() => CorDebugUnmanagedCallback.Create(this);
    public CorDebugUnmanagedCallback Deref() => CorDebugUnmanagedCallback.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult DebugEvent(ref DEBUG_EVENT pDebugEvent, bool fOutOfBand)
        => VTable.DebugEventPtr(Self, ref pDebugEvent, fOutOfBand);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugUnmanagedCallbackVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref DEBUG_EVENT, bool, HResult> DebugEventPtr;
    }
}


[StructLayout(LayoutKind.Explicit)]
unsafe struct DEBUG_EVENT
{
    [FieldOffset(0)]
    public uint dwDebugEventCode;
    [FieldOffset(32)]
    public uint dwProcessId;
    [FieldOffset(64)]
    public uint dwThreadId;
    [FieldOffset(128)]
    public EXCEPTION_DEBUG_INFO Exception;
    [FieldOffset(128)]
    public CREATE_THREAD_DEBUG_INFO CreateThread;
    [FieldOffset(128)]
    public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    [FieldOffset(128)]
    public EXIT_THREAD_DEBUG_INFO ExitThread;
    [FieldOffset(128)]
    public EXIT_PROCESS_DEBUG_INFO ExitProcess;
    [FieldOffset(128)]
    public LOAD_DLL_DEBUG_INFO LoadDll;
    [FieldOffset(128)]
    public UNLOAD_DLL_DEBUG_INFO UnloadDll;
    [FieldOffset(128)]
    public OUTPUT_DEBUG_STRING_INFO DebugString;
    [FieldOffset(128)]
    public RIP_INFO RipInfo;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct EXCEPTION_DEBUG_INFO
{
    [FieldOffset(0)]
    public EXCEPTION_RECORD ExceptionRecord;
    [FieldOffset(704)]
    public uint dwFirstChance;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct EXCEPTION_RECORD
{
    [FieldOffset(0)]
    public uint ExceptionCode;
    [FieldOffset(32)]
    public uint ExceptionFlags;
    [FieldOffset(64)]
    public EXCEPTION_RECORD* ExceptionRecord;
    [FieldOffset(128)]
    public IntPtr ExceptionAddress;
    [FieldOffset(192)]
    public uint NumberParameters;
    [FieldOffset(224)]
    public fixed uint ExceptionInformation[15];
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct CREATE_THREAD_DEBUG_INFO
{
    [FieldOffset(0)]
    public IntPtr hThread;
    [FieldOffset(64)]
    public IntPtr lpThreadLocalBase;
    [FieldOffset(128)]
    public delegate* unmanaged[Stdcall]<IntPtr, uint> lpStartAddress;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct CREATE_PROCESS_DEBUG_INFO
{
    [FieldOffset(0)]
    public IntPtr hFile;
    [FieldOffset(64)]
    public IntPtr hProcess;
    [FieldOffset(128)]
    public IntPtr hThread;
    [FieldOffset(192)]
    public IntPtr lpBaseOfImage;
    [FieldOffset(256)]
    public uint dwDebugInfoFileOffset;
    [FieldOffset(288)]
    public uint nDebugInfoSize;
    [FieldOffset(320)]
    public IntPtr lpThreadLocalBase;
    [FieldOffset(384)]
    public delegate* unmanaged[Stdcall]<IntPtr, uint> lpStartAddress;
    [FieldOffset(448)]
    public IntPtr lpImageName;
    [FieldOffset(512)]
    public ushort fUnicode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct EXIT_THREAD_DEBUG_INFO
{
    [FieldOffset(0)]
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct EXIT_PROCESS_DEBUG_INFO
{
    [FieldOffset(0)]
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct LOAD_DLL_DEBUG_INFO
{
    [FieldOffset(0)]
    public IntPtr hFile;
    [FieldOffset(64)]
    public IntPtr lpBaseOfDll;
    [FieldOffset(128)]
    public uint dwDebugInfoFileOffset;
    [FieldOffset(160)]
    public uint nDebugInfoSize;
    [FieldOffset(192)]
    public IntPtr lpImageName;
    [FieldOffset(256)]
    public ushort fUnicode;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct UNLOAD_DLL_DEBUG_INFO
{
    [FieldOffset(0)]
    public IntPtr lpBaseOfDll;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct OUTPUT_DEBUG_STRING_INFO
{
    [FieldOffset(0)]
    public char* lpDebugStringData;
    [FieldOffset(64)]
    public ushort fUnicode;
    [FieldOffset(80)]
    public ushort nDebugStringLength;
}

[StructLayout(LayoutKind.Explicit)]
unsafe struct RIP_INFO
{
    [FieldOffset(0)]
    public uint dwError;
    [FieldOffset(32)]
    public uint dwType;
}

unsafe record struct CorDebugEnumPtr(IntPtr Pointer)
{
    public CorDebugEnum? DerefOrDefault() => CorDebugEnum.Create(this);
    public CorDebugEnum Deref() => CorDebugEnum.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult Clone(ref CorDebugEnumPtr ppEnum)
        => VTable.ClonePtr(Self, ref ppEnum);

    public HResult GetCount(ref uint pcelt)
        => VTable.GetCountPtr(Self, ref pcelt);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugEnumVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, HResult> SkipPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, HResult> ResetPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugEnumPtr, HResult> ClonePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetCountPtr;
    }
}


unsafe record struct CorDebugFunctionBreakpointPtr(IntPtr Pointer)
{
    public CorDebugFunctionBreakpoint? DerefOrDefault() => CorDebugFunctionBreakpoint.Create(this);
    public CorDebugFunctionBreakpoint Deref() => CorDebugFunctionBreakpoint.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsActive(ref bool pbActive)
        => VTable.IsActivePtr(Self, ref pbActive);

    public HResult GetFunction(ref CorDebugFunctionPtr ppFunction)
        => VTable.GetFunctionPtr(Self, ref ppFunction);

    public HResult GetOffset(ref uint pnOffset)
        => VTable.GetOffsetPtr(Self, ref pnOffset);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugFunctionBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugFunctionPtr, HResult> GetFunctionPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref uint, HResult> GetOffsetPtr;
    }
}


unsafe record struct CorDebugModuleBreakpointPtr(IntPtr Pointer)
{
    public CorDebugModuleBreakpoint? DerefOrDefault() => CorDebugModuleBreakpoint.Create(this);
    public CorDebugModuleBreakpoint Deref() => CorDebugModuleBreakpoint.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsActive(ref bool pbActive)
        => VTable.IsActivePtr(Self, ref pbActive);

    public HResult GetModule(ref CorDebugModulePtr ppModule)
        => VTable.GetModulePtr(Self, ref ppModule);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugModuleBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugModulePtr, HResult> GetModulePtr;
    }
}


unsafe record struct CorDebugValueBreakpointPtr(IntPtr Pointer)
{
    public CorDebugValueBreakpoint? DerefOrDefault() => CorDebugValueBreakpoint.Create(this);
    public CorDebugValueBreakpoint Deref() => CorDebugValueBreakpoint.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult IsActive(ref bool pbActive)
        => VTable.IsActivePtr(Self, ref pbActive);

    public HResult GetValue(ref CorDebugValuePtr ppValue)
        => VTable.GetValuePtr(Self, ref ppValue);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ICorDebugValueBreakpointVTable
    {
        public readonly delegate* unmanaged[Stdcall]<IntPtr, bool, HResult> ActivatePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref bool, HResult> IsActivePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref CorDebugValuePtr, HResult> GetValuePtr;
    }
}


unsafe record struct CorDebugRegisterSetPtr(IntPtr Pointer)
{
    public CorDebugRegisterSet? DerefOrDefault() => CorDebugRegisterSet.Create(this);
    public CorDebugRegisterSet Deref() => CorDebugRegisterSet.Create(this) ?? throw new InvalidOperationException("Pointer was null");
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

    public HResult GetRegistersAvailable(ref ulong pAvailable)
        => VTable.GetRegistersAvailablePtr(Self, ref pAvailable);

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
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ref ulong, HResult> GetRegistersAvailablePtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, ulong[], HResult> GetRegistersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, ulong, uint, ulong[], HResult> SetRegistersPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, byte[], HResult> GetThreadContextPtr;
        public readonly delegate* unmanaged[Stdcall]<IntPtr, uint, byte[], HResult> SetThreadContextPtr;
    }
}


