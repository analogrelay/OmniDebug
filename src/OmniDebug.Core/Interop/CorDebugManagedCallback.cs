// Most of this file is copied from the dotnet/diagnostics repo.
// Specifically: https://github.com/dotnet/diagnostics/blob/1a12972c49eec0af5ca5a1b07cfd387f6c084a38/src/tests/DbgShim.UnitTests/ManagedCallbackWrapper.cs
// Used under the MIT license: https://github.com/dotnet/diagnostics/blob/1a12972c49eec0af5ca5a1b07cfd387f6c084a38/LICENSE.TXT

using System.Diagnostics;
using System.Runtime.InteropServices;

using Microsoft.Diagnostics.Runtime.Utilities;
using Microsoft.Extensions.Logging;

namespace OmniDebug.Interop;

internal sealed class CorDebugManagedCallback : COMCallableIUnknown
{
    static readonly Guid ICorDebugManagedCallbackIID = new("3D6F5F60-7538-11D3-8D5B-00104B35E7EF");
    static readonly Guid ICorDebugManagedCallback2IID = new("250E5EEA-DB5C-4C76-B6F3-8C46F12E3203");
    private readonly ICorDebugManagedCallback _callback;
    readonly ILogger _logger;

    public nint ICorDebugManagedCallback { get; }

    public CorDebugManagedCallback(CorDebugManagedCallback callback, ILogger logger)
    {
        _callback = callback;
        _logger = logger;
        
        VTableBuilder builder = AddInterface(ICorDebugManagedCallbackIID, validate: false);
        builder.AddMethod(new BreakpointDelegate((self, pAppDomain, pThread, pBreakpoint) => Unimplemented("Breakpoint")));
        builder.AddMethod(new StepCompleteDelegate((self, pAppDomain, pThread, pStepper, reason) => Unimplemented("StepComplete")));
        builder.AddMethod(new BreakDelegate((self, pAppDomain, pThread) => Unimplemented("Break")));
        builder.AddMethod(new ExceptionDelegate((self, pAppDomain, pThread, unhandled) => Unimplemented("Exception")));
        builder.AddMethod(new EvalCompleteDelegate((self, pAppDomain, pThread, pEval) => Unimplemented("EvalComplete")));
        builder.AddMethod(new EvalExceptionDelegate((self, pAppDomain, pThread, pEval) => Unimplemented("EvalException")));
        builder.AddMethod(new CreateProcessDelegate((self, pProcess) =>
        {
            try
            {
                _callback.CreateProcess(CorDebugProcess.Create(pProcess) ?? throw new UnreachableException());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CorDebugManagedCallback exception");
                return HResult.E_FAIL;
            }

            return HResult.S_OK;
        }));
        builder.AddMethod(new ExitProcessDelegate((self, pProcess) =>
        {
            try
            {
                _callback.ExitProcess(CorDebugProcess.Create(pProcess) ?? throw new UnreachableException());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CorDebugManagedCallback exception");
                return HResult.E_FAIL;
            }

            return HResult.S_OK;
        });
        builder.AddMethod(new CreateThreadDelegate((self, pAppDomain, pThread) => Unimplemented("CreateThread")));
        builder.AddMethod(new ExitThreadDelegate((self, pAppDomain, pThread) => Unimplemented("ExitThread")));
        builder.AddMethod(new LoadModuleDelegate((self, pAppDomain, pModule) => Unimplemented("LoadModule")));
        builder.AddMethod(new UnloadModuleDelegate((self, pAppDomain, pModule) => Unimplemented("UnloadModule")));
        builder.AddMethod(new LoadClassDelegate((self, pAppDomain, c) => Unimplemented("LoadClass")));
        builder.AddMethod(new UnloadClassDelegate((self, pAppDomain, c) => Unimplemented("UnloadClass")));
        builder.AddMethod(new DebuggerErrorDelegate((self, pProcess, errorHR, errorCode) => Unimplemented("DebuggerError")));
        builder.AddMethod(new LogMessageDelegate((self, pAppDomain, pThread, lLevel, pLogSwitchName, pMessage) =>
            Unimplemented("LogMessage")));
        builder.AddMethod(new LogSwitchDelegate(
            (self, pAppDomain, pThread, lLevel, ulReason, pLogSwitchName, pParentName) => Unimplemented("LogSwitch")));
        builder.AddMethod(new CreateAppDomainDelegate((self, pProcess, pAppDomain) => Unimplemented("CreateAppDomain")));
        builder.AddMethod(new ExitAppDomainDelegate((self, pProcess, pAppDomain) => Unimplemented("ExitAppDomain")));
        builder.AddMethod(new LoadAssemblyDelegate((self, pAppDomain, pAssembly) => Unimplemented("LoadAssembly")));
        builder.AddMethod(new UnloadAssemblyDelegate((self, pAppDomain, pAssembly) => Unimplemented("UnloadAssembly")));
        builder.AddMethod(new ControlCTrapDelegate((self, pProcess) => Unimplemented("ControlCTrap")));
        builder.AddMethod(new NameChangeDelegate((self, pAppDomain, pThread) => Unimplemented("NameChange")));
        builder.AddMethod(
            new UpdateModuleSymbolsDelegate((self, pAppDomain, pModule, pSymbolStream) => Unimplemented("UpdateModuleSymbols")));
        builder.AddMethod(new EditAndContinueRemapDelegate((self, pAppDomain, pThread, pFunction, fAccurate) =>
            Unimplemented("EditAndContinueRemap")));
        builder.AddMethod(new BreakpointSetErrorDelegate((self, pAppDomain, pThread, pBreakpoint, dwError) =>
            Unimplemented("BreakpointSetError")));
        ICorDebugManagedCallback = builder.Complete();

        builder = AddInterface(ICorDebugManagedCallback2IID, validate: false);
        builder.AddMethod(new FunctionRemapOpportunityDelegate(
            (self, pAppDomain, pThread, pOldFunction, pNewFunction, oldILOffset) => Unimplemented("FunctionRemapOpportunity")));
        builder.AddMethod(new CreateConnectionDelegate(
            (nint self, nint pProcess, uint dwConnectionId, ref ushort pConnName) => Unimplemented("CreateConnection")));
        builder.AddMethod(new ChangeConnectionDelegate((self, pProcess, dwConnectionId) => Unimplemented("ChangeConnection")));
        builder.AddMethod(new DestroyConnectionDelegate((self, pProcess, dwConnectionId) => Unimplemented("DestroyConnection")));
        builder.AddMethod(new ExceptionDelegate2((self, pAppDomain, pThread, pFrame, nOffset, dwEventType, dwFlags) =>
            Unimplemented("Exception2")));
        builder.AddMethod(new ExceptionUnwindDelegate((self, pAppDomain, pThread, dwEventType, dwFlags) =>
            Unimplemented("ExceptionUnwind")));
        builder.AddMethod(
            new FunctionRemapCompleteDelegate((self, pAppDomain, pThread, pFunction) => Unimplemented("FunctionRemapComplete")));
        builder.AddMethod(new MDANotificationDelegate((self, pController, pThread, pMDA) => Unimplemented("MDANotification")));
        builder.Complete();

        AddRef();
    }

    HResult Unimplemented(string callbackName)
    {
        _logger.LogError("Unimplemented callback {CallbackName}", callbackName);
        return HResult.S_OK;
    }

    #region ICorDebugManagedCallback delegates

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult BreakpointDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pBreakpoint);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult StepCompleteDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pStepper, [In] int reason);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult BreakDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ExceptionDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] int unhandled);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult EvalCompleteDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pEval);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult EvalExceptionDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pEval);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult CreateProcessDelegate([In] nint self, [In] nint pProcess);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ExitProcessDelegate([In] nint self, [In] nint pProcess);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult CreateThreadDelegate([In] nint self, [In] nint pAppDomain, [In] nint thread);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ExitThreadDelegate([In] nint self, [In] nint pAppDomain, [In] nint thread);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult LoadModuleDelegate([In] nint self, [In] nint pAppDomain, [In] nint pModule);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult UnloadModuleDelegate([In] nint self, [In] nint pAppDomain, [In] nint pModule);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult LoadClassDelegate([In] nint self, [In] nint pAppDomain, [In] nint c);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult UnloadClassDelegate([In] nint self, [In] nint pAppDomain, [In] nint c);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult DebuggerErrorDelegate([In] nint self, [In] nint pProcess, [In] HResult errorHR,
        [In] uint errorCode);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult LogMessageDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] int lLevel, [In, MarshalAs(UnmanagedType.LPWStr)] string pLogSwitchName,
        [In, MarshalAs(UnmanagedType.LPWStr)] string pMessage);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult LogSwitchDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] int lLevel, [In] uint ulReason, [In, MarshalAs(UnmanagedType.LPWStr)] string pLogSwitchName,
        [In, MarshalAs(UnmanagedType.LPWStr)] string pParentName);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult CreateAppDomainDelegate([In] nint self, [In] nint pProcess, [In] nint pAppDomain);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ExitAppDomainDelegate([In] nint self, [In] nint pProcess, [In] nint pAppDomain);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult LoadAssemblyDelegate([In] nint self, [In] nint pAppDomain, [In] nint pAssembly);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult UnloadAssemblyDelegate([In] nint self, [In] nint pAppDomain, [In] nint pAssembly);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ControlCTrapDelegate([In] nint self, [In] nint pProcess);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult NameChangeDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult UpdateModuleSymbolsDelegate([In] nint self, [In] nint pAppDomain, [In] nint pModule,
        [In] nint pSymbolStream);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult EditAndContinueRemapDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pFunction, [In] int fAccurate);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult BreakpointSetErrorDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pBreakpoint, [In] uint dwError);

    #endregion

    #region ICorDebugManagedCallback2 delegates

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult FunctionRemapOpportunityDelegate([In] nint self, [In] nint pAppDomain,
        [In] nint pThread, [In] nint pOldFunction, [In] nint pNewFunction, [In] uint oldILOffset);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult CreateConnectionDelegate([In] nint self, [In] nint pProcess, [In] uint dwConnectionId,
        [In] ref ushort pConnName);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ChangeConnectionDelegate([In] nint self, [In] nint pProcess, [In] uint dwConnectionId);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult
        DestroyConnectionDelegate([In] nint self, [In] nint pProcess, [In] uint dwConnectionId);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ExceptionDelegate2([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] nint pFrame, [In] uint nOffset, [In] int dwEventType, [In] uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult ExceptionUnwindDelegate([In] nint self, [In] nint pAppDomain, [In] nint pThread,
        [In] int dwEventType, [In] uint dwFlags);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult FunctionRemapCompleteDelegate([In] nint self, [In] nint pAppDomain,
        [In] nint pThread, [In] nint pFunction);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate HResult MDANotificationDelegate([In] nint self, [In] nint pController, [In] nint pThread,
        [In] nint pMDA);

    #endregion
}