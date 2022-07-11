// ReSharper disable All
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

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

    protected virtual HResult LogMessage(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, ref int pLogSwitchName, ref int pMessage)
    {
        return HResult.E_NOTIMPL;
    }

    protected virtual HResult LogSwitch(CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, ref int pLogSwitchName, ref int pParentName)
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

    protected virtual HResult CreateConnection(CorDebugProcessPtr pProcess, uint dwConnectionId, ref int pConnName)
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
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.BreakpointDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint) => self.Breakpoint(pAppDomain, pThread, pBreakpoint)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.StepCompleteDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugStepperPtr pStepper, CorDebugStepReason reason) => self.StepComplete(pAppDomain, pThread, pStepper, reason)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.BreakDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread) => self.Break(pAppDomain, thread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExceptionDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, bool unhandled) => self.Exception(pAppDomain, pThread, unhandled)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.EvalCompleteDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval) => self.EvalComplete(pAppDomain, pThread, pEval)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.EvalExceptionDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugEvalPtr pEval) => self.EvalException(pAppDomain, pThread, pEval)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.CreateProcessWDelegate((IntPtr Self, CorDebugProcessPtr pProcess) => self.CreateProcessW(pProcess)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExitProcessDelegate((IntPtr Self, CorDebugProcessPtr pProcess) => self.ExitProcess(pProcess)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.CreateThreadDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread) => self.CreateThread(pAppDomain, thread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExitThreadDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr thread) => self.ExitThread(pAppDomain, thread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LoadModuleDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule) => self.LoadModule(pAppDomain, pModule)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UnloadModuleDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule) => self.UnloadModule(pAppDomain, pModule)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LoadClassDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c) => self.LoadClass(pAppDomain, c)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UnloadClassDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugClassPtr c) => self.UnloadClass(pAppDomain, c)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.DebuggerErrorDelegate((IntPtr Self, CorDebugProcessPtr pProcess, HResult errorHR, uint errorCode) => self.DebuggerError(pProcess, errorHR, errorCode)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LogMessageDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, ref int pLogSwitchName, ref int pMessage) => self.LogMessage(pAppDomain, pThread, lLevel, ref pLogSwitchName, ref pMessage)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LogSwitchDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, ref int pLogSwitchName, ref int pParentName) => self.LogSwitch(pAppDomain, pThread, lLevel, ulReason, ref pLogSwitchName, ref pParentName)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.CreateAppDomainDelegate((IntPtr Self, CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain) => self.CreateAppDomain(pProcess, pAppDomain)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ExitAppDomainDelegate((IntPtr Self, CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain) => self.ExitAppDomain(pProcess, pAppDomain)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.LoadAssemblyDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly) => self.LoadAssembly(pAppDomain, pAssembly)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UnloadAssemblyDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugAssemblyPtr pAssembly) => self.UnloadAssembly(pAppDomain, pAssembly)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.ControlCTrapDelegate((IntPtr Self, CorDebugProcessPtr pProcess) => self.ControlCTrap(pProcess)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.NameChangeDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread) => self.NameChange(pAppDomain, pThread)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.UpdateModuleSymbolsDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule, IntPtr pSymbolStream) => self.UpdateModuleSymbols(pAppDomain, pModule, pSymbolStream)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.EditAndContinueRemapDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction, bool fAccurate) => self.EditAndContinueRemap(pAppDomain, pThread, pFunction, fAccurate)));
        builder.AddMethod(new ICorDebugManagedCallbackDelegates.BreakpointSetErrorDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugBreakpointPtr pBreakpoint, uint dwError) => self.BreakpointSetError(pAppDomain, pThread, pBreakpoint, dwError)));
        return new CorDebugManagedCallbackPtr(builder.Complete());
    }

    static CorDebugManagedCallback2Ptr DefineICorDebugManagedCallback2(CorDebugManagedCallbackBase self, Guid iid)
    {
        var builder = self.AddInterface(iid, validate: false);
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.FunctionRemapOpportunityDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pOldFunction, CorDebugFunctionPtr pNewFunction, uint oldILOffset) => self.FunctionRemapOpportunity(pAppDomain, pThread, pOldFunction, pNewFunction, oldILOffset)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.CreateConnectionDelegate((IntPtr Self, CorDebugProcessPtr pProcess, uint dwConnectionId, ref int pConnName) => self.CreateConnection(pProcess, dwConnectionId, ref pConnName)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.ChangeConnectionDelegate((IntPtr Self, CorDebugProcessPtr pProcess, uint dwConnectionId) => self.ChangeConnection(pProcess, dwConnectionId)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.DestroyConnectionDelegate((IntPtr Self, CorDebugProcessPtr pProcess, uint dwConnectionId) => self.DestroyConnection(pProcess, dwConnectionId)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.ExceptionDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFramePtr pFrame, uint nOffset, CorDebugExceptionCallbackType dwEventType, uint dwFlags) => self.Exception(pAppDomain, pThread, pFrame, nOffset, dwEventType, dwFlags)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.ExceptionUnwindDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugExceptionUnwindCallbackType dwEventType, uint dwFlags) => self.ExceptionUnwind(pAppDomain, pThread, dwEventType, dwFlags)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.FunctionRemapCompleteDelegate((IntPtr Self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, CorDebugFunctionPtr pFunction) => self.FunctionRemapComplete(pAppDomain, pThread, pFunction)));
        builder.AddMethod(new ICorDebugManagedCallback2Delegates.MDANotificationDelegate((IntPtr Self, CorDebugControllerPtr pController, CorDebugThreadPtr pThread, CorDebugMDAPtr pMDA) => self.MDANotification(pController, pThread, pMDA)));
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
        public delegate HResult LogMessageDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, ref int pLogSwitchName, ref int pMessage);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate HResult LogSwitchDelegate(IntPtr self, CorDebugAppDomainPtr pAppDomain, CorDebugThreadPtr pThread, int lLevel, uint ulReason, ref int pLogSwitchName, ref int pParentName);

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
        public delegate HResult CreateConnectionDelegate(IntPtr self, CorDebugProcessPtr pProcess, uint dwConnectionId, ref int pConnName);

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
