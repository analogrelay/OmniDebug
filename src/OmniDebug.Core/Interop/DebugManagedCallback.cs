using System.Diagnostics;

namespace OmniDebug.Interop;

class DebugManagedCallback: CorDebugManagedCallbackBase
{
    protected override HResult CreateProcessW(CorDebugProcessPtr pProcess)
    {
        var process = pProcess.Deref();
        process.Continue(false).ThrowIfFailed();
        return HResult.S_OK;
    }

    protected override HResult CreateAppDomain(CorDebugProcessPtr pProcess, CorDebugAppDomainPtr pAppDomain)
    {
        var appDomain = pAppDomain.Deref();
        appDomain.Attach().ThrowIfFailed();
        appDomain.Continue(false);
        return HResult.S_OK;
    }

    protected override HResult LoadModule(CorDebugAppDomainPtr pAppDomain, CorDebugModulePtr pModule)
    {
        var module = pModule.Deref();
        return base.LoadModule(pAppDomain, pModule);
    }
}