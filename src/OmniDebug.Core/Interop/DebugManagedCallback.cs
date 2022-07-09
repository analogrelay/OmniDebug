using System.Diagnostics;

namespace OmniDebug.Interop;

class DebugManagedCallback: CorDebugManagedCallbackBase
{
    protected override HResult CreateProcessW(CorDebugProcessPtr pProcess)
    {
        var process = pProcess.Deref() ?? throw new UnreachableException();
        process.Continue(false).ThrowIfFailed();
    }
}