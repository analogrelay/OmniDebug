namespace OmniDebug.Interop;

internal interface ICorDebugManagedCallback
{
    void CreateProcess(CorDebugProcess process);
    void ExitProcess(CorDebugProcess process);
}