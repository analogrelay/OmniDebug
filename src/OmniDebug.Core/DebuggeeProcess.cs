using OmniDebug.Interop;

namespace OmniDebug;

/// <summary>
/// Represents a process being debugged.
/// </summary>
public class DebuggeeProcess
{
    readonly int _processId;
    readonly CorDebug _cordbg;

    internal DebuggeeProcess(int processId, CorDebug cordbg)
    {
        _processId = processId;
        _cordbg = cordbg;
    }

    internal void InitializeDebugger() => _cordbg.Initialize();
}