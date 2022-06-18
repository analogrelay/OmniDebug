using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

using OmniDebug.Interop;

namespace OmniDebug;

public class DebuggerEngine
{
    readonly DebuggerShim _dbgShim;

    [Obsolete("You should not create a DebuggerEngine directly, use a DebuggerHost to access one.")]
    public DebuggerEngine(DebuggerShim dbgShim)
    {
        _dbgShim = dbgShim;
    }

    public IReadOnlyList<RuntimeReference> EnumerateRuntimes(int processId) => _dbgShim.EnumerateRuntimes(processId);
}