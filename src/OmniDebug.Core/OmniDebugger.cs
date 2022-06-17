using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

using OmniDebug.Interop.DbgShim;

namespace OmniDebug;

public class OmniDebugger
{
    static readonly string DebuggerShimLibraryName = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
        ? "libdbgshim.dylib"
        : RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "dbgshim.dll"
            : "libdbgshim.so";
    
    readonly DbgShim _dbgShim;

    public OmniDebugger(DbgShim dbgShim)
    {
        _dbgShim = dbgShim;
    }

    public IReadOnlyList<RuntimeReference> EnumerateRuntimes(int processId)
    {
        return _dbgShim.EnumerateRuntimes(processId)
            .Where(t => t.Path is { Length: >0 })
            .Select(t => new RuntimeReference(t.Handle, t.Path!))
            .ToList();
    }

    public static bool TryCreate([NotNullWhen(true)] out OmniDebugger? debugger)
    {
        if (!TryResolveDbgShim(out var dbgShimPath))
        {
            debugger = null;
            return false;
        }

        return TryCreate(dbgShimPath, out debugger);
    }

    public static bool TryCreate(string debuggerShimPath, [NotNullWhen(true)] out OmniDebugger? debugger)
    {
        if(!DbgShim.TryCreate(debuggerShimPath, out var dbgShim))
        {
            debugger = null;
            return false;
        }

        debugger = new OmniDebugger(dbgShim);
        return true;
    }
    
    static bool TryResolveDbgShim([NotNullWhen(true)] out string? debuggerShimPath)
    {
        // Find dbgshim
        var dbgShimPath = Environment.GetEnvironmentVariable("OMNIDEBUG_DBGSHIM_PATH");
        if (dbgShimPath is { Length: > 0 })
        {
            debuggerShimPath = dbgShimPath;
            return true;
        }

        // Check the app base directory
        var appBaseDbgShim = Path.Combine(AppContext.BaseDirectory, DebuggerShimLibraryName);
        if (File.Exists(appBaseDbgShim))
        {
            debuggerShimPath = appBaseDbgShim;
            return true;
        }

        debuggerShimPath = null;
        return false;
    }
}

public record struct RuntimeReference(IntPtr Handle, string Path);
