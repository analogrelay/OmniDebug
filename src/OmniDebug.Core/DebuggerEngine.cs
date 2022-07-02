using Microsoft.Extensions.Logging;

using OmniDebug.Interop;

namespace OmniDebug;

public class DebuggerEngine
{
    readonly IDebuggerShim _dbgShim;
    private readonly ILoggerFactory _loggerFactory;
    readonly ILogger<DebuggerEngine> _logger;
    readonly Dictionary<int, DebuggeeProcess> _processes = new();

    public IReadOnlyDictionary<int, DebuggeeProcess> Processes => _processes;

    [Obsolete("You should not create a DebuggerEngine directly, use a DebuggerHost to access one.")]
    public DebuggerEngine(IDebuggerShim dbgShim, ILoggerFactory loggerFactory)
    {
        _dbgShim = dbgShim;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<DebuggerEngine>();
    }

    public IReadOnlyList<RuntimeReference> EnumerateRuntimes(int processId) => _dbgShim.EnumerateRuntimes(processId);

    public void AttachToProcess(int processId)
    {
        // First, enumerate the runtimes for the process.
        var runtimes = EnumerateRuntimes(processId);
        
        // Now create version strings for each CLR
        foreach (var runtime in runtimes)
        {
            if (runtime.Path is { Length: > 0 })
            {
                var versionString = _dbgShim.CreateVersionStringFromModule(processId, runtime.Path);
                var cordbgPtr = _dbgShim.CreateDebuggingInterfaceFromVersion(versionString);
                _logger.LogDebug("Loaded debugging interface for process {ProcessId} {VersionString}: {CordbgHandle}", processId, versionString, $"0x{cordbgPtr:X8}");
                
                // Start debugging services
                var cordbg = CorDebug.Create(cordbgPtr) ?? throw new InvalidOperationException("Failed to creatre debugging interface");
                cordbg.Initialize();
                
                // Attach a managed handler
                var handler = new CorDebugManagedCallback(_loggerFactory.CreateLogger<CorDebugManagedCallback>());
                cordbg.SetManagedHandler(handler.ICorDebugManagedCallback);
                
                // Attach to the process
                var processHandle = cordbg.DebugActiveProcess(processId);
                _logger.LogDebug("Attached debugger {CordbgHandle} to process {ProcessId}: {ProcessHandle}", $"0x{cordbgPtr:X8}", processId, $"0x{processHandle:X8}");
            }
        }
    }
}