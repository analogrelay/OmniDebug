// See https://aka.ms/new-console-template for more information

using System.Runtime.InteropServices;

using OmniDebug;

if (!OmniDebugger.TryCreate(out var debugger))
{
    Console.Error.WriteLine("Failed to locate 'dbgshim'. Try setting the 'OMNIDEBUG_DBGSHIM_PATH' environment variable.");
    return 1;
}

var pid = int.Parse(args[0]);
Console.WriteLine($"CLRs in process {pid}:");
foreach (var rt in debugger.EnumerateRuntimes(pid))
{
    Console.WriteLine($"* 0x{rt.Handle:X8} {rt.Path}");
}

return 0;