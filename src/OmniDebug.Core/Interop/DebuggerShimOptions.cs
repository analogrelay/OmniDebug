using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

public class DebuggerShimOptions
{
    public static readonly string LibraryName = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
        ? "libdbgshim.dylib"
        : RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "dbgshim.dll"
            : "libdbgshim.so";

    public string? Path { get; set; } =
        System.IO.Path.Combine(AppContext.BaseDirectory, DebuggerShimOptions.LibraryName);
}