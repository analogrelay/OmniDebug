using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

/// <summary>
/// Provides configuration options for an implementation of <see cref="IDebuggerShim"/>.
/// </summary>
public class DebuggerShimOptions
{
    public static readonly string LibraryName = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
        ? "libdbgshim.dylib"
        : RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "dbgshim.dll"
            : "libdbgshim.so";

    /// <summary>
    /// Gets or sets the path to the "dbgshim" library.
    /// </summary>
    public string? Path { get; set; } =
        System.IO.Path.Combine(AppContext.BaseDirectory, DebuggerShimOptions.LibraryName);
}