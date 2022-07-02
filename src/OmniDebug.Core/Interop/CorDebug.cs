// Most of this file is copied from the dotnet/diagnostics repo.
// Specifically: https://github.com/dotnet/diagnostics/blob/1a12972c49eec0af5ca5a1b07cfd387f6c084a38/src/tests/DbgShim.UnitTests/ICorDebug.cs
// Used under the MIT license: https://github.com/dotnet/diagnostics/blob/1a12972c49eec0af5ca5a1b07cfd387f6c084a38/LICENSE.TXT

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using Microsoft.Diagnostics.Runtime;
using Microsoft.Diagnostics.Runtime.Utilities;

namespace OmniDebug.Interop;

/// <summary>
/// This type supports OmniDebug and is not intended to be used directly from your code.
/// </summary>
internal unsafe class CorDebug : CallableCOMWrapper
{
    static readonly Guid IID = new Guid("3d6f5f61-7538-11d3-8d5b-00104b35e7ef");
    ref readonly ICorDebugVTable VTable => ref Unsafe.AsRef<ICorDebugVTable>(_vtable);

    public static CorDebug? Create(nint punk) => punk != 0 ? new CorDebug(punk) : null;

    CorDebug(nint punk) : base(new RefCountedFreeLibrary(0), IID, punk)
    {
        SuppressRelease();
    }

    public void Initialize()
    {
        var hr = VTable.Initialize(Self);
        Marshal.ThrowExceptionForHR(hr);
    }

    public void Terminate()
    {
        var hr = VTable.Terminate(Self);
        Marshal.ThrowExceptionForHR(hr);
    }

    public void SetManagedHandler(nint managedCallback)
    {
        var hr = VTable.SetManangedHandler(Self, managedCallback);
        Marshal.ThrowExceptionForHR(hr);
    }

    public nint DebugActiveProcess(int processId)
    {
        var hr = VTable.DebugActiveProcess(Self, processId, 0, out var process);
        Marshal.ThrowExceptionForHR(hr);
        return process;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly unsafe struct ICorDebugVTable
    {
        public readonly delegate* unmanaged[Stdcall]<nint, HResult> Initialize;
        public readonly delegate* unmanaged[Stdcall]<nint, HResult> Terminate;
        public readonly delegate* unmanaged[Stdcall]<nint, nint, HResult> SetManangedHandler;
        public readonly delegate* unmanaged[Stdcall]<nint, nint, HResult> SetUnmanangedHandler;
        public readonly delegate* unmanaged[Stdcall]<nint, HResult> CreateProcess;
        public readonly delegate* unmanaged[Stdcall]<nint, int, int, out nint, HResult> DebugActiveProcess;
    }
}