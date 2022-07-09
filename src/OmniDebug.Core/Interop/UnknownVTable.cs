// Based on https://raw.githubusercontent.com/microsoft/clrmd/0c6e80073b1e4af842705b45467d25691bd369d3/src/Microsoft.Diagnostics.Runtime/src/Utilities/COMInterop/UnknownVTable.cs
// Used under MIT license: https://raw.githubusercontent.com/microsoft/clrmd/0c6e80073b1e4af842705b45467d25691bd369d3/LICENSE

namespace OmniDebug.Interop;

/// <summary>
/// The basic VTable for an IUnknown interface.
/// </summary>
public unsafe struct IUnknownVTable
{
    public delegate* unmanaged[Stdcall]<IntPtr, in Guid, out IntPtr, int> QueryInterface;
    public delegate* unmanaged[Stdcall]<IntPtr, int> AddRef;
    public delegate* unmanaged[Stdcall]<IntPtr, int> Release;
}