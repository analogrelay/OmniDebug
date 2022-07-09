// Based on: https://raw.githubusercontent.com/microsoft/clrmd/0c6e80073b1e4af842705b45467d25691bd369d3/src/Microsoft.Diagnostics.Runtime/src/Common/RefCountedFreeLibrary.cs
// Used under MIT license: https://raw.githubusercontent.com/microsoft/clrmd/0c6e80073b1e4af842705b45467d25691bd369d3/LICENSE

using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

public sealed class RefCountedFreeLibrary
{
    private readonly IntPtr _library;
    private int _refCount;

    public RefCountedFreeLibrary(IntPtr library)
    {
        _library = library;
        _refCount = 1;
    }

    public int AddRef()
    {
        return Interlocked.Increment(ref _refCount);
    }

    public int Release()
    {
        int count = Interlocked.Decrement(ref _refCount);
        if (count == 0 && _library != IntPtr.Zero)
            NativeLibrary.Free(_library);

        return count;
    }
}