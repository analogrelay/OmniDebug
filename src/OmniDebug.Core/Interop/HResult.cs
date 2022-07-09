// Based on https://raw.githubusercontent.com/microsoft/clrmd/0c6e80073b1e4af842705b45467d25691bd369d3/src/Microsoft.Diagnostics.Runtime/src/Utilities/COMInterop/HResult.cs
// Used under MIT license: https://raw.githubusercontent.com/microsoft/clrmd/0c6e80073b1e4af842705b45467d25691bd369d3/LICENSE

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace OmniDebug.Interop;

public record struct HResult(int Value)
{
    public const int S_OK = 0;
    public const int S_FALSE = 1;
    public const int E_FAIL = unchecked((int)0x80004005);
    public const int E_INVALIDARG = unchecked((int)0x80070057);
    public const int E_NOTIMPL = unchecked((int)0x80004001);
    public const int E_NOINTERFACE = unchecked((int)0x80004002);
    public const int CORDBG_E_PROCESS_TERMINATED = unchecked((int)0x80131301);
    public const int CORDBG_E_OBJECT_NEUTERED = unchecked((int)0x8013134F);
    public const int CORDBG_E_STATIC_VAR_NOT_AVAILABLE = unchecked((int)0x8013131A);
    public const int CORDBG_E_CLASS_NOT_LOADED = unchecked((int)0x80131303);
    public const int CORDBG_E_ILLEGAL_IN_NATIVE_CODE = unchecked((int)0x80131C25);
    public const int CORDBG_E_ILLEGAL_AT_GC_UNSAFE_POINT = unchecked((int)0x80131C23);
    public const int CORDBG_E_ILLEGAL_IN_OPTIMIZED_CODE = unchecked((int)0x80131C26);
    public const int CORDBG_E_ILLEGAL_IN_PROLOG = unchecked((int)0x80131C24);
    public const int CORDBG_E_UNCOMPATIBLE_PLATFORMS = unchecked((int)0x80131C30);
    public const int CORDBG_E_UNRECOVERABLE_ERROR = unchecked((int)0x80131300);
    public const int CORDBG_E_PROCESS_NOT_SYNCHRONIZED = unchecked((int)0x80131302);
    public const int CLDB_E_RECORD_NOTFOUND = unchecked((int)0x80131130);
    public const int CLDB_E_INDEX_NOTFOUND = unchecked((int)0x80131124);
    public const int CORDBG_E_IL_VAR_NOT_AVAILABLE = unchecked((int)0x80131304);
    public const int CORDBG_E_INVALID_OPCODE = unchecked((int)0x80131C4D);
    public const int CORDBG_E_UNSUPPORTED = unchecked((int)0x80131C4E);
    public const int META_E_BAD_SIGNATURE = unchecked((int)0x80131192);
    
    public static implicit operator HResult(int hr) => new HResult(hr);
    public static implicit operator int(HResult hr) => hr.Value;
    
    public bool Succeeded => Value >= 0;

    public void ThrowIfFailed()
    {
        Marshal.ThrowExceptionForHR(Value);
    }

    public override string ToString()
    {
        return Value switch
        {
            S_OK => "S_OK",
            S_FALSE => "S_FALSE",
            E_FAIL => "E_FAIL",
            E_INVALIDARG => "E_INVALIDARG",
            E_NOTIMPL => "E_NOTIMPL",
            E_NOINTERFACE => "E_NOINTERFACE",
            CORDBG_E_PROCESS_TERMINATED => "CORDBG_E_PROCESS_TERMINATED",
            CORDBG_E_OBJECT_NEUTERED => "CORDBG_E_OBJECT_NEUTERED",
            CORDBG_E_STATIC_VAR_NOT_AVAILABLE => "CORDBG_E_STATIC_VAR_NOT_AVAILABLE",
            CORDBG_E_CLASS_NOT_LOADED => "CORDBG_E_CLASS_NOT_LOADED",
            CORDBG_E_ILLEGAL_IN_NATIVE_CODE => "CORDBG_E_ILLEGAL_IN_NATIVE_CODE",
            CORDBG_E_ILLEGAL_AT_GC_UNSAFE_POINT => "CORDBG_E_ILLEGAL_AT_GC_UNSAFE_POINT",
            CORDBG_E_ILLEGAL_IN_OPTIMIZED_CODE => "CORDBG_E_ILLEGAL_IN_OPTIMIZED_CODE",
            CORDBG_E_ILLEGAL_IN_PROLOG => "CORDBG_E_ILLEGAL_IN_PROLOG",
            CORDBG_E_UNCOMPATIBLE_PLATFORMS => "CORDBG_E_UNCOMPATIBLE_PLATFORMS",
            CORDBG_E_UNRECOVERABLE_ERROR => "CORDBG_E_UNRECOVERABLE_ERROR",
            CORDBG_E_PROCESS_NOT_SYNCHRONIZED => "CORDBG_E_PROCESS_NOT_SYNCHRONIZED",
            CLDB_E_RECORD_NOTFOUND => "CLDB_E_RECORD_NOTFOUND",
            CLDB_E_INDEX_NOTFOUND => "CLDB_E_INDEX_NOTFOUND",
            CORDBG_E_IL_VAR_NOT_AVAILABLE => "CORDBG_E_IL_VAR_NOT_AVAILABLE",
            CORDBG_E_INVALID_OPCODE => "CORDBG_E_INVALID_OPCODE",
            CORDBG_E_UNSUPPORTED => "CORDBG_E_UNSUPPORTED",
            META_E_BAD_SIGNATURE => "META_E_BAD_SIGNATURE",
            _ => $"0x{Value:x8}",
        };
    }
}