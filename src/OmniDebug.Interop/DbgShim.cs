using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace OmniDebug.Interop.DbgShim;

public class DbgShim
{
    readonly DbgShimNative _native;

    DbgShim(DbgShimNative native)
    {
        _native = native;
    }

    public static bool TryCreate(string dbgshimPath, [NotNullWhen(true)] out DbgShim? shim)
    {
        if (DbgShimNative.TryCreate(dbgshimPath, out var native))
        {
            shim = new DbgShim(native);
            return true;
        }

        shim = null;
        return false;
    }
    
    public unsafe IReadOnlyList<(IntPtr Handle, string? Path)> EnumerateRuntimes(int debugeePID)
    {
        var hr = _native.EnumerateCLRs(
            debugeePID,
            out var ppHandleArrayOut,
            out var ppStringArrayOut,
            out var pdwArrayLengthOut);
        Marshal.ThrowExceptionForHR(hr);

        var refs = new (IntPtr Handle, string? Path)[pdwArrayLengthOut];
        for (int i = 0; i < pdwArrayLengthOut; i++)
        {
            var handle = Unsafe.Read<IntPtr>(Unsafe.Add<IntPtr>(ppHandleArrayOut, i));
            var pathPtr = Unsafe.Read<IntPtr>(Unsafe.Add<IntPtr>(ppStringArrayOut, i));
            var path = Marshal.PtrToStringUni(pathPtr);
            refs[i] = (handle, path);
        }

        hr = _native.CloseCLREnumeration(ppHandleArrayOut, ppStringArrayOut, pdwArrayLengthOut);
        Marshal.ThrowExceptionForHR(hr);

        return refs;
    }

    /// <summary>
    /// P/Invoke definitions for the dbgshim native library
    /// </summary>
    class DbgShimNative
    {
        readonly EnumerateCLRsDelegate _enumerateClrs;
        readonly CloseCLREnumerationDelegate _closeClrEnumeration;

        DbgShimNative(EnumerateCLRsDelegate enumerateClrs, CloseCLREnumerationDelegate closeClrEnumeration)
        {
            _enumerateClrs = enumerateClrs;
            _closeClrEnumeration = closeClrEnumeration;
        }

        public unsafe int EnumerateCLRs(
            int debugeePID,
            out void* ppHandleArrayOut,
            out void* ppStringArrayOut,
            out int pdwArrayLengthOut)
            => _enumerateClrs(debugeePID, out ppHandleArrayOut, out ppStringArrayOut, out pdwArrayLengthOut); 
        
        public unsafe int CloseCLREnumeration(
            void* ppHandleArrayOut,
            void* ppStringArrayOut,
            int pdwArrayLengthOut)
            => _closeClrEnumeration(ppHandleArrayOut, ppStringArrayOut, pdwArrayLengthOut);

        public static bool TryCreate(string path, [NotNullWhen(true)] out DbgShimNative? native)
        {
            if (!NativeLibrary.TryLoad(path, out var lib))
            {
                native = null;
                return false;
            }

            var success = true;
            success &= TryGetFunctionPointer<EnumerateCLRsDelegate>(lib, "EnumerateCLRs", out var enumerateClrs);
            success &= TryGetFunctionPointer<CloseCLREnumerationDelegate>(lib, "CloseCLREnumeration",
                out var closeClrEnumeration);

            if (success)
            {
                native = new DbgShimNative(
                    enumerateClrs,
                    closeClrEnumeration);
                return true;
            }

            native = null;
            return false;
        }

        static bool TryGetFunctionPointer<T>(IntPtr lib, string entryPoint, [NotNullWhen(true)] out T? func)
            where T : Delegate
        {
            if (NativeLibrary.TryGetExport(lib, entryPoint, out var ptr))
            {
                func = Marshal.GetDelegateForFunctionPointer<T>(ptr);
                return true;
            }

            func = null;
            return false;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private unsafe delegate int EnumerateCLRsDelegate(
            int debugeePID,
            out void* ppHandleArrayOut,
            out void* ppStringArrayOut,
            out int pdwArrayLengthOut);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private unsafe delegate int CloseCLREnumerationDelegate(
            void* ppHandleArrayOut,
            void* ppStringArrayOut,
            int pdwArrayLengthOut);
    }
}