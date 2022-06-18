using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

using Microsoft.Extensions.Options;

namespace OmniDebug.Interop;

public class DebuggerShim
{
    readonly DbgShim _native;

    public DebuggerShim(IOptions<DebuggerShimOptions> options)
    {
        _native = DbgShim.Create(options.Value.Path ?? throw new ArgumentException("Missing required configuration setting 'DebuggerShim:Path'"));
    }

    public unsafe IReadOnlyList<RuntimeReference> EnumerateRuntimes(int debugeePID)
    {
        var hr = _native.EnumerateCLRs(
            debugeePID,
            out var ppHandleArrayOut,
            out var ppStringArrayOut,
            out var pdwArrayLengthOut);
        Marshal.ThrowExceptionForHR(hr);

        var refs = new RuntimeReference[pdwArrayLengthOut];
        for (int i = 0; i < pdwArrayLengthOut; i++)
        {
            var handle = Unsafe.Read<IntPtr>(Unsafe.Add<IntPtr>(ppHandleArrayOut, i));
            var pathPtr = Unsafe.Read<IntPtr>(Unsafe.Add<IntPtr>(ppStringArrayOut, i));
            var path = Marshal.PtrToStringUni(pathPtr);
            refs[i] = new(handle, path);
        }

        hr = _native.CloseCLREnumeration(ppHandleArrayOut, ppStringArrayOut, pdwArrayLengthOut);
        Marshal.ThrowExceptionForHR(hr);

        return refs;
    }

    /// <summary>
    /// P/Invoke definitions for the dbgshim native library
    /// </summary>
    unsafe class DbgShim
    {
        readonly EnumerateCLRsDelegate _enumerateClrs;
        readonly CloseCLREnumerationDelegate _closeClrEnumeration;

        DbgShim(EnumerateCLRsDelegate enumerateClrs, CloseCLREnumerationDelegate closeClrEnumeration)
        {
            _enumerateClrs = enumerateClrs;
            _closeClrEnumeration = closeClrEnumeration;
        }

        public int EnumerateCLRs(
            int debugeePID,
            out void* ppHandleArrayOut,
            out void* ppStringArrayOut,
            out int pdwArrayLengthOut)
            => _enumerateClrs(debugeePID, out ppHandleArrayOut, out ppStringArrayOut, out pdwArrayLengthOut);

        public int CloseCLREnumeration(
            void* ppHandleArrayOut,
            void* ppStringArrayOut,
            int pdwArrayLengthOut)
            => _closeClrEnumeration(ppHandleArrayOut, ppStringArrayOut, pdwArrayLengthOut);

        public static DbgShim Create(string path)
        {
            var lib = NativeLibrary.Load(path);
            var enumerateClrs = GetFunctionPointer<EnumerateCLRsDelegate>(lib, "EnumerateCLRs");
            var closeClrEnumeration = GetFunctionPointer<CloseCLREnumerationDelegate>(lib, "CloseCLREnumeration");

            return new DbgShim(enumerateClrs, closeClrEnumeration);
        }

        static T GetFunctionPointer<T>(IntPtr lib, string entryPoint)
            where T : Delegate
        {
            var ptr = NativeLibrary.GetExport(lib, entryPoint);
            return Marshal.GetDelegateForFunctionPointer<T>(ptr);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int EnumerateCLRsDelegate(
            int debugeePID,
            out void* ppHandleArrayOut,
            out void* ppStringArrayOut,
            out int pdwArrayLengthOut);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CloseCLREnumerationDelegate(
            void* ppHandleArrayOut,
            void* ppStringArrayOut,
            int pdwArrayLengthOut);
    }
}