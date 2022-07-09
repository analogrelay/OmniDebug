using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using Microsoft.Extensions.Options;

namespace OmniDebug.Interop;

/// <summary>
/// Provides an interface to the .NET "Debugger Shim" (dbgshim.dll).
/// </summary>
public interface IDebuggerShim
{
    IReadOnlyList<RuntimeReference> EnumerateRuntimes(int debugeePID);
    string CreateVersionStringFromModule(int processId, string modulePath);

    nint CreateDebuggingInterfaceFromVersion(string versionString,
        int debuggerVersion = DebuggerShim.CorDebugVersion4);
}

/// <summary>
/// This type supports OmniDebug and is not intended to be used directly from your code.
/// </summary>
internal class DebuggerShim : IDebuggerShim
{
    const int HRESULT_ERROR_INSUFFICIENT_BUFFER = unchecked((int)0x8007007a);
    readonly DbgShim _native;
    
    public const int CorDebugVersion2 = 3;
    public const int CorDebugVersion4 = 4;

    public DebuggerShim(IOptions<DebuggerShimOptions> options)
    {
        _native = DbgShim.Create(options.Value.Path ??
                                 throw new ArgumentException(
                                     "Missing required configuration setting 'DebuggerShim:Path'"));
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
            var handle = Unsafe.Read<nint>(Unsafe.Add<nint>(ppHandleArrayOut, i));
            var pathPtr = Unsafe.Read<nint>(Unsafe.Add<nint>(ppStringArrayOut, i));
            var path = Marshal.PtrToStringUni(pathPtr);
            refs[i] = new(handle, path);
        }

        hr = _native.CloseCLREnumeration(ppHandleArrayOut, ppStringArrayOut, pdwArrayLengthOut);
        Marshal.ThrowExceptionForHR(hr);

        return refs;
    }

    public unsafe string CreateVersionStringFromModule(int processId, string modulePath)
    {
        // Call the API once with a null buffer to get the required buffer size.
        var hr = _native.CreateVersionStringFromModule(processId, modulePath, null, 0, out var versionStringSize);
        if (hr == HRESULT_ERROR_INSUFFICIENT_BUFFER)
        {
            var buffer = new char[versionStringSize];
            fixed (char* bufferPtr = buffer)
            {
                hr = _native.CreateVersionStringFromModule(
                    processId,
                    modulePath, 
                    bufferPtr, 
                    versionStringSize,
                    out versionStringSize);
                Marshal.ThrowExceptionForHR(hr);
            }

            return new string(buffer);
        }

        Marshal.ThrowExceptionForHR(hr);
        
        // We shouldn't get here.
        // We passed a null buffer, but the API didn't return an error. That's B A D.
        throw new UnreachableException();
    }

    public nint CreateDebuggingInterfaceFromVersion(string versionString,
        int debuggerVersion = CorDebugVersion4)
    {
        var hr = _native.CreateDebuggingInterfaceFromVersion2(debuggerVersion, versionString, null, out var cordbg);
        Marshal.ThrowExceptionForHR(hr);
        return cordbg;
    }

    /// <summary>
    /// P/Invoke definitions for the dbgshim native library
    /// </summary>
    unsafe class DbgShim
    {
        readonly EnumerateCLRsDelegate _enumerateClrs;
        readonly CloseCLREnumerationDelegate _closeClrEnumeration;
        private readonly CreateVersionStringFromModuleDelegate _createVersionStringFromModule;
        private readonly CreateDebuggingInterfaceFromVersion2Delegate _createDebuggingInterfaceFromVersion2;

        DbgShim(
            EnumerateCLRsDelegate enumerateClrs,
            CloseCLREnumerationDelegate closeClrEnumeration,
            CreateVersionStringFromModuleDelegate createVersionStringFromModule,
            CreateDebuggingInterfaceFromVersion2Delegate createDebuggingInterfaceFromVersion2)
        {
            _enumerateClrs = enumerateClrs;
            _closeClrEnumeration = closeClrEnumeration;
            _createVersionStringFromModule = createVersionStringFromModule;
            _createDebuggingInterfaceFromVersion2 = createDebuggingInterfaceFromVersion2;
        }

        public HResult EnumerateCLRs(
            int debugeePID,
            out void* ppHandleArrayOut,
            out void* ppStringArrayOut,
            out int pdwArrayLengthOut)
            => _enumerateClrs(debugeePID, out ppHandleArrayOut, out ppStringArrayOut, out pdwArrayLengthOut);

        public HResult CloseCLREnumeration(
            void* ppHandleArrayOut,
            void* ppStringArrayOut,
            int pdwArrayLengthOut)
            => _closeClrEnumeration(ppHandleArrayOut, ppStringArrayOut, pdwArrayLengthOut);

        public HResult CreateVersionStringFromModule(
            int processId,
            [MarshalAs(UnmanagedType.LPWStr)] string moduleName,
            char* versionString,
            int versionStringLength,
            out int actualVersionStringLength)
            => _createVersionStringFromModule(processId, moduleName, versionString, versionStringLength, out actualVersionStringLength);
        
        public HResult CreateDebuggingInterfaceFromVersion2(
            int debuggerVersion,
            [MarshalAs(UnmanagedType.LPWStr)] string versionString,
            [MarshalAs(UnmanagedType.LPWStr)] string? applicationGroupId,
            out nint cordbg)
            => _createDebuggingInterfaceFromVersion2(debuggerVersion, versionString, applicationGroupId, out cordbg);

        public static DbgShim Create(string path)
        {
            var lib = NativeLibrary.Load(path);
            var enumerateClrs = GetFunctionPointer<EnumerateCLRsDelegate>(lib, "EnumerateCLRs");
            var closeClrEnumeration = GetFunctionPointer<CloseCLREnumerationDelegate>(lib, "CloseCLREnumeration");
            var createVersionStringFromModule =
                GetFunctionPointer<CreateVersionStringFromModuleDelegate>(lib, "CreateVersionStringFromModule");
            var createDebuggingInterfaceFromVersion2 =
                GetFunctionPointer<CreateDebuggingInterfaceFromVersion2Delegate>(lib, "CreateDebuggingInterfaceFromVersion2");

            return new DbgShim(
                enumerateClrs,
                closeClrEnumeration, 
                createVersionStringFromModule,
                createDebuggingInterfaceFromVersion2);
        }

        static T GetFunctionPointer<T>(nint lib, string entryPoint)
            where T : Delegate
        {
            var ptr = NativeLibrary.GetExport(lib, entryPoint);
            return Marshal.GetDelegateForFunctionPointer<T>(ptr);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate HResult EnumerateCLRsDelegate(
            int debugeePID,
            out void* ppHandleArrayOut,
            out void* ppStringArrayOut,
            out int pdwArrayLengthOut);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate HResult CloseCLREnumerationDelegate(
            void* ppHandleArrayOut,
            void* ppStringArrayOut,
            int pdwArrayLengthOut);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate HResult CreateVersionStringFromModuleDelegate(
            int processId,
            [MarshalAs(UnmanagedType.LPWStr)] string moduleName,
            char* versionString,
            int versionStringLength,
            out int actualVersionStringLength);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate HResult CreateDebuggingInterfaceFromVersion2Delegate(
            int debuggerVersion,
            [MarshalAs(UnmanagedType.LPWStr)] string versionString,
            [MarshalAs(UnmanagedType.LPWStr)] string? applicationGroupId,
            out nint cordbg);
    }
}