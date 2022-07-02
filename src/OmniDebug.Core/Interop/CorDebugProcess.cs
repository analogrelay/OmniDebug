using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using Microsoft.Diagnostics.Runtime;
using Microsoft.Diagnostics.Runtime.Utilities;

namespace OmniDebug.Interop;

internal unsafe class CorDebugProcess : CorDebugController
{
    private static readonly Guid IID = new Guid("3d6f5f64-7538-11d3-8d5b-00104b35e7ef");

    private ref readonly CorDebugProcessVTable VTable => ref Unsafe.AsRef<CorDebugProcessVTable>(ChildVtablePointer);

    public static CorDebugProcess? Create(nint punk) => punk != 0 ? new CorDebugProcess(punk) : null;

    CorDebugProcess(nint punk) : base(new RefCountedFreeLibrary(0), IID, punk)
    {
        SuppressRelease();
    }

    /// <summary>
    /// Gets the operating system (OS) ID of the process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-getid-method"/>
    /// </summary>
    /// <returns>The unique ID of the process.</returns>
    public int GetID()
    {
        var hr = VTable.GetID(Self, out var pid);
        Marshal.ThrowExceptionForHR(hr);
        return pid;
    }
    
    /// <summary>
    /// Gets a handle to the process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-gethandle-method"/>
    /// </summary>
    /// <returns>A pointer to an HPROCESS that is the handle to the process.</returns>
    public nint GetHandle()
    {
        var hr = VTable.GetHandle(Self, ut var handle);
        Marshal.ThrowExceptionForHR(hr);
        return handle;
    }

    /// <summary>
    /// Gets this process's thread that has the specified operating system (OS) thread ID.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-getthread-method"/>
    /// </summary>
    /// <param name="threadId">The OS thread ID of the thread to be retrieved.</param>
    /// <returns>A pointer to the address of an ICorDebugThread object that represents the thread.</returns>
    public nint GetThread(int threadId)
    {
        var hr = VTable.GetThread(Self, threadId, out var thread);
        Marshal.ThrowExceptionForHR(hr);
        return thread;
    }
    
    // EnumerateObjects has not been implemented: 
    // https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-enumerateobjects-method
    
    /// <summary>
    /// Gets a value that indicates whether an address is inside a stub that will cause a transition to managed code.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-istransitionstub-method" />
    /// </summary>
    /// <param name="address">The address in question.</param>
    /// <returns><c>true</c> if the specified address is inside a stub that will cause a transition to managed code; otherwise <c>false</c>.</returns>
    public bool IsTransitionStub(ulong address)
    {
        var hr = VTable.IsTransitionStub(Self, address, out var isStub);
        Marshal.ThrowExceptionForHR(hr);
        return isStub;
    }

    /// <summary>
    /// Gets a value that indicates whether the specified thread has been suspended as a result of the debugger stopping this process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-isossuspended-method" />
    /// </summary>
    /// <param name="threadId">The ID of thread in question.</param>
    /// <returns><c>true</c> if the specified thread has been suspended; otherwise <c>false</c>.</returns>
    public bool IsOSSuspended(int threadId)
    {
        var hr = VTable.IsOSSuspended(Self, threadId, out var isSuspended);
        Marshal.ThrowExceptionForHR(hr);
        return isSuspended;
    }
    
    /// <summary>
    /// Gets the context for the given thread in this process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-getthreadcontext-method" />
    /// </summary>
    /// <param name="threadId">The ID of the thread for which to retrieve the context.</param>
    /// <param name="context">
    /// An array of bytes that describe the thread's context.
    /// The context specifies the architecture of the processor on which the thread is executing.
    /// On Windows platforms, this is a CONTEXT structure and should be initialized before calling the function.
    /// </param>
    public void GetThreadContext(int threadId, Span<byte> context)
    {
        fixed(byte* contextPtr = context)
        {
            var hr = VTable.GetThreadContext(Self, threadId, (uint)context.Length, contextPtr);
            Marshal.ThrowExceptionForHR(hr);
        }
    }
    
    /// <summary>
    /// Sets the context for the given thread in this process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-setthreadcontext-method" />
    /// </summary>
    /// <param name="threadId">The ID of the thread for which to retrieve the context.</param>
    /// <param name="context">
    /// An array of bytes that describe the thread's context.
    /// The context specifies the architecture of the processor on which the thread is executing.
    /// On Windows platforms, this is a CONTEXT structure and should be initialized before calling the function.
    /// </param>
    public void SetThreadContext(int threadId, Span<byte> context)
    {
        fixed(byte* contextPtr = context)
        {
            var hr = VTable.SetThreadContext(Self, threadId, (uint)context.Length, contextPtr);
            Marshal.ThrowExceptionForHR(hr);
        }
    }

    /// <summary>
    /// Reads a specified area of memory for this process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-readmemory-method" />
    /// </summary>
    /// <param name="address">The base address of the memory to be read.</param>
    /// <param name="buffer">A buffer that receives the contents of the memory.</param>
    /// <returns>The number of bytes transferred into the specified buffer.</returns>
    public int ReadMemory(ulong address, Span<byte> buffer)
    {
        fixed (byte* bufferPtr = buffer)
        {
            var hr = VTable.ReadMemory(Self, address, buffer.Length, bufferPtr, out var bytesWritten);
            Marshal.ThrowExceptionForHR(hr);
            return bytesWritten;
        }
    }

    /// <summary>
    /// Writes data to an area of memory in this process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-writememory-method" />
    /// </summary>
    /// <param name="address">
    /// The base address of the memory area to which data is written.
    /// Before data transfer occurs, the system verifies that the memory area of the specified size, beginning at the base address, is accessible for writing.
    /// If it is not accessible, the method fails.
    /// </param>
    /// <param name="buffer">A buffer that contains data to be written.</param>
    /// <returns>The number of bytes written to the memory area.</returns>
    public int WriteMemory(ulong address, ReadOnlySpan<byte> buffer)
    {
        fixed (byte* bufferPtr = buffer)
        {
            var hr = VTable.WriteMemory(Self, address, buffer.Length, bufferPtr, out var bytesWritten);
            Marshal.ThrowExceptionForHR(hr);
            return bytesWritten;
        }
    }

    /// <summary>
    /// Clears the current unmanaged exception on the given thread.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-clearcurrentexception-method" />
    /// </summary>
    /// <param name="threadId">The ID of the thread on which the current unmanaged exception will be cleared.</param>
    public void ClearCurrentException(int threadId)
    {
        var hr = VTable.ClearCurrentException(Self, threadId);
        Marshal.ThrowExceptionForHR(hr);
    }

    /// <summary>
    /// Enables and disables the transmission of log messages to the debugger.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-enablelogmessages-method" />
    /// </summary>
    /// <param name="onOff"><c>true</c> enables the transmission of log messages; <c>false</c> disables the transmission.</param>
    public void EnableLogMessages(bool onOff)
    {
        var hr = VTable.EnableLogMessages(Self, onOff);
        Marshal.ThrowExceptionForHR(hr);
    }
    
    /// <summary>
    /// Sets the severity level of the specified log switch.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-modifylogswitch-method" />
    /// </summary>
    /// <param name="logSwitchName">A string that specifies the name of the log switch.</param>
    /// <param name="level">The severity level to be set for the specified log switch.</param>
    public void ModifyLogSwitch(string logSwitchName, int level)
    {
        fixed(char* logSwitchNamePtr = logSwitchName)
        {
            var hr = VTable.ModifyLogSwitch(Self, logSwitchNamePtr, level);
            Marshal.ThrowExceptionForHR(hr);
        }
    }

    /// <summary>
    /// Enumerates all the application domains in this process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-enumerateappdomains-method" />
    /// </summary>
    /// <returns>A pointer to the address of an ICorDebugAppDomainEnum that is an enumerator for the application domains in this process.</returns>
    public nint EnumerateAppDomains()
    {
        var hr = VTable.EnumerateAppDomains(Self, out var appDomainEnum);
        Marshal.ThrowExceptionForHR(hr);
        return appDomainEnum;
    }
    
    // GetObject has not been implemented yet.
    // https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-getobject-method

    // ThreadForFiberCookie has not been implemented yet.
    // https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-threadforfibercookie-method

    /// <summary>
    /// Gets the operating system (OS) thread ID of the debugger's internal helper thread.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugprocess-gethelperthreadid-method" />
    /// </summary>
    /// <returns>The OS thread ID of the debugger's internal helper thread.</returns>
    public int GetHelperThreadId()
    {
        var hr = VTable.GetHelperThreadID(Self, out var helperThreadId);
        Marshal.ThrowExceptionForHR(hr);
        return helperThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly unsafe struct CorDebugProcessVTable
    {
        public readonly delegate* unmanaged[Stdcall]<nint, out int, HResult> GetID;
        public readonly delegate* unmanaged[Stdcall]<nint, out nint, HResult> GetHandle;
        public readonly delegate* unmanaged[Stdcall]<nint, int, out IntPtr, HResult> GetThread;
        public readonly delegate* unmanaged[Stdcall]<nint, out nint, HResult> EnumerateObjects;
        public readonly delegate* unmanaged[Stdcall]<nint, ulong, out bool, HResult> IsTransitionStub;
        public readonly delegate* unmanaged[Stdcall]<nint, int, out bool, HResult> IsOSSuspended;
        public readonly delegate* unmanaged[Stdcall]<nint, int, uint, byte*, HResult> GetThreadContext;
        public readonly delegate* unmanaged[Stdcall]<nint, int, uint, byte*, HResult> SetThreadContext;
        public readonly delegate* unmanaged[Stdcall]<nint, ulong, int, byte*, out int, HResult> ReadMemory;
        public readonly delegate* unmanaged[Stdcall]<nint, ulong, int, byte*, out int, HResult> WriteMemory;
        public readonly delegate* unmanaged[Stdcall]<nint, int, HResult> ClearCurrentException;
        public readonly delegate* unmanaged[Stdcall]<nint, bool, HResult> EnableLogMessages;
        public readonly delegate* unmanaged[Stdcall]<nint, char*, int, HResult> ModifyLogSwitch;
        public readonly delegate* unmanaged[Stdcall]<nint, out nint, HResult> EnumerateAppDomains;
        public readonly delegate* unmanaged[Stdcall]<nint, out nint, HResult> GetObject;
        public readonly delegate* unmanaged[Stdcall]<nint, int, out nint, HResult> ThreadForFiberCookie;
        public readonly delegate* unmanaged[Stdcall]<nint, out int, HResult> GetHelperThreadID;
    }
}