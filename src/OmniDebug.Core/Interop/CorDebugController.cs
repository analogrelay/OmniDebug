using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using Microsoft.Diagnostics.Runtime;
using Microsoft.Diagnostics.Runtime.Utilities;

namespace OmniDebug.Interop;

internal abstract unsafe class CorDebugController : CallableCOMWrapper
{
    ref readonly CorDebugControllerVTable VTable => ref Unsafe.AsRef<CorDebugControllerVTable>(_vtable);
    protected void* ChildVtablePointer => (CorDebugControllerVTable*)_vtable + 1;
    
    protected CorDebugController(RefCountedFreeLibrary? library, in Guid desiredInterface, nint pUnknown) : base(library, in desiredInterface, pUnknown)
    {
    }

    /// <summary>
    /// Performs a cooperative stop on all threads that are running managed code in the process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-stop-method"/>
    /// </summary>
    public void Stop()
    {
        // > The dwTimeoutIgnored value is currently ignored and treated as INFINITE (-1).
        // https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-stop-method
        var hr = VTable.Stop(Self, -1);
        Marshal.ThrowExceptionForHR(hr);
    }

    /// <summary>
    /// Resumes execution of managed threads after a call to <see cref="Stop"/>.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-continue-method" />
    /// </summary>
    /// <param name="isOutOfBand">Set to <c>true</c> if continuing from an out-of-band event; otherwise, set to <c>false</c></param>
    public void Continue(bool isOutOfBand)
    {
        var hr = VTable.Continue(Self, isOutOfBand);
        Marshal.ThrowExceptionForHR(hr);
    }

    /// <summary>
    /// Gets a value that indicates whether the threads in the process are currently running freely.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-isrunning-method" />
    /// </summary>
    /// <returns><c>true</c> if the threads in the process are running freely; otherwise, <c>false</c>.</returns>
    public bool IsRunning()
    {
        var hr = VTable.IsRunning(Self, out var running);
        Marshal.ThrowExceptionForHR(hr);
        return running;
    }

    /// <summary>
    /// Gets a value that indicates whether any managed callbacks are currently queued for the specified thread.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-hasqueuedcallbacks-method" />
    /// </summary>
    /// <param name="thread">A pointer to an "ICorDebugThread" object that represents the thread.</param>
    /// <returns><c>true</c> if any managed callbacks are currently queued for the specified thread; otherwise, <c>false</c>.</returns>
    // TODO: Replace nint with CorDebugThread instance.
    public bool HasQueuedCallbacks(nint thread)
    {
        var hr = VTable.HasQueuedCallbacks(Self, thread, out var queued);
        Marshal.ThrowExceptionForHR(hr);
        return queued;
    }

    /// <summary>
    /// Gets an enumerator for the active managed threads in the process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-enumeratethreads-method" />
    /// </summary>
    /// <returns>A pointer to the address of an "ICorDebugThreadEnum" object that represents an enumerator for all managed threads that are active in the process.</returns>
    public nint EnumerateThreads()
    {
        var hr = VTable.EnumerateThreads(Self, out var enumerator);
        Marshal.ThrowExceptionForHR(hr);
        return enumerator;
    }

    /// <summary>
    /// Sets the debug state of all managed threads in the process.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-setallthreadsdebugstate-method" />
    /// </summary>
    /// <param name="state">A value of the <see cref="CorDebugThreadState"/> enumeration that specifies the state of the thread for debugging.</param>
    /// <param name="exceptThisThread">A pointer to an "ICorDebugThread" object that represents a thread to be exempted from the debug state setting. If this value is <see cref="nint.Zero"/>, no thread is exempted.</param>
    public void SetAllThreadsDebugState(CorDebugThreadState state, nint exceptThisThread)
    {
        var hr = VTable.SetAllThreadsDebugState(Self, state, exceptThisThread);
        Marshal.ThrowExceptionForHR(hr);
    }

    /// <summary>
    /// Detaches the debugger from the process or application domain.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-detach-method" />
    /// </summary>
    public void Detach()
    {
        var hr = VTable.Detach(Self);
        Marshal.ThrowExceptionForHR(hr);
    }

    /// <summary>
    /// Detaches the debugger from the process or application domain.
    /// <seealso href="https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/debugging/icordebugcontroller-terminate-method" />
    /// </summary>
    /// <param name="exitCode">A numeric value that is the exit code. The valid numeric values are defined in Winbase.h.</param>
    public void Terminate(uint exitCode)
    {
        var hr = VTable.Terminate(Self, exitCode);
        Marshal.ThrowExceptionForHR(hr);
    }
    
    // CanCommitChanges and CommitChanges are not implemented as they are obsolete.
    
    [StructLayout(LayoutKind.Sequential)]
    internal readonly unsafe struct CorDebugControllerVTable
    {
        public readonly delegate* unmanaged[Stdcall]<nint, int, HResult> Stop;
        public readonly delegate* unmanaged[Stdcall]<nint, bool, HResult> Continue;
        public readonly delegate* unmanaged[Stdcall]<nint, out bool, HResult> IsRunning;
        public readonly delegate* unmanaged[Stdcall]<nint, nint, out bool, HResult> HasQueuedCallbacks;
        public readonly delegate* unmanaged[Stdcall]<nint, out nint, HResult> EnumerateThreads;
        public readonly delegate* unmanaged[Stdcall]<nint, CorDebugThreadState, nint, HResult> SetAllThreadsDebugState;
        public readonly delegate* unmanaged[Stdcall]<nint, HResult> Detach;
        public readonly delegate* unmanaged[Stdcall]<nint, uint, HResult> Terminate;
        
        // CanCommitChanges and CommitChanges are not implemented as they are obsolete.
        // But they are still in the VTable, so we need to define them.
        public readonly delegate* unmanaged[Stdcall]<uint, nint[], out nint, HResult> CanCommitChanges;
        public readonly delegate* unmanaged[Stdcall]<uint, nint[], out nint, HResult> CommitChanges;
    }
}