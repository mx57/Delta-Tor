using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DeltaTor.Core.Util;

/// <summary>
/// Ensures all spawned child processes (Tor, Lyrebird, etc.) are bound to a Win32
/// Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so that they are
/// terminated by the operating system if DeltaTor exits, crashes, or is killed.
/// </summary>
public static class ChildProcessTracker
{
    private const uint JobObjectBasicLimitInformation = 2;
    private const uint JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob, uint JobObjectInformationClass, IntPtr lpJobInformation, uint cbJobInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static readonly IntPtr s_jobHandle;

    static ChildProcessTracker()
    {
        try
        {
            s_jobHandle = CreateJobObject(IntPtr.Zero, null);
            if (s_jobHandle == IntPtr.Zero)
            {
                AppLog.W("ChildProcessTracker", $"CreateJobObject failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            var info = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            };
            var extendedInfo = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation = info
            };

            int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr extendedInfoPtr = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(extendedInfo, extendedInfoPtr, false);
                if (!SetInformationJobObject(s_jobHandle, JobObjectExtendedLimitInformation, extendedInfoPtr, (uint)length))
                {
                    AppLog.W("ChildProcessTracker", $"SetInformationJobObject failed: {Marshal.GetLastWin32Error()}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(extendedInfoPtr);
            }
        }
        catch (Exception e)
        {
            AppLog.W("ChildProcessTracker", $"Failed to initialize JobObject: {e.Message}");
        }
    }

    public static void Track(Process process)
    {
        if (s_jobHandle != IntPtr.Zero)
        {
            try
            {
                if (!process.HasExited)
                {
                    AssignProcessToJobObject(s_jobHandle, process.Handle);
                }
            }
            catch (Exception e)
            {
                AppLog.W("ChildProcessTracker", $"Failed to assign process {process.Id} to JobObject: {e.Message}");
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryLimit;
        public UIntPtr PeakJobMemoryLimit;
    }
}
