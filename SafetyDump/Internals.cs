using System;
using System.Runtime.InteropServices;

namespace SafetyDump
{
    public static class Internals
    {
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        internal static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType,
            IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct MINIDUMP_IO_CALLBACK
        {
            internal IntPtr Handle;
            internal ulong Offset;
            internal IntPtr Buffer;
            internal int BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct MINIDUMP_CALLBACK_INFORMATION
        {
            internal MinidumpCallbackRoutine CallbackRoutine;
            internal IntPtr CallbackParam;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct MINIDUMP_CALLBACK_INPUT
        {
            internal int ProcessId;
            internal IntPtr ProcessHandle;
            internal MINIDUMP_CALLBACK_TYPE CallbackType;
            internal MINIDUMP_IO_CALLBACK Io;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate bool MinidumpCallbackRoutine(IntPtr CallbackParam, IntPtr CallbackInput,
            IntPtr CallbackOutput);

        internal enum HRESULT : uint
        {
            S_FALSE = 0x0001,
            S_OK = 0x0000,
            E_INVALIDARG = 0x80070057,
            E_OUTOFMEMORY = 0x8007000E
        }

        internal struct MINIDUMP_CALLBACK_OUTPUT
        {
            internal HRESULT status;
        }

        internal enum MINIDUMP_CALLBACK_TYPE
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }
    }
}