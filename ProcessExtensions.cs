using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MapDetection
{
    // THIS CLASS IS A WRAPPER FOR THE MANAGED PROCESS/PROCESSTHREAD CLASS
    public unsafe static class WhatMicrosoftShouldHaveDone
    {
        #region Information
        public static bool IsWow64(this Process process)
        {
            if (!NT.IsWow64Process(process.Handle, out bool wow64Process))
                throw new Exception($"IsWow64 - IsWow64Process() failed - {Marshal.GetLastWin32Error().ToString("x2")}");
            
            return wow64Process;
        }
        #endregion

        #region Memory
        public static NT.MEMORY_BASIC_INFORMATION VirtualQuery(this Process process, ulong memoryPointer)
        {
            var structSize = (uint)Marshal.SizeOf(typeof(NT.MEMORY_BASIC_INFORMATION));
            NT.VirtualQueryEx(process.Handle, memoryPointer, out NT.MEMORY_BASIC_INFORMATION mem, structSize);
            return mem;
        }
        public static byte[] ReadMemory(this Process process, ulong memoryPointer, ulong size)
        {
            byte[] buffer = new byte[size];

            if (!NT.ReadProcessMemory(process.Handle, memoryPointer, buffer, buffer.Length, 0))
                throw new Exception($"ReadMemory - ReadProcessMemory() failed - {Marshal.GetLastWin32Error().ToString("x2")}");

            return buffer;
        }
        #endregion
        
        #region Modules
        
        public static List<NT.ModuleInfo> GetModules(this Process process)
        {
            List<NT.ModuleInfo> modules = new List<NT.ModuleInfo>();

            ulong[] moduleHandleArray = new ulong[1000];

            fixed (ulong* hMods = moduleHandleArray)
            {
                if (NT.EnumProcessModulesEx(process.Handle, (ulong)hMods, sizeof(ulong) * 1000, out uint cbNeeded, 0x3) > 0)
                {
                    for (int moduleIndex = 0; moduleIndex < cbNeeded / sizeof(ulong); moduleIndex++)
                    {
                        NT.GetModuleInformation(process.Handle, (IntPtr)moduleHandleArray[moduleIndex], out NT.MODULEINFO modinfo, (uint)Marshal.SizeOf<NT.MODULEINFO>());

                        modules.Add(new NT.ModuleInfo()
                        {
                            ModuleHandle = moduleHandleArray[moduleIndex],
                            ModuleSize = modinfo.SizeOfImage
                        });
                    }
                }
            }

            return modules;

        }
        #endregion

        #region Threads
        public static ulong GetNativeHandle(this ProcessThread thread, NT.ThreadAccess accessRights) => NT.OpenThread(accessRights, false, thread.Id);

        public static ulong GetRealStartAddress(this ProcessThread thread)
        {
            var handle = thread.GetNativeHandle(NT.ThreadAccess.QUERY_INFORMATION);

            ulong startAddress = 0;
            NT.NtQueryInformationThread((IntPtr)handle, NT.ThreadInfoClass.ThreadQuerySetWin32StartAddress, new IntPtr(&startAddress), 8, IntPtr.Zero);

            NT.CloseHandle(handle);

            return startAddress;
        }

        public static ulong GetInstructionPointer(this ProcessThread thread, bool wow64Process)
        {
            var threadHandle = thread.GetNativeHandle(NT.ThreadAccess.GET_CONTEXT);

            ulong instructionPointer = 0;

            if (wow64Process)
            {
                NT.CONTEXT ctx = new NT.CONTEXT() { ContextFlags = NT.CONTEXT_FLAGS.CONTEXT_CONTROL };
                NT.GetThreadContext(threadHandle, ref ctx);
                instructionPointer = ctx.Eip;
            }
            else
            {
                NT.CONTEXT64 ctx = new NT.CONTEXT64() { ContextFlags = NT.CONTEXT_FLAGS.CONTEXT_CONTROL };
                NT.GetThreadContext(threadHandle, ref ctx);
                instructionPointer = ctx.Rip;
            }

            NT.CloseHandle(threadHandle);
            return instructionPointer;

        }
        #endregion
    }
}
