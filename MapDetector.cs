using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace MapDetection
{
    public static unsafe class MapDetector
    {
        enum PE_SECTION_INFO
        {
            Valid,
            InvalidHeader,
            UnlinkedModule,
            InvalidSectionType
        };

        public enum SCAN_MODE
        {
            QUICK,
            DEEP
        };

        static List<NT.ModuleInfo> g_linkedModules = null;
        public static void ScanForAnomalies(Process targetProcess, SCAN_MODE mode)
        {
            Log.LogGeneral($"Scanning {targetProcess.ProcessName}/{targetProcess.Id}");

            var scanList = new List<NT.MEMORY_BASIC_INFORMATION>();

            foreach (ProcessThread thread in targetProcess.Threads)
            {
                var startAddress = thread.GetRealStartAddress();
                var query = targetProcess.VirtualQuery(startAddress);

                if (query.AllocationBase > 0 && !scanList.Exists(x => x.AllocationBase == query.AllocationBase))
                    scanList.Add(query);

                // GET THREAD INSTRUCTION POINTERS 
                // TO PREVENT BYPASSING BY UNMAPPING
                // ALLOCATION BASE AFTER JUMPING TO 
                // SOMEWHERE ELSE
                var instructionPointer = thread.GetInstructionPointer(targetProcess.IsWow64());
                var threadQuery = targetProcess.VirtualQuery(instructionPointer);

                if (threadQuery.AllocationBase > 0 && !scanList.Exists(x => x.AllocationBase == threadQuery.AllocationBase))
                    scanList.Add(threadQuery);

            }

            // GET ALL MODULES VIA EnumProcessModulesEx
            g_linkedModules = targetProcess.GetModules();

            Log.LogInfo($"Finished iterating threads - Scanning {scanList.Count} address(es)", 1);
            scanList.ForEach(scanData =>
            {
                var result = ValidateImage(targetProcess, scanData);

                if (result != PE_SECTION_INFO.Valid)
                    Log.LogWarning($"{scanData.AllocationBase.ToString("x2")} -> {result}", 2);

            });

            // DO A DEEPER SCAN BY WALKING THE VIRTUAL ADDRESSES, LOOKING FOR 
            // INDEPENDENT EXECUTABLE VIRTUAL PAGES
            if (mode == SCAN_MODE.DEEP)
            {
                var query = new NT.MEMORY_BASIC_INFORMATION();

                do
                {
                    query = targetProcess.VirtualQuery(query.BaseAddress + query.RegionSize);

                    if (query.State == NT.PAGE_STATE.MEM_FREE)
                        continue;

                    if (query.AllocationProtect != NT.MemoryProtection.ExecuteReadWrite &&
                        query.AllocationProtect != NT.MemoryProtection.ExecuteWriteCopy)
                        continue;
                    
                    // TEST IF ADDRESS IS WITHIN ANY LINKED MODULE
                    if (!g_linkedModules.Any(module => IsAddressInsideModule(module, query.AllocationBase)))
                        Log.LogWarning($"{query.BaseAddress.ToString("x2")} - {query.AllocationProtect}", 2);

                } while (query.RegionSize > 0);
            }

            bool IsAddressInsideModule(NT.ModuleInfo module, ulong address) =>
                module.ModuleHandle <= address && (module.ModuleHandle + module.ModuleSize) > address;
        }

        /// <summary>
        /// Validate if mapped image is legitimate
        /// </summary>
        /// <param name="targetProcess">Target process</param>
        /// <param name="data">VirtualQuery data</param>
        /// <returns></returns>
        private static PE_SECTION_INFO ValidateImage(Process targetProcess, NT.MEMORY_BASIC_INFORMATION data)
        {
            if (!g_linkedModules.Exists(module => module.ModuleHandle == data.AllocationBase))
                return PE_SECTION_INFO.UnlinkedModule;

            byte[] sectionData = targetProcess.ReadMemory(data.AllocationBase, data.RegionSize);

            if (!ValidateHeaders(sectionData))
                return PE_SECTION_INFO.InvalidHeader;

            // I TESTED THIS ON EVERY RUNNING PROCESS ON MY SYSTEM AND
            // NOT A SINGLE PROCESS HAD AN IMAGE LOADED THAT WERE HAD DIFFERENT
            // ALLOCATION FLAGS, MIGHT CAUSE FALSE POSITIVES SO BE AWARE
            bool validAllocationFlags = data.AllocationProtect == NT.MemoryProtection.ExecuteWriteCopy || data.AllocationProtect == NT.MemoryProtection.ReadOnly;
            if (data.Type != NT.PAGE_TYPE.MEM_IMAGE || !validAllocationFlags)
                return PE_SECTION_INFO.InvalidSectionType;

            return PE_SECTION_INFO.Valid;
        }

        /// <summary>
        /// Validate if PE headers are legitimate and not tampered with
        /// </summary>
        /// <param name="sectionData">Data read from beginning of allocation</param>
        /// <returns></returns>
        private static bool ValidateHeaders(byte[] sectionData)
        {
            // CHECK FOR INVALID SIGNATURE 'MZ'
            if (sectionData[0] != 0x4D || sectionData[1] != 0x5A)
                return false;

            NT.IMAGE_DOS_HEADER* dosHeader;
            NT.IMAGE_NT_HEADERS* ntHeader;
            NT.IMAGE_FILE_HEADER fileHeader;
            NT.IMAGE_OPTIONAL_HEADER64 optionalHeader;

            // GET HEADERS
            fixed (byte* dataPointer = &sectionData[0])
            {
                dosHeader = (NT.IMAGE_DOS_HEADER*)dataPointer;
                ntHeader = (NT.IMAGE_NT_HEADERS*)(dataPointer + dosHeader->e_lfanew);
                fileHeader = ntHeader->FileHeader;
                optionalHeader = ntHeader->OptionalHeader;
            }

            // CHECK IF HEADERS ARE VALID
            if (ntHeader->Signature != 0x4550/*PE*/)
                return false;

            if (optionalHeader.Magic != NT.MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                optionalHeader.Magic != NT.MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return false;

            return true;
        }
    }
}
