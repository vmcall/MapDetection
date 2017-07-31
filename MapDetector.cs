using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace MapDetection
{
    public static unsafe class MapDetector
    {
        static List<ulong> g_linkedModules = null;
        public static void ScanForAnomalies(Process targetProcess)
        {
            Log.LogGeneral($"Scanning {targetProcess.ProcessName}/{targetProcess.Id}");
            
            var scanList = new List<NT.MEMORY_BASIC_INFORMATION>();

            foreach (ProcessThread thread in targetProcess.Threads)
            {
                var startAddress = thread.GetRealStartAddress();
                var query = targetProcess.VirtualQuery(startAddress);
                
                if (!scanList.Exists(x => x.AllocationBase == query.AllocationBase))
                    scanList.Add(query);
            }

            g_linkedModules = targetProcess.GetModules();

            Log.LogInfo($"Finished iterating threads - Scanning {scanList.Count} address(es)", 1);
            scanList.ForEach(scanData =>
            {
                var result = ValidateImage(targetProcess, scanData);

                if (result != PE_SECTION_INFO.Valid)
                    Log.LogWarning($"{scanData.AllocationBase.ToString("x2")} -> {result}", 2);

            });
        }

        enum PE_SECTION_INFO
        {
            Valid,
            InvalidHeader,
            UnlinkedModule
        };

        private static PE_SECTION_INFO ValidateImage(Process targetProcess, NT.MEMORY_BASIC_INFORMATION data)
        {
            byte[] sectionData = targetProcess.ReadMemory(data.AllocationBase, data.RegionSize);

            if (!ValidateHeaders(sectionData))
                return PE_SECTION_INFO.InvalidHeader;
            
            if (g_linkedModules.Where(baseAddress => baseAddress == data.AllocationBase).Count() == 0)
                return PE_SECTION_INFO.UnlinkedModule;

            return PE_SECTION_INFO.Valid;
        }

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
