using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MapDetection
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            Process.EnterDebugMode();
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    MapDetector.ScanForAnomalies(process);
                }
                catch (Exception e)
                {
                    // Log Error?
                }
            }

            Log.LogInfo($"Finished scanning all processes - {stopWatch.ElapsedMilliseconds}ms");

            Console.ReadLine();
        }
    }
}
