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
            
            Process.GetProcesses().ToList().ForEach(process =>
            {
                try
                {
                    MapDetector.ScanForAnomalies(process, MapDetector.SCAN_MODE.DEEP);
                }
                catch
                {
            
                }
            });

            Log.LogInfo($"Finished scanning - {stopWatch.ElapsedMilliseconds}ms");

            Console.ReadLine();
        }
    }
}
