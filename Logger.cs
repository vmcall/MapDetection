using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MapDetection
{
    public static class Log
    {
        public static void LogGeneral(string general, int padCount = 0)
        {
            var oldColor = SetConsoleColor(ConsoleColor.DarkGreen);

            for (int i = 0; i < padCount; i++)
                Console.Write("  ");

            Console.WriteLine($"[+] {general}");
            SetConsoleColor(oldColor);
        }

        public static void LogInfo(string information, int padCount = 0)
        {
            var oldColor = SetConsoleColor(ConsoleColor.DarkCyan);

            for (int i = 0; i < padCount; i++)
                Console.Write("  ");

            Console.WriteLine($"[?] {information}");
            SetConsoleColor(oldColor);
        }

        public static void LogVariable<T>(string variableName, T variable, int padCount = 0)
        {
            var oldColor = SetConsoleColor(ConsoleColor.DarkCyan);

            for (int i = 0; i < padCount; i++)
                Console.Write("  ");

            Console.WriteLine($"[?] {variableName} - {variable}");
            SetConsoleColor(oldColor);
        }

        public static void LogWarning(string error, int padCount = 0)
        {
            var oldColor = SetConsoleColor(ConsoleColor.DarkYellow);

            for (int i = 0; i < padCount; i++)
                Console.Write("  ");

            Console.WriteLine($"[!] {error}");
            SetConsoleColor(oldColor);
        }

        public static void LogError(string error, int padCount = 0)
        {
            var oldColor = SetConsoleColor(ConsoleColor.DarkRed);

            for (int i = 0; i < padCount; i++)
                Console.Write("  ");

            Console.WriteLine($"[!!] {error}");
            SetConsoleColor(oldColor);
        }

        private static ConsoleColor SetConsoleColor(ConsoleColor newColor)
        {
            var oldColor = Console.ForegroundColor;
            Console.ForegroundColor = newColor;
            return oldColor;
        }

        public static void ShowWarning(string message, string title) =>
            MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);

        public static void ShowInformation(string message, string title) =>
            MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Information);

        public static void ShowError(string message, string title) =>
           MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
