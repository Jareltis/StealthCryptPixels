using System;
using System.Text;
using System.Security.Cryptography;

namespace StealthCryptPixel
{
    // Консольный ввод пароля со звёздочками + подтверждение.
    // Перенесено из Program.cs без изменения логики.
    internal static class PasswordPrompt
    {
        public static byte[] PromptPassword(bool confirm = false)
        {
            byte[] pass = ReadHidden("Введите пароль (скрыто): ");
            if (pass.Length == 0) throw new Exception("Пароль пуст.");
            if (confirm)
            {
                byte[] pass2 = ReadHidden("Повторите пароль (скрыто): ");
                bool same = CryptographicOperations.FixedTimeEquals(pass, pass2);
                Array.Clear(pass2, 0, pass2.Length);
                if (!same)
                {
                    Array.Clear(pass, 0, pass.Length);
                    throw new Exception("Пароли не совпадают.");
                }
            }
            return pass;
        }

        private static byte[] ReadHidden(string prompt)
        {
            Console.Write(prompt);
            char[] buf = new char[64];
            int len = 0;
            do
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    if (len == buf.Length)
                    {
                        char[] bigger = new char[buf.Length * 2];
                        Array.Copy(buf, bigger, len);
                        Array.Clear(buf, 0, buf.Length);
                        buf = bigger;
                    }
                    buf[len++] = key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && len > 0)
                {
                    buf[--len] = '\0';
                    Console.Write("\b \b");
                }
                else if (key.Key == ConsoleKey.Enter) break;
            } while (true);
            Console.WriteLine();
            byte[] pw = Encoding.UTF8.GetBytes(buf, 0, len);
            Array.Clear(buf, 0, buf.Length);
            return pw;
        }
    }
}
