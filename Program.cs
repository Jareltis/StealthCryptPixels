using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Metadata;
using SixLabors.ImageSharp.Formats.Png;
using Konscious.Security.Cryptography;

namespace StealthCryptPixel
{
    class Program
    {

        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("=== StealthCryptPixel V4 ===\n");
            Console.ResetColor();

            if (args.Length == 0) { PrintHelp(); return; }
            if (args.Length < 2 && args[0] != "-t5") { PrintHelp(); return; }

            var sw = Stopwatch.StartNew();
            string mode = args[0];
            byte[]? password = null;

            try
            {
                if (mode == "-c" || mode == "-c5")
                {
                    string inputFile = args[1];
                    List<string> donorImages;

                    if (File.Exists(args[2]) && ImageIo.IsImageFile(args[2]))
                    {
                        password = PasswordPrompt.PromptPassword(confirm: true);
                        donorImages = args.Skip(2).ToList();
                    }
                    else
                    {
                        password = Encoding.UTF8.GetBytes(args[2]);
                        donorImages = args.Skip(3).ToList();
                    }

                    ValidateInputs(inputFile, donorImages);
                    if (mode == "-c5") AdaptiveV5.EncryptV5(inputFile, donorImages, password);
                    else ShardedV4.EncryptSharded(inputFile, donorImages, password);
                }
                else if (mode == "-d" || mode == "-d5")
                {
                    string lastArg = args[args.Length - 1];
                    List<string> stegoImages;

                    if (File.Exists(lastArg) && ImageIo.IsImageFile(lastArg))
                    {
                        stegoImages = args.Skip(1).ToList();
                        password = PasswordPrompt.PromptPassword();
                    }
                    else
                    {
                        password = Encoding.UTF8.GetBytes(lastArg);
                        stegoImages = args.Skip(1).Take(args.Length - 2).ToList();
                    }

                    if (mode == "-d5") AdaptiveV5.DecryptV5(stegoImages, password);
                    else ShardedV4.DecryptSharded(stegoImages, password);
                }
                else if (mode == "-t5") AdaptiveV5.SelfTest();
                else PrintHelp();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[X] ОШИБКА: {ex.Message}");
                Console.ResetColor();
            }
            finally
            {
                if (password != null) Array.Clear(password, 0, password.Length);
                sw.Stop();
                Console.WriteLine($"\nВремя выполнения: {sw.Elapsed.TotalSeconds:F2} сек.");
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("Использование:");
            Console.WriteLine("  Шифровать (V4):   -c  <файл> [пароль] <img1> [img2] ...");
            Console.WriteLine("  Дешифровать (V4): -d  <stego1> [stego2] ... [пароль]");
            Console.WriteLine("  Шифровать (V5 адаптивный, против ML): -c5 <файл> [пароль] <img1> ...");
            Console.WriteLine("  Дешифровать (V5): -d5 <stego1> ... [пароль]");
            Console.WriteLine("  Self-test V5:     -t5");
            Console.WriteLine();
            Console.WriteLine("  V4 — прячет размер payload (хорош против простых тулз).");
            Console.WriteLine("  V5 — стойкость к ML-стегоанализу, НО ёмкость ниже и размер payload не скрывается.");
        }

        static void ValidateInputs(string inputFile, List<string> images)
        {
            if (!File.Exists(inputFile)) throw new Exception($"Файл не найден: {inputFile}");
            if (images.Count == 0) throw new Exception("Не указаны картинки.");
            foreach (var img in images)
            {
                if (!File.Exists(img)) throw new Exception($"Картинка не найдена: {img}");
                try { var info = Image.Identify(img); if (info == null) throw new Exception(); }
                catch { throw new Exception($"Файл поврежден или не картинка: {img}"); }
            }
        }

    }
}