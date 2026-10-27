using System;
using System.Collections.Generic;
using System.IO;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Metadata;
using SixLabors.ImageSharp.Formats.Png;

namespace StealthCryptPixel
{
    // Работа с изображениями и форматами доноров: проверка формата, предупреждение о JPEG,
    // LSB-matching запись бита, сохранение PNG с переносом/чисткой метаданных, timestomp.
    // Перенесено из Program.cs без изменения логики.
    internal static class ImageIo
    {
        public static bool IsImageFile(string path)
        {
            return path.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
                   path.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                   path.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase) ||
                   path.EndsWith(".bmp", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsJpeg(string path)
        {
            try
            {
                var fmt = Image.DetectFormat(path);
                return fmt != null &&
                       (fmt.Name.Equals("JPEG", StringComparison.OrdinalIgnoreCase) ||
                        fmt.DefaultMimeType.Equals("image/jpeg", StringComparison.OrdinalIgnoreCase));
            }
            catch { return false; }
        }

        public static void WarnIfLossyDonors(List<string> donorPaths)
        {
            List<string> jpeg = new List<string>();
            foreach (var p in donorPaths) if (IsJpeg(p)) jpeg.Add(Path.GetFileName(p));
            if (jpeg.Count == 0) return;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[!] ВНИМАНИЕ: JPEG-доноры: {string.Join(", ", jpeg)}");
            Console.WriteLine("    LSB не переживает JPEG, поэтому вывод ВСЕГДА PNG (stego_*.png).");
            Console.WriteLine("    Это меняет формат и расширение и сильно увеличивает размер файла");
            Console.WriteLine("    (фотография в PNG легко вырастает в 5-10 раз). Если канал ожидает");
            Console.WriteLine("    именно фото/JPEG — это демаскирует факт обработки. Для скрытности");
            Console.WriteLine("    берите lossless-донор (PNG/BMP), естественный для вашего канала.");
            Console.ResetColor();
        }

        public static byte ApplySecureLsb(byte val, int bit, byte rand)
        {
            if ((val & 1) == bit) return val;
            if (val == 0) return 1;
            if (val == 255) return 254;
            return ((rand & 1) == 1) ? (byte)(val + 1) : (byte)(val - 1);
        }

        public static void CleanMetadataAndSave(Image<Rgb24> img, string src, string dest)
        {
            bool skip = false;
            using (var orig = Image.Load(src))
            {
                bool hasMeta = (orig.Metadata.ExifProfile?.Values.Count > 0) || (orig.Metadata.XmpProfile != null);
                if (!hasMeta) { skip = true; img.Metadata.HorizontalResolution = 0; img.Metadata.VerticalResolution = 0; img.Metadata.ResolutionUnits = PixelResolutionUnit.AspectRatio; }
                else
                {
                    img.Metadata.ExifProfile = orig.Metadata.ExifProfile?.DeepClone();
                    img.Metadata.IccProfile = orig.Metadata.IccProfile?.DeepClone();
                    img.Metadata.ResolutionUnits = orig.Metadata.ResolutionUnits;
                    img.Metadata.HorizontalResolution = orig.Metadata.HorizontalResolution;
                    img.Metadata.VerticalResolution = orig.Metadata.VerticalResolution;
                }
            }
            img.SaveAsPng(dest, new PngEncoder { CompressionLevel = PngCompressionLevel.BestCompression, SkipMetadata = skip });
        }

        public static void Timestomp(string src, string dest) { try { var s = new FileInfo(src); var d = new FileInfo(dest); d.CreationTime = s.CreationTime; d.LastWriteTime = s.LastWriteTime; d.LastAccessTime = s.LastAccessTime; } catch { } }
    }
}
