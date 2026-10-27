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
    // Движок V4 (full-LSB, скрывает размер payload): константы формата, хаотичное распределение,
    // keyed-перестановка (SHA256 keystream), nonce-регион, шифрование/дешифрование/самопроверка.
    // Перенесено из Program.cs без изменения логики.
    internal static class ShardedV4
    {
        // === НАСТРОЙКИ V4 ===
        private const int SaltSize = 16;
        private const int NonceSize = 12;   // GCM Nonce
        private const int TagSize = 16;     // GCM Tag
        private const string MagicSignature = "STGP_V4";

        // KDF контента: Argon2id. Параметры пишутся в заголовок -> смена дефолтов не ломает старые файлы.
        private const byte KdfArgon2id = 1;
        private const int Argon2MemoryKiB = 65536;   // 64 MiB
        private const int Argon2Iterations = 3;
        private const int Argon2Parallelism = 1;

        // HKDF-метки для разделения ключей размещения (выводятся из пароля, без соли).
        private const string HkdfPerm = "SCP-v3-perm";
        private const string HkdfOffset = "SCP-v3-offset";
        private const string HkdfDist = "SCP-v3-dist";
        private const string HkdfPlacement = "SCP-v4-placement";

        // #5 placement-nonce: случайный на каждое сообщение, лежит в фиксированной области картинки 0.
        private const int PlacementNonceSize = 16;
        private const int NonceReservePixels = (PlacementNonceSize * 8 + 2) / 3;   // 43 пикселя под 128 бит

        // Заголовок V3: [kdfId(1)][memKiB(4)][iter(4)][par(1)][salt(16)][nonce(12)][tag(16)][len(4)]
        private const int KdfParamsSize = 1 + 4 + 4 + 1;   // 10
        private const int HeaderSize = KdfParamsSize + SaltSize + NonceSize + TagSize + 4;   // 58

        public static void EncryptSharded(string inputFile, List<string> donorPaths, byte[] password)
        {
            ImageIo.WarnIfLossyDonors(donorPaths);
            Console.Write("[*] Шифрование AES-GCM... ");
            var (header, body) = PrepareEncryptedParts(inputFile, password);
            long totalDataSize = header.Length + body.Length;

            byte[] placementNonce = RandomNumberGenerator.GetBytes(PlacementNonceSize);
            byte[] placementMaster = HKDF.DeriveKey(HashAlgorithmName.SHA256, password, 32, placementNonce, Encoding.UTF8.GetBytes(HkdfPlacement));
            Console.WriteLine($"Размер: {totalDataSize:N0} байт.");

            long totalBitsNeeded = totalDataSize * 8;

            List<long> capacities = new List<long>();
            long totalCapacity = 0;
            for (int ci = 0; ci < donorPaths.Count; ci++)
            {
                var info = Image.Identify(donorPaths[ci]);
                long reservePx = (ci == 0) ? NonceReservePixels : 0;
                long cap = ((long)info.Width * info.Height - reservePx) * 3;
                capacities.Add(cap);
                totalCapacity += cap;
            }

            double usagePercent = (double)totalBitsNeeded / totalCapacity * 100.0;
            Console.WriteLine($"[*] Емкость: {totalCapacity:N0} бит. Заполнение: {usagePercent:F2}%");
            if (usagePercent > 100) throw new Exception("Не хватает места!");

            if (usagePercent > 40) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] ВЫСОКИЙ РИСК (High Detectability)"); }
            else if (usagePercent < 15) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine("[+] STEALTH MODE ACTIVE"); }
            Console.ResetColor();

            long[] distribution = CalculateChaoticDistribution(totalBitsNeeded, capacities, placementMaster);

            Console.Write("[*] Генерация глобального шардинга (Body Shuffle)... ");
            int[] bodyPermutation = GetCryptoPermutation(body.Length, placementMaster, "GlobalShard");
            Console.WriteLine("Готово.");

            byte[] offsetKey = CryptoCore.PlacementKey(placementMaster, HkdfOffset);
            byte[] currentSeed = SHA256.HashData(offsetKey);
            Array.Clear(offsetKey, 0, offsetKey.Length);
            byte[] noiseBuffer = new byte[4096]; RandomNumberGenerator.Fill(noiseBuffer); int noiseIdx = 0;
            byte[] lsbBuffer = new byte[1024]; int lsbIdx = 1024;

            long globalByteIndex = 0;
            int currentBitInByte = 0;
            List<string> outputPaths = new List<string>();

            for (int imgIdx = 0; imgIdx < donorPaths.Count; imgIdx++)
            {
                string path = donorPaths[imgIdx];
                Console.Write($"[*] Обработка {Path.GetFileName(path)}... ");

                string outPath = Path.Combine(Path.GetDirectoryName(path) ?? "", "stego_" + Path.GetFileNameWithoutExtension(path) + ".png");
                string tempPath = outPath + ".tmp";

                using var image = Image.Load<Rgb24>(path);
                int reserve = (imgIdx == 0) ? NonceReservePixels : 0;
                if (imgIdx == 0) WriteNonceRegion(image, placementNonce);
                int[] perm = GetCryptoPermutation(image.Width * image.Height - reserve, placementMaster, $"Img_{imgIdx}");
                int offset = CryptoCore.UnbiasedReduce(SHA256.HashData(currentSeed), perm.Length);

                long capacity = (long)perm.Length * 3;
                long bitsAssigned = distribution[imgIdx];
                long localBitsWritten = 0;

                for (long i = 0; i < capacity; i++)
                {
                    long circularIndex = (offset + i) % capacity;
                    int flatIndex = reserve + perm[circularIndex / 3];
                    int channel = (int)(circularIndex % 3);
                    int x = flatIndex % image.Width;
                    int y = flatIndex / image.Width;

                    Rgb24 p = image[x, y];
                    int targetBit;

                    if (localBitsWritten < bitsAssigned && globalByteIndex < totalDataSize)
                    {
                        byte byteToWrite;

                        if (globalByteIndex < header.Length)
                        {
                            byteToWrite = header[globalByteIndex];
                        }
                        else
                        {
                            long bodyIdx = globalByteIndex - header.Length;
                            byteToWrite = body[bodyPermutation[bodyIdx]];
                        }

                        targetBit = (byteToWrite >> (7 - currentBitInByte)) & 1;

                        currentBitInByte++;
                        if (currentBitInByte == 8)
                        {
                            currentBitInByte = 0;
                            globalByteIndex++;
                        }
                        localBitsWritten++;
                    }
                    else
                    {
                        if (noiseIdx >= noiseBuffer.Length) { RandomNumberGenerator.Fill(noiseBuffer); noiseIdx = 0; }
                        targetBit = (noiseBuffer[noiseIdx / 8] >> (7 - (noiseIdx % 8))) & 1;
                        noiseIdx++;
                    }

                    if (lsbIdx >= lsbBuffer.Length) { RandomNumberGenerator.Fill(lsbBuffer); lsbIdx = 0; }
                    byte randByte = lsbBuffer[lsbIdx++];

                    if (channel == 0) p.R = ImageIo.ApplySecureLsb(p.R, targetBit, randByte);
                    else if (channel == 1) p.G = ImageIo.ApplySecureLsb(p.G, targetBit, randByte);
                    else p.B = ImageIo.ApplySecureLsb(p.B, targetBit, randByte);

                    image[x, y] = p;
                }

                ImageIo.CleanMetadataAndSave(image, path, tempPath);

                if (File.Exists(outPath)) File.Delete(outPath);
                File.Move(tempPath, outPath);
                ImageIo.Timestomp(path, outPath);
                outputPaths.Add(outPath);

                Console.WriteLine($"OK ({localBitsWritten} бит).");
                currentSeed = SHA256.HashData(currentSeed);
            }

            Array.Clear(body, 0, body.Length);

            Console.Write("[*] Самопроверка (round-trip)... ");
            byte[] checkBlob = ReadStegoToBlob(outputPaths, password);
            var (_, checkData) = ExtractPayload(checkBlob, password);
            byte[] original = File.ReadAllBytes(inputFile);
            bool selfCheckOk = original.AsSpan().SequenceEqual(checkData);
            Array.Clear(checkData, 0, checkData.Length);
            Array.Clear(original, 0, original.Length);
            if (!selfCheckOk)
                throw new Exception("Самопроверка не пройдена: расшифровка не совпала с оригиналом. Файлы stego_* использовать НЕЛЬЗЯ.");
            Console.WriteLine("OK");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Успешно. Глобальный шардинг + Хаос применены.");
            Console.ResetColor();
        }

        static byte[] ReadStegoToBlob(List<string> stegoPaths, byte[] password)
        {
            Console.WriteLine("[*] Чтение и дешардинг...");

            List<long> capacities = new List<long>();
            for (int ci = 0; ci < stegoPaths.Count; ci++)
            {
                if (!File.Exists(stegoPaths[ci])) throw new Exception($"Файл не найден: {stegoPaths[ci]}");
                var info = Image.Identify(stegoPaths[ci]);
                long reservePx = (ci == 0) ? NonceReservePixels : 0;
                capacities.Add(((long)info.Width * info.Height - reservePx) * 3);
            }

            byte[] placementNonce;
            using (var img0 = Image.Load<Rgb24>(stegoPaths[0])) placementNonce = ReadNonceRegion(img0);
            byte[] placementMaster = HKDF.DeriveKey(HashAlgorithmName.SHA256, password, 32, placementNonce, Encoding.UTF8.GetBytes(HkdfPlacement));

            byte[] offsetKey = CryptoCore.PlacementKey(placementMaster, HkdfOffset);
            byte[] currentSeed = SHA256.HashData(offsetKey);
            Array.Clear(offsetKey, 0, offsetKey.Length);

            List<byte> rawStream = new List<byte>();

            int currentByte = 0; int bitCount = 0;
            long? payloadTotalBytes = null;
            long[]? distributionMap = null;

            byte[] headerBytes = new byte[HeaderSize];
            bool headerFound = false;

            for (int imgIdx = 0; imgIdx < stegoPaths.Count; imgIdx++)
            {
                string path = stegoPaths[imgIdx];
                long currentImageCap = capacities[imgIdx];
                Console.WriteLine($"    -> Чтение {Path.GetFileName(path)}");

                using var image = Image.Load<Rgb24>(path);
                int reserve = (imgIdx == 0) ? NonceReservePixels : 0;
                int[] perm = GetCryptoPermutation(image.Width * image.Height - reserve, placementMaster, $"Img_{imgIdx}");
                int offset = CryptoCore.UnbiasedReduce(SHA256.HashData(currentSeed), perm.Length);

                long limitForThisImage = currentImageCap;
                if (distributionMap != null) limitForThisImage = distributionMap[imgIdx];

                long localBitsRead = 0;

                for (long i = 0; i < currentImageCap; i++)
                {
                    if (distributionMap != null && localBitsRead >= limitForThisImage) break;

                    long circularIndex = (offset + i) % currentImageCap;
                    int flatIndex = reserve + perm[circularIndex / 3];
                    int channel = (int)(circularIndex % 3);
                    var p = image[flatIndex % image.Width, flatIndex / image.Width];

                    int bit = (channel == 0) ? p.R & 1 : (channel == 1) ? p.G & 1 : p.B & 1;

                    currentByte = (currentByte << 1) | bit;
                    bitCount++;

                    if (bitCount == 8)
                    {
                        byte readByte = (byte)currentByte;
                        rawStream.Add(readByte);

                        if (!headerFound)
                        {
                            if (rawStream.Count <= HeaderSize)
                                headerBytes[rawStream.Count - 1] = readByte;

                            if (rawStream.Count == HeaderSize)
                            {
                                int offsetLen = HeaderSize - 4;
                                int bodyLen = headerBytes[offsetLen] | (headerBytes[offsetLen + 1] << 8) | (headerBytes[offsetLen + 2] << 16) | (headerBytes[offsetLen + 3] << 24);

                                if (bodyLen > 0 && bodyLen < 500_000_000)
                                {
                                    payloadTotalBytes = HeaderSize + bodyLen;
                                    Console.WriteLine($"    [*] Заголовок найден! Body: {bodyLen} байт. Строю карту...");

                                    distributionMap = CalculateChaoticDistribution(payloadTotalBytes.Value * 8, capacities, placementMaster);
                                    limitForThisImage = distributionMap[imgIdx];
                                    headerFound = true;
                                }
                            }
                        }
                        currentByte = 0; bitCount = 0;
                    }
                    localBitsRead++;
                }
                currentSeed = SHA256.HashData(currentSeed);
            }

            if (!headerFound || payloadTotalBytes == null) throw new Exception("Не удалось собрать данные: неверный пароль, либо повреждённый / неполный / переставленный набор картинок.");

            int actualBodyLen = rawStream.Count - HeaderSize;
            byte[] finalBody = new byte[actualBodyLen];

            byte[] shuffledBody = new byte[actualBodyLen];
            rawStream.CopyTo(HeaderSize, shuffledBody, 0, actualBodyLen);

            Console.Write("[*] Дешардинг (Unshuffling)... ");
            int[] bodyPerm = GetCryptoPermutation(actualBodyLen, placementMaster, "GlobalShard");

            for (int i = 0; i < actualBodyLen; i++)
            {
                int originalIndex = bodyPerm[i];
                finalBody[originalIndex] = shuffledBody[i];
            }
            Console.WriteLine("Готово.");

            byte[] fullBlob = new byte[HeaderSize + actualBodyLen];
            Buffer.BlockCopy(headerBytes, 0, fullBlob, 0, HeaderSize);
            Buffer.BlockCopy(finalBody, 0, fullBlob, HeaderSize, actualBodyLen);

            return fullBlob;
        }

        public static void DecryptSharded(List<string> stegoPaths, byte[] password)
        {
            byte[] blob = ReadStegoToBlob(stegoPaths, password);
            var (name, data) = ExtractPayload(blob, password);
            string safe = Path.GetFileName(name);
            if (string.IsNullOrWhiteSpace(safe)) safe = "recovered_file.bin";
            string outName = "Decrypted_" + safe;
            File.WriteAllBytes(outName, data);
            Console.WriteLine($"[+] Файл: {outName}");
        }

        static (byte[] header, byte[] body) PrepareEncryptedParts(string inputFile, byte[] password)
        {
            byte[] raw = File.ReadAllBytes(inputFile);
            byte[] name = Encoding.UTF8.GetBytes(Path.GetFileName(inputFile));
            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var zip = new GZipStream(ms, CompressionLevel.Optimal))
                {
                    zip.Write(Encoding.ASCII.GetBytes(MagicSignature));
                    zip.Write(BitConverter.GetBytes(name.Length));
                    zip.Write(name);
                    zip.Write(BitConverter.GetBytes((long)raw.Length));
                    zip.Write(raw);
                }
                compressed = ms.ToArray();
            }
            Array.Clear(raw, 0, raw.Length);

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] key = CryptoCore.DeriveContentKey(password, salt, Argon2MemoryKiB, Argon2Iterations, Argon2Parallelism);

            try
            {
                using var aes = new AesGcm(key, TagSize);
                byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
                byte[] ciphertext = new byte[compressed.Length];
                byte[] tag = new byte[TagSize];
                aes.Encrypt(nonce, compressed, ciphertext, tag);

                byte[] header = new byte[HeaderSize];
                int p = 0;
                header[p++] = KdfArgon2id;

                header[p++] = (byte)(Argon2MemoryKiB & 0xFF);
                header[p++] = (byte)((Argon2MemoryKiB >> 8) & 0xFF);
                header[p++] = (byte)((Argon2MemoryKiB >> 16) & 0xFF);
                header[p++] = (byte)((Argon2MemoryKiB >> 24) & 0xFF);

                header[p++] = (byte)(Argon2Iterations & 0xFF);
                header[p++] = (byte)((Argon2Iterations >> 8) & 0xFF);
                header[p++] = (byte)((Argon2Iterations >> 16) & 0xFF);
                header[p++] = (byte)((Argon2Iterations >> 24) & 0xFF);

                header[p++] = (byte)Argon2Parallelism;
                Buffer.BlockCopy(salt, 0, header, p, SaltSize); p += SaltSize;
                Buffer.BlockCopy(nonce, 0, header, p, NonceSize); p += NonceSize;
                Buffer.BlockCopy(tag, 0, header, p, TagSize); p += TagSize;
                int len = ciphertext.Length;
                header[p++] = (byte)(len & 0xFF); header[p++] = (byte)((len >> 8) & 0xFF); header[p++] = (byte)((len >> 16) & 0xFF); header[p++] = (byte)((len >> 24) & 0xFF);

                return (header, ciphertext);
            }
            finally { Array.Clear(key, 0, key.Length); Array.Clear(compressed, 0, compressed.Length); }
        }

        static long[] CalculateChaoticDistribution(long totalBits, List<long> capacities, byte[] password)
        {
            long[] dist = new long[capacities.Count];
            if (capacities.Count == 0) throw new Exception("Нет картинок для распределения.");

            long headerBits = (long)HeaderSize * 8;
            if (capacities[0] < headerBits)
                throw new Exception($"Первая картинка слишком мала: нужна ёмкость >= {headerBits} бит для заголовка.");
            dist[0] = headerBits;

            long remaining = totalBits - headerBits;
            if (remaining < 0) throw new Exception("Внутренняя ошибка: размер данных меньше заголовка.");

            byte[] distKey = CryptoCore.PlacementKey(password, HkdfDist);
            using var hmac = new HMACSHA256(distKey);
            Array.Clear(distKey, 0, distKey.Length);
            byte[] counter = new byte[4]; int cVal = 0;

            while (remaining > 0)
            {
                double[] weights = new double[capacities.Count];
                double totalW = 0;
                bool space = false;
                for (int i = 0; i < capacities.Count; i++)
                {
                    if (dist[i] < capacities[i])
                    {
                        space = true;
                        BitConverter.TryWriteBytes(counter, cVal++);
                        byte[] h = hmac.ComputeHash(counter);
                        int val = (h[0] << 8) | h[1];
                        weights[i] = (val / 65535.0) + 0.01;
                        totalW += weights[i];
                    }
                }
                if (!space) throw new Exception("Inner Error: No Space");

                long roundDist = 0;
                long bitsToDist = remaining;
                for (int i = 0; i < capacities.Count; i++)
                {
                    if (dist[i] < capacities[i])
                    {
                        long share = (long)(bitsToDist * (weights[i] / totalW));
                        if (share == 0 && remaining > 0) share = 1;
                        long avail = capacities[i] - dist[i];
                        if (share > avail) share = avail;
                        if (share > remaining) share = remaining;
                        dist[i] += share; remaining -= share; roundDist += share;
                        if (remaining == 0) break;
                    }
                }
                if (roundDist == 0 && remaining > 0)
                {
                    for (int i = 0; i < capacities.Count; i++)
                        if (dist[i] < capacities[i]) { dist[i]++; remaining--; break; }
                }
            }
            return dist;
        }

        static int[] GetCryptoPermutation(int length, byte[] password, string context)
        {
            int[] idx = new int[length];
            for (int i = 0; i < length; i++) idx[i] = i;
            using var sha = SHA256.Create();
            byte[] permKey = CryptoCore.PlacementKey(password, HkdfPerm);
            byte[] ctx = Encoding.UTF8.GetBytes(context);
            byte[] seedInput = new byte[permKey.Length + ctx.Length];
            Buffer.BlockCopy(permKey, 0, seedInput, 0, permKey.Length);
            Buffer.BlockCopy(ctx, 0, seedInput, permKey.Length, ctx.Length);
            byte[] seed = sha.ComputeHash(seedInput);
            Array.Clear(seedInput, 0, seedInput.Length);
            Array.Clear(permKey, 0, permKey.Length);
            // keyed CSPRNG (SHA256 counter-mode keystream) вместо одного HMAC на каждый элемент:
            // один init + поток блоков -> на больших картинках кратно меньше хэш-вызовов. Конструкция как в V5 KeyedPerm.
            if (length > 1)
            {
                int need = 8 * (length - 1);
                byte[] pool = new byte[((need + 31) / 32) * 32];
                byte[] inp = new byte[seed.Length + 8];
                Buffer.BlockCopy(seed, 0, inp, 0, seed.Length);
                long counter = 0; int filled = 0;
                while (filled < pool.Length)
                {
                    BitConverter.GetBytes(counter).CopyTo(inp, seed.Length); counter++;
                    byte[] blk = SHA256.HashData(inp);
                    Buffer.BlockCopy(blk, 0, pool, filled, 32); filled += 32;
                }
                byte[] h8 = new byte[8]; int pos = 0;
                for (int i = length - 1; i > 0; i--)
                {
                    Buffer.BlockCopy(pool, pos, h8, 0, 8); pos += 8;
                    int r = CryptoCore.UnbiasedReduce(h8, i + 1);
                    (idx[i], idx[r]) = (idx[r], idx[i]);
                }
            }
            return idx;
        }

        static void WriteNonceRegion(Image<Rgb24> image, byte[] nonce)
        {
            int slots = NonceReservePixels * 3;
            int nonceBits = nonce.Length * 8;
            byte[] rnd = RandomNumberGenerator.GetBytes(slots);
            for (int s = 0; s < slots; s++)
            {
                int pixel = s / 3, ch = s % 3;
                int bit = (s < nonceBits) ? ((nonce[s / 8] >> (7 - (s % 8))) & 1) : (rnd[s] & 1);
                int x = pixel % image.Width, y = pixel / image.Width;
                Rgb24 p = image[x, y];
                if (ch == 0) p.R = ImageIo.ApplySecureLsb(p.R, bit, rnd[s]);
                else if (ch == 1) p.G = ImageIo.ApplySecureLsb(p.G, bit, rnd[s]);
                else p.B = ImageIo.ApplySecureLsb(p.B, bit, rnd[s]);
                image[x, y] = p;
            }
        }

        static byte[] ReadNonceRegion(Image<Rgb24> image)
        {
            int nonceBits = PlacementNonceSize * 8;
            byte[] nonce = new byte[PlacementNonceSize];
            for (int s = 0; s < nonceBits; s++)
            {
                int pixel = s / 3, ch = s % 3;
                int x = pixel % image.Width, y = pixel / image.Width;
                Rgb24 p = image[x, y];
                int bit = (ch == 0) ? (p.R & 1) : (ch == 1) ? (p.G & 1) : (p.B & 1);
                if (bit != 0) nonce[s / 8] |= (byte)(1 << (7 - (s % 8)));
            }
            return nonce;
        }

        static (string name, byte[] data) ExtractPayload(byte[] blob, byte[] password)
        {
            if (blob.Length < HeaderSize) throw new Exception("Повреждённые данные (заголовок неполный).");
            int ptr = 0;
            byte kdfId = blob[ptr++];
            int memKiB = blob[ptr] | (blob[ptr + 1] << 8) | (blob[ptr + 2] << 16) | (blob[ptr + 3] << 24); ptr += 4;
            int iter = blob[ptr] | (blob[ptr + 1] << 8) | (blob[ptr + 2] << 16) | (blob[ptr + 3] << 24); ptr += 4;
            int par = blob[ptr++];
            byte[] salt = blob[ptr..(ptr += SaltSize)];
            byte[] nonce = blob[ptr..(ptr += NonceSize)];
            byte[] tag = blob[ptr..(ptr += TagSize)];
            int len = blob[ptr] | (blob[ptr + 1] << 8) | (blob[ptr + 2] << 16) | (blob[ptr + 3] << 24);
            ptr += 4;
            if (len < 0 || ptr + (long)len > blob.Length)
                throw new Exception("Повреждённые данные (длина шифротекста).");
            byte[] cipher = blob[ptr..(ptr + len)];
            if (kdfId != KdfArgon2id) throw new Exception("Неподдерживаемый KDF в заголовке.");
            if (memKiB < 8 || memKiB > 1048576 || iter < 1 || iter > 64 || par < 1 || par > 64)
                throw new Exception("Повреждённые данные (параметры KDF вне диапазона).");
            byte[] key = CryptoCore.DeriveContentKey(password, salt, memKiB, iter, par);
            byte[] plain = new byte[cipher.Length];
            byte[]? memBuf = null;
            try
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Decrypt(nonce, cipher, tag, plain);
                using var ms = new MemoryStream(plain);
                using var zip = new GZipStream(ms, CompressionMode.Decompress);
                using var mem = new MemoryStream();
                zip.CopyTo(mem); mem.Position = 0;
                memBuf = mem.GetBuffer();
                using var br = new BinaryReader(mem);
                string sig = Encoding.ASCII.GetString(br.ReadBytes(MagicSignature.Length));
                if (sig != MagicSignature)
                    throw new Exception($"Неподдерживаемая версия формата (ожидается {MagicSignature}).");
                int nLen = br.ReadInt32();
                if (nLen < 0 || nLen > mem.Length - mem.Position)
                    throw new Exception("Повреждённые данные (длина имени файла).");
                string name = Encoding.UTF8.GetString(br.ReadBytes(nLen));
                long fLen = br.ReadInt64();
                if (fLen < 0 || fLen > mem.Length - mem.Position)
                    throw new Exception("Повреждённые данные (размер файла).");
                byte[] data = br.ReadBytes((int)fLen);
                return (name, data);
            }
            catch (CryptographicException)
            {
                throw new Exception("Не удалось расшифровать: неверный пароль, либо повреждённый / неполный / переставленный набор картинок.");
            }
            finally { Array.Clear(key, 0, key.Length); Array.Clear(plain, 0, plain.Length); if (memBuf != null) Array.Clear(memBuf, 0, memBuf.Length); }
        }
    }
}
