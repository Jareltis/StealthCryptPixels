using System;
using System.Text;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace StealthCryptPixel
{
    // Криптографическое ядро: вывод контентного ключа (Argon2id), HKDF-подключи размещения,
    // несмещённая редукция (метод Лемира, UInt128) для перестановок и offset.
    // Перенесено из Program.cs без изменения логики.
    internal static class CryptoCore
    {
        public const int KeySize = 32;     // AES-256

        public static int UnbiasedReduce(byte[] randomBytes, int n)
        {
            ulong x = BitConverter.ToUInt64(randomBytes, 0);
            UInt128 product = (UInt128)x * (UInt128)(ulong)n;
            return (int)(ulong)(product >> 64);
        }

        public static byte[] DeriveContentKey(byte[] password, byte[] salt, int memoryKiB, int iterations, int parallelism)
        {
            var argon2 = new Argon2id(password)
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism
            };
            return argon2.GetBytes(KeySize);
        }

        public static byte[] PlacementKey(byte[] password, string label)
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, password, 32, null, Encoding.UTF8.GetBytes(label));
        }
    }
}
