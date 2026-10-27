using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace StealthCryptPixel
{
    internal static class AdaptiveV5
    {
        // ===== Параметры V5 =====
        public const int StcHeight = 10;          // высота решётки STC (2^10 состояний)
        public const int StcWidth = 5;            // bpp ≈ 1/W = 0.2
        public const double HillEps = 1e-12;
        public const double HillRhoMax = 1e8;

        // ===== Криптопараметры V5 =====
        const string MagicV5 = "STGP_V5";
        const string HkdfPlacement = "SCP-v5-placement";
        const int SaltSize = 16, NonceSize = 12, TagSize = 16, KeySize = 32, PlacementNonceSize = 16;
        const int Argon2MemoryKiB = 65536, Argon2Iterations = 3, Argon2Parallelism = 1;
        const byte KdfArgon2id = 1, CostHill = 0;
        const int BootstrapSize = 77;
        public const int BootstrapReservePixels = (BootstrapSize * 8 + 2) / 3;   // 206 пикселей картинки 0

        // Таблица порождающих подматриц STC по ширине (w столбцов, каждый 10-битный нечётный, popcount>=3).
        // Проверены Python-валидацией на идеальный round-trip. w=5 — исходный набор (обратная совместимость
        // со старыми V5-стего). bpp ≈ 1/w.
        static readonly Dictionary<int, int[]> ColIntsByWidth = new Dictionary<int, int[]>
        {
            { 2,  new int[] { 721, 27 } },
            { 3,  new int[] { 241, 215, 695 } },
            { 5,  new int[] { 617, 703, 99, 841, 569 } },
            { 8,  new int[] { 673, 101, 917, 787, 435, 351, 295, 31 } },
            { 12, new int[] { 1005, 291, 723, 351, 383, 307, 287, 739, 673, 399, 1011, 571 } },
            { 16, new int[] { 31, 717, 561, 569, 895, 485, 67, 829, 63, 837, 415, 77, 853, 587, 127, 711 } },
        };
        // Для авто-выбора: от самой скрытной (большой w, низкий bpp) к ёмкой (малый w, высокий bpp).
        static readonly int[] WidthLadder = new int[] { 16, 12, 8, 5, 3, 2 };
        static int[] ColsForWidth(int w)
        {
            if (!ColIntsByWidth.TryGetValue(w, out int[]? cols))
                throw new Exception($"V5: неподдерживаемая ширина STC w={w}.");
            return cols;
        }

        public static double[] HillCost(byte[] plane, int width, int height)
        {
            int n = width * height;
            double[] X = new double[n];
            for (int i = 0; i < n; i++) X[i] = plane[i];

            double[] kb = { -1, 2, -1, 2, -4, 2, -1, 2, -1 };   // KB high-pass 3x3
            double[] R = Convolve3x3(X, width, height, kb);
            for (int i = 0; i < n; i++) R[i] = Math.Abs(R[i]);

            double[] W = BoxAvg(R, width, height, 3);           // L1
            double[] rho = new double[n];
            for (int i = 0; i < n; i++) rho[i] = 1.0 / (W[i] + HillEps);
            rho = BoxAvg(rho, width, height, 15);               // L2
            for (int i = 0; i < n; i++) if (rho[i] > HillRhoMax) rho[i] = HillRhoMax;
            return rho;
        }

        static int Mirror(int i, int n)
        {
            if (n == 1) return 0;
            int period = 2 * (n - 1);
            int m = ((i % period) + period) % period;
            return (m <= n - 1) ? m : period - m;
        }

        static double[] Convolve3x3(double[] img, int w, int h, double[] k)
        {
            double[] outp = new double[w * h];
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    double acc = 0.0;
                    for (int dy = -1; dy <= 1; dy++)
                        for (int dx = -1; dx <= 1; dx++)
                        {
                            int yy = Mirror(y + dy, h);
                            int xx = Mirror(x + dx, w);
                            acc += img[yy * w + xx] * k[(dy + 1) * 3 + (dx + 1)];
                        }
                    outp[y * w + x] = acc;
                }
            return outp;
        }

        static double[] BoxAvg(double[] img, int w, int h, int size)
        {
            int r = size / 2;
            double inv = 1.0 / (size * size);
            double[] outp = new double[w * h];
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    double acc = 0.0;
                    for (int dy = -r; dy <= r; dy++)
                        for (int dx = -r; dx <= r; dx++)
                        {
                            int yy = Mirror(y + dy, h);
                            int xx = Mirror(x + dx, w);
                            acc += img[yy * w + xx];
                        }
                    outp[y * w + x] = acc * inv;
                }
            return outp;
        }

        public static byte[] StcEmbed(byte[] x, double[] rho, byte[] msg, int[] cols)
        {
            int h = StcHeight, w = cols.Length;
            int mLen = msg.Length, n = x.Length;
            if (n != w * mLen) throw new ArgumentException($"STC: n({n}) != W*mLen({w * mLen})");
            int nstates = 1 << h;
            double INF = double.PositiveInfinity;

            double[] cost = new double[nstates];
            for (int i = 0; i < nstates; i++) cost[i] = INF;
            cost[0] = 0.0;

            byte[][] ybList = new byte[n][];
            int[] colMasked = new int[n];

            for (int b = 0; b < mLen; b++)
            {
                int active = Math.Min(h, mLen - b);
                int mask = (1 << active) - 1;
                int mb = msg[b];
                for (int c = 0; c < w; c++)
                {
                    int j = b * w + c;
                    int cm = cols[c] & mask;
                    colMasked[j] = cm;
                    double d0 = (x[j] == 0) ? 0.0 : rho[j];
                    double d1 = (x[j] == 1) ? 0.0 : rho[j];
                    double[] newcost = new double[nstates];
                    byte[] yb = new byte[nstates];
                    for (int s = 0; s < nstates; s++)
                    {
                        double a = cost[s] + d0;
                        double bb = cost[s ^ cm] + d1;
                        if (bb < a) { newcost[s] = bb; yb[s] = 1; }
                        else { newcost[s] = a; yb[s] = 0; }
                    }
                    cost = newcost;
                    ybList[j] = yb;
                }
                double[] newc = new double[nstates];
                for (int i = 0; i < nstates; i++) newc[i] = INF;
                int half = nstates >> 1;
                for (int ts = 0; ts < half; ts++)
                {
                    int s = (ts << 1) | mb;
                    newc[ts] = cost[s];
                }
                cost = newc;
            }
            if (double.IsInfinity(cost[0])) throw new Exception("STC: нет решения (cost[0]=inf)");

            byte[] y = new byte[n];
            int sNext = 0;
            for (int b = mLen - 1; b >= 0; b--)
            {
                int cur = (sNext << 1) | msg[b];
                for (int c = w - 1; c >= 0; c--)
                {
                    int j = b * w + c;
                    int ybit = ybList[j][cur];
                    if (ybit != 0) cur ^= colMasked[j];
                    y[j] = (byte)ybit;
                }
                sNext = cur;
            }
            if (sNext != 0) throw new Exception($"STC: S0 != 0 (={sNext})");
            return y;
        }

        public static byte[] StcExtract(byte[] y, int mLen, int[] cols)
        {
            int h = StcHeight, w = cols.Length;
            byte[] syn = new byte[mLen];
            for (int j = 0; j < y.Length; j++)
            {
                if (y[j] != 0)
                {
                    int b = j / w;
                    int cc = cols[j % w];
                    for (int i = 0; i < h; i++)
                    {
                        int rr = b + i;
                        if (rr < mLen) syn[rr] ^= (byte)((cc >> i) & 1);
                    }
                }
            }
            return syn;
        }

        public static void SelfTest()
        {
            CheckStc("V0", V0_x, V0_rho, V0_msg, V0_y);
            CheckStc("V1", V1_x, V1_rho, V1_msg, V1_y);
            CheckStc("V2", V2_x, V2_rho, V2_msg, V2_y);
            CheckHill();
            CheckMultiPlane();
            CheckBootstrap();
            CheckWidths();
            Console.WriteLine("[V5 self-test] STC векторы + HILL эталон + мульти-план + bootstrap/биты + ширины bpp: OK");
        }

        static void CheckWidths()
        {
            Random rng = new Random(20260614);
            foreach (var kv in ColIntsByWidth)
            {
                int[] cols = kv.Value;
                if (cols.Length != kv.Key) throw new Exception($"V5 width: ширина {kv.Key} != длины столбцов {cols.Length}");
                foreach (int cc in cols)
                    if ((cc & 1) == 0) throw new Exception($"V5 width w={kv.Key}: чётный столбец {cc} (нужны нечётные)");
                for (int t = 0; t < 5; t++)
                {
                    int mLen = 20 + rng.Next(40);
                    int n = cols.Length * mLen;
                    byte[] x = new byte[n]; double[] rho = new double[n]; byte[] msg = new byte[mLen];
                    for (int i = 0; i < n; i++) { x[i] = (byte)rng.Next(2); rho[i] = rng.NextDouble() * 10 + 1e-3; }
                    for (int i = 0; i < mLen; i++) msg[i] = (byte)rng.Next(2);
                    byte[] y = StcEmbed(x, rho, msg, cols);
                    byte[] rec = StcExtract(y, mLen, cols);
                    for (int i = 0; i < mLen; i++)
                        if (rec[i] != msg[i]) throw new Exception($"V5 width w={kv.Key}: mismatch at bit {i}");
                }
            }
        }

        static void CheckStc(string name, byte[] x, double[] rho, byte[] msg, byte[] expY)
        {
            byte[] y = StcEmbed(x, rho, msg, ColsForWidth(StcWidth));
            for (int i = 0; i < y.Length; i++)
                if (y[i] != expY[i]) throw new Exception($"STC {name}: y[{i}]={y[i]} != {expY[i]}");
            byte[] m2 = StcExtract(y, msg.Length, ColsForWidth(StcWidth));
            for (int i = 0; i < msg.Length; i++)
                if (m2[i] != msg[i]) throw new Exception($"STC {name}: extract[{i}] mismatch");
        }

        static void CheckHill()
        {
            int hh = 32, ww = 32;
            byte[] plane = new byte[hh * ww];
            for (int y = 0; y < hh; y++)
                for (int x = 0; x < ww; x++)
                    plane[y * ww + x] = (byte)((37 * x + 17 * y + ((x * y) % 53) + 7 * ((x * x) % 11)) % 256);
            double[] rho = HillCost(plane, ww, hh);
            for (int p = 0; p < HillExp.Length; p++)
            {
                int r = HillPts[p, 0], c = HillPts[p, 1];
                double got = rho[r * ww + c], exp = HillExp[p];
                double rel = Math.Abs(got - exp) / Math.Max(1e-9, Math.Abs(exp));
                // допуск 1e-2: C# использует ручную свёртку, эталон сгенерён scipy; реальная
                // максимальная кросс-разница ~1.8e-3. Порог ловит грубые ошибки (не тот фильтр/формула = десятки %).
                if (rel > 1e-2) throw new Exception($"HILL ({r},{c}): {got} vs {exp} (rel {rel:E3})");
            }
        }

        static void CheckMultiPlane()
        {
            Random rng = new Random(1234);
            int[][] dims = { new[] { 40, 40 }, new[] { 32, 48 }, new[] { 24, 24 }, new[] { 50, 30 } };
            int k = dims.Length;
            byte[][] planes = new byte[k][];
            int[] caps = new int[k];
            int totalCap = 0;
            for (int i = 0; i < k; i++)
            {
                int np = dims[i][0] * dims[i][1];
                planes[i] = new byte[np];
                for (int t = 0; t < np; t++) planes[i][t] = (byte)rng.Next(256);
                caps[i] = PlaneCapacityBits(np, StcWidth); totalCap += caps[i];
            }
            byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes("selftest-key"));
            int[] order = KeyedPlaneOrder(k, key);
            int totalBits = (int)(totalCap * 0.6);
            byte[] payload = new byte[totalBits];
            for (int i = 0; i < totalBits; i++) payload[i] = (byte)rng.Next(2);
            int[] mlens = SplitLengths(totalBits, caps, order);

            int pos = 0;
            foreach (int p in order)
            {
                int mk = mlens[p]; if (mk == 0) continue;
                byte[] msg = new byte[mk]; Array.Copy(payload, pos, msg, 0, mk); pos += mk;
                int[] perm = KeyedPerm(planes[p].Length, key, $"plane-{p}");
                EmbedPlane(planes[p], dims[p][0], dims[p][1], msg, perm, 0, ColsForWidth(StcWidth));
            }
            byte[] rec = new byte[totalBits]; int rpos = 0;
            foreach (int p in order)
            {
                int mk = mlens[p]; if (mk == 0) continue;
                int[] perm = KeyedPerm(planes[p].Length, key, $"plane-{p}");
                byte[] bits = ExtractPlaneBits(planes[p], perm, mk, 0, ColsForWidth(StcWidth));
                Array.Copy(bits, 0, rec, rpos, mk); rpos += mk;
            }
            for (int i = 0; i < totalBits; i++)
                if (rec[i] != payload[i]) throw new Exception($"V5 multi-plane: mismatch at bit {i}");
        }

        static void CheckBootstrap()
        {
            byte[] salt = new byte[SaltSize]; for (int i = 0; i < SaltSize; i++) salt[i] = (byte)(i * 7 + 1);
            byte[] nonce = new byte[NonceSize]; for (int i = 0; i < NonceSize; i++) nonce[i] = (byte)(i * 5 + 2);
            byte[] tag = new byte[TagSize]; for (int i = 0; i < TagSize; i++) tag[i] = (byte)(i * 3 + 9);
            byte[] pnonce = new byte[PlacementNonceSize]; for (int i = 0; i < PlacementNonceSize; i++) pnonce[i] = (byte)(i * 11 + 4);
            int totalLen = 123456;
            byte[] h = PackBootstrap(salt, nonce, tag, pnonce, totalLen, StcWidth);
            if (h.Length != BootstrapSize) throw new Exception($"bootstrap size {h.Length} != {BootstrapSize}");
            BootstrapInfo bi = UnpackBootstrap(h);
            if (!Eq(bi.Salt, salt) || !Eq(bi.GcmNonce, nonce) || !Eq(bi.GcmTag, tag) || !Eq(bi.PlacementNonce, pnonce))
                throw new Exception("bootstrap: байтовые поля не совпали");
            if (bi.TotalLen != totalLen || bi.MemKiB != Argon2MemoryKiB || bi.Iter != Argon2Iterations ||
                bi.Par != Argon2Parallelism || bi.CostId != CostHill || bi.Height != StcHeight || bi.Width != StcWidth)
                throw new Exception("bootstrap: числовые поля не совпали");

            Random rng = new Random(77);
            byte[] blob = new byte[257];
            for (int i = 0; i < blob.Length; i++) blob[i] = (byte)rng.Next(256);
            byte[] back = BitsToBytes(BytesToBits(blob));
            if (!Eq(back, blob)) throw new Exception("bits round-trip mismatch");
        }

        static int UnbiasedReduce(byte[] bytes8, int bound)
        {
            ulong r = BitConverter.ToUInt64(bytes8, 0);
            System.UInt128 m = (System.UInt128)r * (System.UInt128)(ulong)bound;
            return (int)(ulong)(m >> 64);
        }

        static int[] KeyedPerm(int count, byte[] key, string label)
        {
            int[] p = new int[count];
            for (int i = 0; i < count; i++) p[i] = i;
            if (count <= 1) return p;

            byte[] seed;
            using (var hmac = new HMACSHA256(key)) seed = hmac.ComputeHash(Encoding.UTF8.GetBytes(label));

            int need = 8 * (count - 1);
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
            for (int i = count - 1; i > 0; i--)
            {
                Buffer.BlockCopy(pool, pos, h8, 0, 8); pos += 8;
                int j = UnbiasedReduce(h8, i + 1);
                int tmp = p[i]; p[i] = p[j]; p[j] = tmp;
            }
            return p;
        }

        public static int PlaneCapacityBits(int nPixels, int w) => nPixels / w;

        public static int[] KeyedPlaneOrder(int numPlanes, byte[] key) => KeyedPerm(numPlanes, key, "SCP-v5-plane-order");

        public static int[] SplitLengths(int totalBits, int[] caps, int[] order)
        {
            int[] m = new int[caps.Length];
            int rem = totalBits;
            foreach (int p in order)
            {
                if (rem <= 0) break;
                int take = Math.Min(rem, caps[p]);
                m[p] = take; rem -= take;
            }
            if (rem > 0) throw new Exception($"V5: payload не влезает, остаток {rem} бит");
            return m;
        }

        public static void EmbedPlane(byte[] plane, int width, int height, byte[] msgBits, int[] perm, int reserve, int[] cols)
        {
            int avail = plane.Length - reserve;
            int n = cols.Length * msgBits.Length;
            if (n > avail) throw new ArgumentException("V5: плоскость мала для сообщения");
            double[] rho = HillCost(plane, width, height);
            byte[] x = new byte[n];
            double[] rhoSeq = new double[n];
            for (int k = 0; k < n; k++) { int idx = reserve + perm[k]; x[k] = (byte)(plane[idx] & 1); rhoSeq[k] = rho[idx]; }
            byte[] y = StcEmbed(x, rhoSeq, msgBits, cols);
            // Направление ±1 — случайное, а не детерминированный +1: убирает направленный сдвиг гистограммы,
            // который могла бы выучить CNN. LSB-результат идентичен (и +1, и -1 переворачивают младший бит),
            // поэтому STC-декодер и -t5 не затрагиваются; декодеру направление не нужно (читает только LSB).
            byte[] dir = RandomNumberGenerator.GetBytes(n);
            for (int k = 0; k < n; k++)
            {
                if (y[k] != x[k])
                {
                    int idx = reserve + perm[k];
                    plane[idx] = ImageIo.ApplySecureLsb(plane[idx], y[k], dir[k]);
                }
            }
        }

        public static byte[] ExtractPlaneBits(byte[] plane, int[] perm, int mLen, int reserve, int[] cols)
        {
            int n = cols.Length * mLen;
            byte[] y = new byte[n];
            for (int k = 0; k < n; k++) y[k] = (byte)(plane[reserve + perm[k]] & 1);
            return StcExtract(y, mLen, cols);
        }

        internal sealed class BootstrapInfo
        {
            public byte[] Salt = null!, GcmNonce = null!, GcmTag = null!, PlacementNonce = null!;
            public int MemKiB, Iter, Par, TotalLen, Height, Width;
            public byte CostId;
        }

        static void WriteI32(byte[] buf, ref int p, int v)
        {
            buf[p++] = (byte)(v & 0xFF); buf[p++] = (byte)((v >> 8) & 0xFF); buf[p++] = (byte)((v >> 16) & 0xFF); buf[p++] = (byte)((v >> 24) & 0xFF);
        }
        static int ReadI32(byte[] buf, ref int p)
        {
            int v = buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16) | (buf[p + 3] << 24); p += 4; return v;
        }

        static byte[] PackBootstrap(byte[] salt, byte[] nonce, byte[] tag, byte[] pnonce, int totalLen, int stcWidth)
        {
            byte[] h = new byte[BootstrapSize];
            int p = 0;
            h[p++] = KdfArgon2id;
            WriteI32(h, ref p, Argon2MemoryKiB);
            WriteI32(h, ref p, Argon2Iterations);
            h[p++] = (byte)Argon2Parallelism;
            Buffer.BlockCopy(salt, 0, h, p, SaltSize); p += SaltSize;
            Buffer.BlockCopy(pnonce, 0, h, p, PlacementNonceSize); p += PlacementNonceSize;
            Buffer.BlockCopy(nonce, 0, h, p, NonceSize); p += NonceSize;
            Buffer.BlockCopy(tag, 0, h, p, TagSize); p += TagSize;
            h[p++] = CostHill;
            h[p++] = (byte)StcHeight;
            h[p++] = (byte)stcWidth;
            WriteI32(h, ref p, totalLen);
            if (p != BootstrapSize) throw new Exception($"bootstrap pack: p={p}");
            return h;
        }

        static BootstrapInfo UnpackBootstrap(byte[] h)
        {
            if (h.Length < BootstrapSize) throw new Exception("V5: bootstrap слишком мал");
            var bi = new BootstrapInfo();
            int p = 0;
            byte kdf = h[p++];
            bi.MemKiB = ReadI32(h, ref p);
            bi.Iter = ReadI32(h, ref p);
            bi.Par = h[p++];
            bi.Salt = h[p..(p += SaltSize)];
            bi.PlacementNonce = h[p..(p += PlacementNonceSize)];
            bi.GcmNonce = h[p..(p += NonceSize)];
            bi.GcmTag = h[p..(p += TagSize)];
            bi.CostId = h[p++];
            bi.Height = h[p++];
            bi.Width = h[p++];
            bi.TotalLen = ReadI32(h, ref p);

            if (kdf != KdfArgon2id) throw new Exception("V5: неподдерживаемый KDF.");
            if (bi.MemKiB < 8 || bi.MemKiB > 1048576 || bi.Iter < 1 || bi.Iter > 64 || bi.Par < 1 || bi.Par > 64)
                throw new Exception("V5: параметры KDF вне диапазона.");
            if (bi.CostId != CostHill) throw new Exception("V5: неизвестная cost-модель.");
            if (bi.Height != StcHeight || !ColIntsByWidth.ContainsKey(bi.Width)) throw new Exception("V5: несовпадение параметров STC.");
            if (bi.TotalLen < 0) throw new Exception("V5: некорректная длина.");
            return bi;
        }

        static byte[] BytesToBits(byte[] data)
        {
            byte[] bits = new byte[data.Length * 8];
            for (int i = 0; i < data.Length; i++)
                for (int b = 0; b < 8; b++) bits[i * 8 + b] = (byte)((data[i] >> (7 - b)) & 1);
            return bits;
        }
        static byte[] BitsToBytes(byte[] bits)
        {
            int nb = bits.Length / 8;
            byte[] data = new byte[nb];
            for (int i = 0; i < nb; i++)
            {
                int v = 0;
                for (int b = 0; b < 8; b++) v = (v << 1) | (bits[i * 8 + b] & 1);
                data[i] = (byte)v;
            }
            return data;
        }

        static (byte[] salt, byte[] nonce, byte[] tag, byte[] placementNonce, byte[] ciphertext) PrepareV5(string inputFile, byte[] password)
        {
            byte[] raw = File.ReadAllBytes(inputFile);
            byte[] name = Encoding.UTF8.GetBytes(Path.GetFileName(inputFile));
            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var zip = new GZipStream(ms, CompressionLevel.Optimal))
                {
                    zip.Write(Encoding.ASCII.GetBytes(MagicV5));
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
            byte[] ciphertext, nonce, tag;
            try
            {
                using var aes = new AesGcm(key, TagSize);
                nonce = RandomNumberGenerator.GetBytes(NonceSize);
                ciphertext = new byte[compressed.Length];
                tag = new byte[TagSize];
                aes.Encrypt(nonce, compressed, ciphertext, tag);
            }
            finally { Array.Clear(key, 0, key.Length); Array.Clear(compressed, 0, compressed.Length); }

            byte[] placementNonce = RandomNumberGenerator.GetBytes(PlacementNonceSize);
            return (salt, nonce, tag, placementNonce, ciphertext);
        }

        static (string name, byte[] data) DecryptCipher(byte[] ciphertext, BootstrapInfo bi, byte[] password)
        {
            byte[] key = CryptoCore.DeriveContentKey(password, bi.Salt, bi.MemKiB, bi.Iter, bi.Par);
            byte[] plain = new byte[ciphertext.Length];
            byte[]? memBuf = null;
            try
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Decrypt(bi.GcmNonce, ciphertext, bi.GcmTag, plain);
                using var ms = new MemoryStream(plain);
                using var zip = new GZipStream(ms, CompressionMode.Decompress);
                using var mem = new MemoryStream();
                zip.CopyTo(mem); mem.Position = 0; memBuf = mem.GetBuffer();
                using var br = new BinaryReader(mem);
                string sig = Encoding.ASCII.GetString(br.ReadBytes(MagicV5.Length));
                if (sig != MagicV5) throw new Exception($"V5: неподдерживаемая версия формата (ожидается {MagicV5}).");
                int nLen = br.ReadInt32();
                if (nLen < 0 || nLen > mem.Length - mem.Position) throw new Exception("V5: повреждённая длина имени.");
                string name = Encoding.UTF8.GetString(br.ReadBytes(nLen));
                long fLen = br.ReadInt64();
                if (fLen < 0 || fLen > mem.Length - mem.Position) throw new Exception("V5: повреждённый размер файла.");
                byte[] data = br.ReadBytes((int)fLen);
                return (name, data);
            }
            catch (CryptographicException)
            {
                throw new Exception("V5: не удалось расшифровать (неверный пароль / повреждённый / неполный / переставленный набор картинок).");
            }
            finally { Array.Clear(key, 0, key.Length); Array.Clear(plain, 0, plain.Length); if (memBuf != null) Array.Clear(memBuf, 0, memBuf.Length); }
        }

        static bool Eq(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static byte[] GetPlane(Image<Rgb24> img, int channel)
        {
            int W = img.Width, H = img.Height;
            byte[] p = new byte[W * H];
            for (int y = 0; y < H; y++)
                for (int x = 0; x < W; x++)
                {
                    Rgb24 px = img[x, y];
                    p[y * W + x] = channel == 0 ? px.R : channel == 1 ? px.G : px.B;
                }
            return p;
        }

        static void SetPlane(Image<Rgb24> img, int channel, byte[] p)
        {
            int W = img.Width, H = img.Height;
            for (int y = 0; y < H; y++)
                for (int x = 0; x < W; x++)
                {
                    Rgb24 px = img[x, y];
                    byte v = p[y * W + x];
                    if (channel == 0) px.R = v; else if (channel == 1) px.G = v; else px.B = v;
                    img[x, y] = px;
                }
        }

        static void WriteBootstrapRegion(Image<Rgb24> image, byte[] boot)
        {
            int slots = BootstrapReservePixels * 3;
            int bits = boot.Length * 8;
            byte[] rnd = RandomNumberGenerator.GetBytes(slots);
            for (int s = 0; s < slots; s++)
            {
                int pixel = s / 3, ch = s % 3;
                int bit = (s < bits) ? ((boot[s / 8] >> (7 - (s % 8))) & 1) : (rnd[s] & 1);
                int x = pixel % image.Width, y = pixel / image.Width;
                Rgb24 p = image[x, y];
                if (ch == 0) p.R = ImageIo.ApplySecureLsb(p.R, bit, rnd[s]);
                else if (ch == 1) p.G = ImageIo.ApplySecureLsb(p.G, bit, rnd[s]);
                else p.B = ImageIo.ApplySecureLsb(p.B, bit, rnd[s]);
                image[x, y] = p;
            }
        }

        static byte[] ReadBootstrapRegion(Image<Rgb24> image)
        {
            int bits = BootstrapSize * 8;
            byte[] boot = new byte[BootstrapSize];
            for (int s = 0; s < bits; s++)
            {
                int pixel = s / 3, ch = s % 3;
                int x = pixel % image.Width, y = pixel / image.Width;
                Rgb24 p = image[x, y];
                int bit = (ch == 0) ? (p.R & 1) : (ch == 1) ? (p.G & 1) : (p.B & 1);
                if (bit != 0) boot[s / 8] |= (byte)(1 << (7 - (s % 8)));
            }
            return boot;
        }

        static void BuildPlaneMeta(Image<Rgb24>[] imgs, int stcWidth,
            out int[] imgIdx, out int[] chan, out int[] reserve, out int[] pw, out int[] ph, out int[] caps)
        {
            int numPlanes = imgs.Length * 3;
            imgIdx = new int[numPlanes]; chan = new int[numPlanes]; reserve = new int[numPlanes];
            pw = new int[numPlanes]; ph = new int[numPlanes]; caps = new int[numPlanes];
            for (int i = 0; i < imgs.Length; i++)
                for (int c = 0; c < 3; c++)
                {
                    int p = i * 3 + c;
                    imgIdx[p] = i; chan[p] = c;
                    reserve[p] = (i == 0) ? BootstrapReservePixels : 0;
                    pw[p] = imgs[i].Width; ph[p] = imgs[i].Height;
                    int np = pw[p] * ph[p];
                    int cap = (np - reserve[p]) / stcWidth;
                    caps[p] = cap < 0 ? 0 : cap;
                }
        }

        public static void EncryptV5(string inputFile, List<string> donorPaths, byte[] password)
        {
            ImageIo.WarnIfLossyDonors(donorPaths);
            Console.Write("[*] V5 шифрование AES-GCM... ");
            var (salt, gnonce, gtag, placementNonce, ciphertext) = PrepareV5(inputFile, password);
            byte[] placementMaster = HKDF.DeriveKey(HashAlgorithmName.SHA256, password, 32, placementNonce, Encoding.UTF8.GetBytes(HkdfPlacement));
            byte[] cipherBits = BytesToBits(ciphertext);
            Console.WriteLine($"шифртекст {ciphertext.Length:N0} Б ({cipherBits.Length:N0} бит).");

            Image<Rgb24>[] imgs = new Image<Rgb24>[donorPaths.Count];
            List<string> outPaths = new List<string>();
            try
            {
                for (int i = 0; i < donorPaths.Count; i++) imgs[i] = Image.Load<Rgb24>(donorPaths[i]);

                // Авто-выбор ширины STC: самая скрытная (низкий bpp), при которой payload ещё влезает.
                // Ёмкость считаем точно как BuildPlaneMeta: сумма floor((пиксели_плоскости - резерв)/w) по всем планам.
                int chosenW = 0;
                foreach (int cand in WidthLadder)
                {
                    long capW = 0;
                    for (int i = 0; i < imgs.Length; i++)
                    {
                        int npp = imgs[i].Width * imgs[i].Height;
                        for (int c = 0; c < 3; c++)
                        {
                            int res = (i == 0) ? BootstrapReservePixels : 0;
                            int cap = (npp - res) / cand;
                            if (cap > 0) capW += cap;
                        }
                    }
                    if (cipherBits.Length <= capW) { chosenW = cand; break; }
                }
                if (chosenW == 0)
                {
                    int densest = WidthLadder[WidthLadder.Length - 1];
                    throw new Exception($"Не хватает ёмкости даже при максимальном bpp≈{1.0 / densest:0.000} (w={densest}): нужно {cipherBits.Length} бит. Возьмите больше/крупнее картинок.");
                }
                int[] cols = ColsForWidth(chosenW);

                if ((long)imgs[0].Width * imgs[0].Height < BootstrapReservePixels)
                    throw new Exception($"Первая картинка слишком мала для V5 (нужно >= {BootstrapReservePixels} пикселей для bootstrap).");
                if (chosenW < StcWidth)
                    Console.WriteLine($"[!] ВНИМАНИЕ: авто-выбран bpp≈{1.0 / chosenW:0.000} (w={chosenW}) — плотнее дефолтного 0.20, скрытность ниже. Возьмите больше/крупнее картинок для меньшего bpp.");

                byte[] bootstrap = PackBootstrap(salt, gnonce, gtag, placementNonce, ciphertext.Length, chosenW);

                BuildPlaneMeta(imgs, chosenW, out int[] pImg, out int[] pCh, out int[] pRes, out int[] pW, out int[] pH, out int[] pCap);
                int numPlanes = imgs.Length * 3;

                int[] order = KeyedPlaneOrder(numPlanes, placementMaster);
                int[] mlens = SplitLengths(cipherBits.Length, pCap, order);

                WriteBootstrapRegion(imgs[0], bootstrap);

                int pos = 0;
                foreach (int p in order)
                {
                    int mk = mlens[p]; if (mk == 0) continue;
                    byte[] msg = new byte[mk]; Array.Copy(cipherBits, pos, msg, 0, mk); pos += mk;
                    byte[] plane = GetPlane(imgs[pImg[p]], pCh[p]);
                    int[] perm = KeyedPerm(plane.Length - pRes[p], placementMaster, $"SCP-v5-plane-{p}");
                    EmbedPlane(plane, pW[p], pH[p], msg, perm, pRes[p], cols);
                    SetPlane(imgs[pImg[p]], pCh[p], plane);
                }

                Console.Write("[*] Сохранение PNG... ");
                for (int i = 0; i < donorPaths.Count; i++)
                {
                    string dir = Path.GetDirectoryName(donorPaths[i]) ?? "";
                    string outPath = Path.Combine(dir, "stego_" + Path.GetFileNameWithoutExtension(donorPaths[i]) + ".png");
                    ImageIo.CleanMetadataAndSave(imgs[i], donorPaths[i], outPath);
                    ImageIo.Timestomp(donorPaths[i], outPath);
                    outPaths.Add(outPath);
                }
                Console.WriteLine("Готово.");

                Console.Write("[*] Самопроверка round-trip... ");
                var (vname, vdata) = DecryptToMemory(outPaths, password);
                byte[] original = File.ReadAllBytes(inputFile);
                bool ok = vdata.Length == original.Length;
                if (ok) for (int i = 0; i < original.Length; i++) if (vdata[i] != original[i]) { ok = false; break; }
                Array.Clear(original, 0, original.Length);
                if (!ok) throw new Exception("V5 self-verify ПРОВАЛ: извлечённые данные не совпали с оригиналом.");
                Console.WriteLine("OK.");

                Console.WriteLine($"[+] V5 готово. Файлов: {outPaths.Count}. bpp≈{1.0 / chosenW:0.000} (w={chosenW}). ВНИМАНИЕ: V5 не скрывает размер payload.");
                foreach (var op in outPaths) Console.WriteLine("    " + op);
            }
            finally
            {
                for (int i = 0; i < imgs.Length; i++) imgs[i]?.Dispose();
            }
        }

        static (string name, byte[] data) DecryptToMemory(List<string> stegoPaths, byte[] password)
        {
            BootstrapInfo bi;
            using (var img0 = Image.Load<Rgb24>(stegoPaths[0]))
                bi = UnpackBootstrap(ReadBootstrapRegion(img0));
            byte[] placementMaster = HKDF.DeriveKey(HashAlgorithmName.SHA256, password, 32, bi.PlacementNonce, Encoding.UTF8.GetBytes(HkdfPlacement));
            int cipherLen = bi.TotalLen;
            int totalBits = cipherLen * 8;

            Image<Rgb24>[] imgs = new Image<Rgb24>[stegoPaths.Count];
            try
            {
                for (int i = 0; i < stegoPaths.Count; i++) imgs[i] = Image.Load<Rgb24>(stegoPaths[i]);
                int[] cols = ColsForWidth(bi.Width);
                BuildPlaneMeta(imgs, bi.Width, out int[] pImg, out int[] pCh, out int[] pRes, out int[] pW, out int[] pH, out int[] pCap);
                int numPlanes = imgs.Length * 3;
                long totalCap = 0; foreach (int cc in pCap) totalCap += cc;
                if (totalBits > totalCap) throw new Exception("V5: набор картинок не вмещает заявленную длину (повреждение/неполный набор).");

                int[] order = KeyedPlaneOrder(numPlanes, placementMaster);
                int[] mlens = SplitLengths(totalBits, pCap, order);

                byte[] cipherBits = new byte[totalBits];
                int rpos = 0;
                foreach (int p in order)
                {
                    int mk = mlens[p]; if (mk == 0) continue;
                    byte[] plane = GetPlane(imgs[pImg[p]], pCh[p]);
                    int[] perm = KeyedPerm(plane.Length - pRes[p], placementMaster, $"SCP-v5-plane-{p}");
                    byte[] bits = ExtractPlaneBits(plane, perm, mk, pRes[p], cols);
                    Array.Copy(bits, 0, cipherBits, rpos, mk); rpos += mk;
                }
                byte[] ciphertext = BitsToBytes(cipherBits);
                if (ciphertext.Length != cipherLen)
                {
                    byte[] trimmed = new byte[cipherLen];
                    Array.Copy(ciphertext, trimmed, Math.Min(cipherLen, ciphertext.Length));
                    ciphertext = trimmed;
                }
                return DecryptCipher(ciphertext, bi, password);
            }
            finally { for (int i = 0; i < imgs.Length; i++) imgs[i]?.Dispose(); }
        }

        public static void DecryptV5(List<string> stegoPaths, byte[] password)
        {
            Console.Write("[*] V5 извлечение... ");
            var (name, data) = DecryptToMemory(stegoPaths, password);
            Console.WriteLine("Готово.");
            string safe = Path.GetFileName(name);
            if (string.IsNullOrWhiteSpace(safe)) safe = "recovered_file.bin";
            string outPath = Path.Combine(Directory.GetCurrentDirectory(), safe);
            File.WriteAllBytes(outPath, data);
            Console.WriteLine($"[+] Восстановлено: {outPath} ({data.Length:N0} Б).");
        }

        // ===== Тест-векторы =====
        static readonly byte[] V0_x = new byte[] { 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0 };
        static readonly double[] V0_rho = new double[] { 8, 88, 47, 70, 22, 33, 12, 73, 77, 22, 71, 9, 39, 16, 74, 34, 47, 47, 48, 27, 56, 81, 50, 20, 3, 13, 9, 10, 13, 60 };
        static readonly byte[] V0_msg = new byte[] { 1, 1, 1, 1, 0, 1 };
        static readonly byte[] V0_y = new byte[] { 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0 };

        static readonly byte[] V1_x = new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1 };
        static readonly double[] V1_rho = new double[] { 4, 18, 39, 31, 95, 44, 65, 15, 80, 22, 76, 47, 41, 48, 54, 26, 13, 30, 98, 28, 67, 26, 83, 48, 57, 21, 61, 50, 71, 25, 61, 84, 47, 18, 8, 86, 50, 18, 30, 75 };
        static readonly byte[] V1_msg = new byte[] { 0, 1, 1, 0, 1, 1, 0, 0 };
        static readonly byte[] V1_y = new byte[] { 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1 };

        static readonly byte[] V2_x = new byte[] { 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1 };
        static readonly double[] V2_rho = new double[] { 7, 34, 17, 28, 13, 28, 35, 9, 35, 48, 10, 88, 87, 94, 12, 3, 96, 91, 80, 13, 67, 75, 29, 89, 75, 17, 58, 33, 78, 38, 86, 35, 66, 52, 42, 1, 98, 42, 34, 87, 1, 9, 47, 48, 85, 48, 70, 78, 27, 96, 94, 71, 5, 28, 14, 67, 3, 35, 1, 77 };
        static readonly byte[] V2_msg = new byte[] { 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1 };
        static readonly byte[] V2_y = new byte[] { 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1 };

        static readonly int[,] HillPts = new int[,] { { 16, 16 }, { 12, 20 }, { 20, 12 }, { 10, 22 }, { 22, 10 } };
        static readonly double[] HillExp = new double[] { 0.00571902, 0.00620497, 0.00741679, 0.00700120, 100000000.00000000 };
		static readonly double HillSum = 54200000002.672363;
    }
}