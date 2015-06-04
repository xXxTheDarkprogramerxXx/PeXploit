namespace edatat
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Media;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Linq;

    internal class pkg2sfo
    {
        private byte[] AesKey = new byte[0x10];
        public string line;
        private byte[] Name2 = ConversionUtils.getByteArray("504152414d2e53464f");
        private byte[] PKGFileKey = new byte[0x10];
        private byte[] PS3AesKey = new byte[] { 0x2e, 0x7b, 0x71, 0xd7, 0xc9, 0xc9, 0xa1, 0x4e, 0xa3, 0x22, 0x1f, 0x18, 0x88, 40, 0xb8, 0xf8 };
        private byte[] PSPAesKey = new byte[] { 7, 0xf2, 0xc6, 130, 0x90, 0xb5, 13, 0x2c, 0x33, 0x81, 0x8d, 0x70, 0x9b, 0x60, 230, 0x2b };
        public string trash;
        private uint uiEncryptedFileStartOffset = 0;

        public static string ByteArrayToAscii(byte[] ByteArray, int startPos, int length, bool cleanEndOfString)
        {
            byte[] destinationArray = new byte[length];
            Array.Copy(ByteArray, startPos, destinationArray, 0, destinationArray.Length);
            return HexStringToAscii(ByteArrayToHexString(destinationArray), true);
        }

        public static string ByteArrayToHexString(byte[] ByteArray)
        {
            string str = "";
            for (int i = 0; i < ByteArray.Length; i++)
            {
                str = str + ByteArray[i].ToString("X2");
            }
            return str;
        }

        private byte[] DecryptData(int dataSize, long dataRelativeOffset, long pkgEncryptedFileStartOffset, byte[] AesKey, Stream encrPKGReadStream, BinaryReader brEncrPKG)
        {
            int num2;
            int count = dataSize % 0x10;
            if (count > 0)
            {
                count = ((dataSize / 0x10) + 1) * 0x10;
            }
            else
            {
                count = dataSize;
            }
            byte[] inByteArray = new byte[count];
            byte[] buffer2 = new byte[count];
            byte[] destinationArray = new byte[count];
            byte[] xORKey = new byte[count];
            byte[] buffer5 = new byte[this.PKGFileKey.Length];
            Array.Copy(this.PKGFileKey, buffer5, this.PKGFileKey.Length);
            encrPKGReadStream.Seek(dataRelativeOffset + pkgEncryptedFileStartOffset, SeekOrigin.Begin);
            inByteArray = brEncrPKG.ReadBytes(count);
            for (num2 = 0; num2 < dataRelativeOffset; num2 += 0x10)
            {
                this.IncrementArray(ref buffer5, this.PKGFileKey.Length - 1);
            }
            for (num2 = 0; num2 < count; num2 += 0x10)
            {
                Array.Copy(buffer5, 0, destinationArray, num2, this.PKGFileKey.Length);
                this.IncrementArray(ref buffer5, this.PKGFileKey.Length - 1);
            }
            xORKey = AESEngine.Encrypt(destinationArray, AesKey, AesKey, CipherMode.ECB, PaddingMode.None);
            return XOREngine.XOR(inByteArray, 0, xORKey.Length, xORKey);
        }

        public string DecryptPKGFile(string PKGFileName)
        {
            if (!File.Exists(PKGFileName))
            {
                Console.WriteLine(PKGFileName + " not found");
                return PKGFileName;
            }
            try
            {
                int num = 0x10000;
                byte[] inByteArray = new byte[this.AesKey.Length * num];
                byte[] buffer = new byte[this.AesKey.Length * num];
                byte[] buffer3 = new byte[this.AesKey.Length];
                byte[] array = new byte[4];
                byte[] buffer5 = new byte[4];
                Stream input = new FileStream(PKGFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                BinaryReader reader = new BinaryReader(input);
                input.Seek(0L, SeekOrigin.Begin);
                byte[] buffer6 = reader.ReadBytes(4);
                if ((((buffer6[0] != 0x7f) || (buffer6[1] != 80)) || (buffer6[2] != 0x4b)) || (buffer6[3] != 0x47))
                {
                    SystemSounds.Beep.Play();
                    return string.Empty;
                }
                input.Seek(4L, SeekOrigin.Begin);
                if (reader.ReadByte() != 0x80)
                {
                    SystemSounds.Beep.Play();
                    SystemSounds.Beep.Play();
                }
                input.Seek(7L, SeekOrigin.Begin);
                switch (reader.ReadByte())
                {
                    case 1:
                        this.AesKey = this.PS3AesKey;
                        break;

                    case 2:
                        this.AesKey = this.PSPAesKey;
                        break;

                    default:
                        SystemSounds.Beep.Play();
                        return string.Empty;
                }
                input.Seek(0x24L, SeekOrigin.Begin);
                array = reader.ReadBytes(array.Length);
                Array.Reverse(array);
                this.uiEncryptedFileStartOffset = BitConverter.ToUInt32(array, 0);
                input.Seek(0x2cL, SeekOrigin.Begin);
                buffer5 = reader.ReadBytes(buffer5.Length);
                Array.Reverse(buffer5);
                uint num4 = BitConverter.ToUInt32(buffer5, 0);
                input.Seek(0x70L, SeekOrigin.Begin);
                this.PKGFileKey = reader.ReadBytes(0x10);
                byte[] destinationArray = new byte[0x10];
                Array.Copy(this.PKGFileKey, destinationArray, this.PKGFileKey.Length);
                buffer3 = AESEngine.Encrypt(this.PKGFileKey, this.AesKey, this.AesKey, CipherMode.ECB, PaddingMode.None);
                double d = ((double) num4) / ((double) this.AesKey.Length);
                ulong num6 = (ulong) Math.Floor(d);
                ulong num7 = ((ulong) num4) / ((ulong) this.AesKey.Length);
                if (num7 > 0L)
                {
                    num6 += (ulong) 1L;
                }
                if (File.Exists(PKGFileName + ".Dec"))
                {
                    File.Delete(PKGFileName + ".Dec");
                }
                FileStream output = new FileStream(PKGFileName + ".Dec", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
                BinaryWriter writer = new BinaryWriter(output);
                input.Seek((long) this.uiEncryptedFileStartOffset, SeekOrigin.Begin);
                double num8 = ((double) num4) / ((double) (this.AesKey.Length * num));
                ulong num9 = (ulong) Math.Floor(num8);
                ulong num10 = ((ulong) num4) % ((ulong) (this.AesKey.Length * num));
                if (num10 > 0L)
                {
                    num9 += (ulong) 1L;
                }
                for (ulong i = 0L; i < 10L; i += (ulong) 1L)
                {
                    if ((num10 > 0L) && (i == (num9 - ((ulong) 1L))))
                    {
                        inByteArray = new byte[num10];
                        buffer = new byte[num10];
                    }
                    inByteArray = reader.ReadBytes(inByteArray.Length);
                    byte[] buffer8 = new byte[inByteArray.Length];
                    byte[] xORKey = new byte[inByteArray.Length];
                    Console.WriteLine("Decrypting");
                    for (int j = 0; j < inByteArray.Length; j += this.AesKey.Length)
                    {
                        Array.Copy(destinationArray, 0, buffer8, j, this.PKGFileKey.Length);
                        this.IncrementArray(ref destinationArray, this.PKGFileKey.Length - 1);
                    }
                    xORKey = AESEngine.Encrypt(buffer8, this.AesKey, this.AesKey, CipherMode.ECB, PaddingMode.None);
                    buffer = XOREngine.XOR(inByteArray, 0, xORKey.Length, xORKey);
                    writer.Write(buffer);
                }
                output.Close();
                writer.Close();
                return this.ExtractFiles(PKGFileName + ".Dec", PKGFileName);
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        private string ExtractFiles(string decryptedPKGFileName, string encryptedPKGFileName)
        {
            Exception exception;
            try
            {
                int num = 0x1400000;
                uint num2 = 0;
                uint num3 = 0;
                uint num4 = 0;
                long sourceIndex = 0L;
                string str = null;
                if (encryptedPKGFileName.Contains(@"\"))
                {
                    str = encryptedPKGFileName.Substring(encryptedPKGFileName.LastIndexOf(@"\")).Replace(@"\", "").Replace(".pkg", "");
                }
                else
                {
                    str = encryptedPKGFileName.Replace(".pkg", "");
                }
                string path = "temp/" + str;
                Directory.CreateDirectory("temp");
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                    Thread.Sleep(100);
                    Directory.CreateDirectory(path);
                    Thread.Sleep(100);
                }
                byte[] sourceArray = new byte[0x4e200];
                byte[] buffer3 = new byte[8];
                byte[] destinationArray = new byte[4];
                byte[] buffer5 = new byte[4];
                byte[] buffer6 = new byte[4];
                byte[] buffer7 = new byte[4];
                byte[] buffer8 = new byte[4];
                byte[] buffer9 = new byte[4];
                byte[] buffer10 = new byte[4];
                byte[] buffer11 = new byte[4];
                byte[] buffer12 = new byte[0x20];
                byte[] buffer13 = new byte[8];
                byte num6 = 0;
                byte num7 = 0;
                bool flag = false;
                Stream input = new FileStream(decryptedPKGFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                BinaryReader reader = new BinaryReader(input);
                Stream stream2 = new FileStream(encryptedPKGFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                BinaryReader brEncrPKG = new BinaryReader(stream2);
                input.Seek(0L, SeekOrigin.Begin);
                sourceArray = reader.ReadBytes(sourceArray.Length);
                sourceIndex = 0L;
                num4 = 0;
                Array.Copy(sourceArray, 0, buffer5, 0, buffer5.Length);
                Array.Reverse(buffer5);
                uint num9 = BitConverter.ToUInt32(buffer5, 0) / 0x20;
                Array.Copy(sourceArray, 12, destinationArray, 0, destinationArray.Length);
                Array.Reverse(destinationArray);
                uint num10 = BitConverter.ToUInt32(destinationArray, 0);
                input.Seek(0L, SeekOrigin.Begin);
                sourceArray = reader.ReadBytes((int) num10);
                if (num9 < 0)
                {
                    return "";
                }
                for (int i = 0; i < num9; i++)
                {
                    byte[] buffer2;
                    BinaryWriter writer;
                    double num14;
                    ulong num15;
                    ulong num16;
                    ulong num17;
                    Array.Copy(sourceArray, sourceIndex + 12L, buffer8, 0L, (long) buffer8.Length);
                    Array.Reverse(buffer8);
                    num2 = BitConverter.ToUInt32(buffer8, 0) + num4;
                    Array.Copy(sourceArray, sourceIndex + 20L, buffer9, 0L, (long) buffer9.Length);
                    Array.Reverse(buffer9);
                    num3 = BitConverter.ToUInt32(buffer9, 0);
                    Array.Copy(sourceArray, sourceIndex, buffer10, 0L, (long) buffer10.Length);
                    Array.Reverse(buffer10);
                    uint num12 = BitConverter.ToUInt32(buffer10, 0);
                    Array.Copy(sourceArray, sourceIndex + 4L, buffer11, 0L, (long) buffer11.Length);
                    Array.Reverse(buffer11);
                    uint num13 = BitConverter.ToUInt32(buffer11, 0);
                    num6 = sourceArray[(int) ((IntPtr) (sourceIndex + 0x18L))];
                    num7 = sourceArray[(int) ((IntPtr) (sourceIndex + 0x1bL))];
                    buffer12 = new byte[num13];
                    Array.Copy(sourceArray, (long) num12, buffer12, 0L, (long) num13);
                    string str5 = ByteArrayToAscii(buffer12, 0, buffer12.Length, true);
                    string str6 = string.Concat((IEnumerable<string>) (from b in buffer12 select b.ToString("x2")));
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                        Thread.Sleep(100);
                    }
                    FileStream output = null;
                    if ((num7 == 4) && (num3 == 0))
                    {
                        flag = false;
                    }
                    else
                    {
                        flag = true;
                    }
                    if (num6 == 0x90)
                    {
                        string str7 = (path + @"\" + str5).Replace("/", @"\");
                        DirectoryInfo parent = Directory.GetParent(str7);
                        if (!Directory.Exists(parent.ToString()))
                        {
                            Directory.CreateDirectory(parent.ToString());
                        }
                        output = new FileStream(str7, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
                    }
                    else
                    {
                        Array.Copy(this.DecryptData((int) num13, (long) num12, (long) this.uiEncryptedFileStartOffset, this.PS3AesKey, stream2, brEncrPKG), 0L, buffer12, 0L, (long) num13);
                        str5 = ByteArrayToAscii(buffer12, 0, buffer12.Length, true);
                        if (!flag)
                        {
                            try
                            {
                            }
                            catch (Exception exception1)
                            {
                                exception = exception1;
                                str5 = i.ToString() + ".raw";
                            }
                        }
                        else if (str5 == "PARAM.SFO")
                        {
                            try
                            {
                                output = new FileStream(path + @"\" + str5, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
                            }
                            catch (Exception exception2)
                            {
                                exception = exception2;
                                str5 = i.ToString() + ".raw";
                            }
                        }
                    }
                    if (((num6 == 0x90) && flag) && (str5 == "PARAM.SFO"))
                    {
                        writer = new BinaryWriter(output);
                        input.Seek((long) num2, SeekOrigin.Begin);
                        num14 = ((double) num3) / ((double) num);
                        num15 = (ulong) Math.Floor(num14);
                        num16 = ((ulong) num3) % ((ulong) num);
                        if (num16 > 0L)
                        {
                            num15 += (ulong) 1L;
                        }
                        buffer2 = new byte[num];
                        num17 = 0L;
                        while (num17 < num15)
                        {
                            if ((num16 > 0L) && (num17 == (num15 - ((ulong) 1L))))
                            {
                                buffer2 = new byte[num16];
                            }
                            reader.Read(buffer2, 0, buffer2.Length);
                            writer.Write(buffer2);
                            num17 += (ulong) 1L;
                        }
                        output.Close();
                        writer.Close();
                    }
                    if (((num6 != 0x90) && flag) && (str5 == "PARAM.SFO"))
                    {
                        writer = new BinaryWriter(output);
                        input.Seek((long) num2, SeekOrigin.Begin);
                        num14 = ((double) num3) / ((double) num);
                        num15 = (ulong) Math.Floor(num14);
                        num16 = ((ulong) num3) % ((ulong) num);
                        if (num16 > 0L)
                        {
                            num15 += (ulong) 1L;
                        }
                        buffer2 = new byte[num];
                        long length = 0L;
                        for (num17 = 0L; num17 < num15; num17 += (ulong) 1L)
                        {
                            if ((num16 > 0L) && (num17 == (num15 - ((ulong) 1L))))
                            {
                                buffer2 = new byte[num16];
                            }
                            byte[] buffer = this.DecryptData(buffer2.Length, num2 + length, (long) this.uiEncryptedFileStartOffset, this.PS3AesKey, stream2, brEncrPKG);
                            length = buffer2.Length;
                            writer.Write(buffer, 0, buffer2.Length);
                        }
                        output.Close();
                        writer.Close();
                    }
                    sourceIndex += 0x20L;
                }
                stream2.Close();
                brEncrPKG.Close();
                input.Close();
                reader.Close();
                if (File.Exists(decryptedPKGFileName))
                {
                    File.Delete(decryptedPKGFileName);
                }
                Console.WriteLine("Creating EDAT");
                string outFile = null;
                C00EDAT cedat = new C00EDAT();
                return cedat.makeedat(path + "/PARAM.SFO", outFile);
            }
            catch (Exception exception3)
            {
                exception = exception3;
                SystemSounds.Beep.Play();
                return "";
            }
        }

        public static string HexStringToAscii(string HexString, bool cleanEndOfString)
        {
            try
            {
                string str = "";
                while (HexString.Length > 0)
                {
                    str = str + Convert.ToChar(Convert.ToUInt32(HexString.Substring(0, 2), 0x10)).ToString();
                    HexString = HexString.Substring(2, HexString.Length - 2);
                }
                if (cleanEndOfString)
                {
                    str = str.Replace("\0", "");
                }
                return str;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private bool IncrementArray(ref byte[] sourceArray, int position)
        {
            if (sourceArray[position] == 0xff)
            {
                if (position != 0)
                {
                    if (this.IncrementArray(ref sourceArray, position - 1))
                    {
                        sourceArray[position] = 0;
                        return true;
                    }
                    return false;
                }
                return false;
            }
            sourceArray[position] = (byte) (sourceArray[position] + 1);
            return true;
        }
    }
}

