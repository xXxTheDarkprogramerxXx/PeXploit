namespace edatat
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Numerics;
    using System.Runtime.CompilerServices;

    public class EDAT
    {
        public static long FLAG_0x02 = 2L;
        public static long FLAG_0x10 = 0x10L;
        public static long FLAG_0x20 = 0x20L;
        public static long FLAG_COMPRESSED = 1L;
        public static long FLAG_DEBUG = 0x80000000L;
        public static long FLAG_KEYENCRYPTED = 8L;
        public static long FLAG_SDAT = 0x1000000L;
        private static int HEADER_MAX_BLOCKSIZE = 0x3c00;
        public static int STATUS_ERROR_DECRYPTING = -5;
        public static int STATUS_ERROR_HASHDEVKLIC = -2;
        public static int STATUS_ERROR_HASHTITLEIDNAME = -1;
        public static int STATUS_ERROR_HEADERCHECK = -4;
        public static int STATUS_ERROR_INCORRECT_FLAGS = -6;
        public static int STATUS_ERROR_INCORRECT_VERSION = -7;
        public static int STATUS_ERROR_INPUTFILE_IO = -100;
        public static int STATUS_ERROR_MISSINGKEY = -3;
        public static int STATUS_OK = 0;

        private byte[] calculateBlockKey(int blk, NPD npd)
        {
            byte[] src = (npd.getVersion() <= 1L) ? new byte[0x10] : npd.getDevHash();
            byte[] dest = new byte[0x10];
            ConversionUtils.arraycopy(src, 0, dest, 0L, 12);
            dest[12] = (byte) ((blk >> 0x18) & 0xff);
            dest[13] = (byte) ((blk >> 0x10) & 0xff);
            dest[14] = (byte) ((blk >> 8) & 0xff);
            dest[15] = (byte) (blk & 0xff);
            return dest;
        }

        private int checkHeader(byte[] rifKey, EDATData data, NPD npd, FileStream i)
        {
            int num8;
            i.Seek(0L, SeekOrigin.Begin);
            byte[] buffer = new byte[160];
            byte[] o = new byte[160];
            byte[] buffer3 = new byte[0x10];
            Console.WriteLine("Checking NPD Version:" + npd.getVersion());
            if ((npd.getVersion() == 0L) || (npd.getVersion() == 1L))
            {
                if ((data.getFlags() & 0x7ffffffeL) != 0L)
                {
                    Console.WriteLine("ERROR: Incorrect Header Flags");
                    return STATUS_ERROR_INCORRECT_FLAGS;
                }
            }
            else if (npd.getVersion() == 2L)
            {
                if ((data.getFlags() & 0x7effffe0L) != 0L)
                {
                    Console.WriteLine("ERROR: Incorrect Header Flags");
                    return STATUS_ERROR_INCORRECT_FLAGS;
                }
            }
            else if ((npd.getVersion() == 3L) || (npd.getVersion() == 4L))
            {
                if ((data.getFlags() & 0x7effffc0L) != 0L)
                {
                    Console.WriteLine("ERROR: Incorrect Header Flags");
                    return STATUS_ERROR_INCORRECT_FLAGS;
                }
            }
            else
            {
                Console.WriteLine("ERROR: Unsupported EDAT version (need keys)");
                return STATUS_ERROR_INCORRECT_VERSION;
            }
            if (npd.getVersion() == 4L)
            {
            }
            i.Read(buffer, 0, buffer.Length);
            i.Read(buffer3, 0, buffer3.Length);
            Console.WriteLine("Checking header hash:");
            AppLoader loader = new AppLoader();
            int hashFlag = ((data.getFlags() & FLAG_KEYENCRYPTED) == 0L) ? 2 : 0x10000002;
            if ((data.getFlags() & FLAG_DEBUG) != 0L)
            {
                hashFlag |= 0x1000000;
            }
            if (!loader.doAll(hashFlag, 1, buffer, 0, o, 0, buffer.Length, new byte[0x10], new byte[0x10], rifKey, buffer3, 0))
            {
                Console.WriteLine("Error verifying header. Is rifKey valid?.");
                return STATUS_ERROR_HEADERCHECK;
            }
            Console.WriteLine("Checking metadata hash:");
            loader = new AppLoader();
            loader.doInit(hashFlag, 1, new byte[0x10], new byte[0x10], rifKey);
            int num3 = ((data.getFlags() & FLAG_COMPRESSED) != 0L) ? 0x20 : 0x10;
            int num4 = (int) (((data.getFileLen() + data.getBlockSize()) - 11) / data.getBlockSize());
            int num5 = 0;
            int num6 = 0x100;
            for (long j = num3 * num4; j > 0L; j -= num8)
            {
                num8 = (HEADER_MAX_BLOCKSIZE > j) ? ((int) j) : HEADER_MAX_BLOCKSIZE;
                i.Seek((long) (num6 + num5), SeekOrigin.Begin);
                byte[] buffer4 = new byte[num8];
                o = new byte[num8];
                i.Read(buffer4, 0, buffer4.Length);
                loader.doUpdate(buffer4, 0, o, 0, num8);
                num5 += num8;
            }
            if (!loader.doFinal(buffer, 0x90))
            {
                Console.WriteLine("Error verifying metadatasection. Data tampered");
                return STATUS_ERROR_HEADERCHECK;
            }
            return STATUS_OK;
        }

        private bool checkNPDHash1(string filename, byte[] npd)
        {
            byte[] src = ConversionUtils.charsToByte(filename.ToCharArray());
            byte[] dest = new byte[0x30 + src.Length];
            ConversionUtils.arraycopy(npd, 0x10, dest, 0L, 0x30);
            ConversionUtils.arraycopy(src, 0, dest, 0x30L, src.Length);
            byte[] buffer3 = ToolsImpl.CMAC128(EDATKeys.npdrm_omac_key3, dest, 0, dest.Length);
            bool flag = this.compareBytes(buffer3, 0, npd, 80, 0x10);
            if (flag)
            {
                Console.WriteLine("NPD hash 1 is valid (" + ConversionUtils.getHexString(buffer3) + ")");
            }
            return flag;
        }

        private bool checkNPDHash2(byte[] klicensee, byte[] npd)
        {
            byte[] output = new byte[0x10];
            ToolsImpl.XOR(output, klicensee, EDATKeys.npdrm_omac_key2);
            byte[] buffer2 = ToolsImpl.CMAC128(output, npd, 0, 0x60);
            bool flag = this.compareBytes(buffer2, 0, npd, 0x60, 0x10);
            if (flag)
            {
                Console.WriteLine("NPD hash 2 is valid (" + ConversionUtils.getHexString(buffer2) + ")");
            }
            return flag;
        }

        private bool compareBytes(byte[] value1, int offset1, byte[] value2, int offset2, int len)
        {
            for (int i = 0; i < len; i++)
            {
                if (value1[i + offset1] != value2[i + offset2])
                {
                    return false;
                }
            }
            return true;
        }

        private byte[] createNPDHash1(string filename, byte[] npd)
        {
            byte[] src = ConversionUtils.charsToByte(filename.ToCharArray());
            byte[] dest = new byte[0x30 + src.Length];
            ConversionUtils.arraycopy(npd, 0x10, dest, 0L, 0x30);
            ConversionUtils.arraycopy(src, 0, dest, 0x30L, src.Length);
            byte[] buffer3 = ToolsImpl.CMAC128(EDATKeys.npdrm_omac_key3, dest, 0, dest.Length);
            ConversionUtils.arraycopy(buffer3, 0, npd, 80L, 0x10);
            if (this.compareBytes(buffer3, 0, npd, 80, 0x10))
            {
                return buffer3;
            }
            return null;
        }

        private byte[] createNPDHash2(byte[] klicensee, byte[] npd)
        {
            byte[] output = new byte[0x10];
            ToolsImpl.XOR(output, klicensee, EDATKeys.npdrm_omac_key2);
            byte[] src = ToolsImpl.CMAC128(output, npd, 0, 0x60);
            ConversionUtils.arraycopy(src, 0, npd, 0x60L, 0x10);
            if (this.compareBytes(src, 0, npd, 0x60, 0x10))
            {
                return src;
            }
            return null;
        }

        private int decryptData(FileStream ii, FileStream o, NPD npd, EDATData data, byte[] rifkey)
        {
            int num = (int) (((data.getFileLen() + data.getBlockSize()) - 1) / data.getBlockSize());
            int num2 = (((data.getFlags() & FLAG_COMPRESSED) != 0L) || ((data.getFlags() & FLAG_0x20) != 0L)) ? 0x20 : 0x10;
            int num3 = 0x100;
            for (int i = 0; i < num; i++)
            {
                long num5;
                int num6;
                byte[] buffer2;
                int num11;
                ii.Seek((long) (num3 + (i * num2)), SeekOrigin.Begin);
                byte[] dest = new byte[0x10];
                int num7 = 0;
                if ((data.getFlags() & FLAG_COMPRESSED) != 0L)
                {
                    buffer2 = new byte[0x20];
                    ii.Read(buffer2, 0, buffer2.Length);
                    byte[] buffer3 = this.decryptMetadataSection(buffer2);
                    num5 = (int) ConversionUtils.be64(buffer3, 0);
                    num6 = (int) ConversionUtils.be32(buffer3, 8);
                    num7 = (int) ConversionUtils.be32(buffer3, 12);
                    ConversionUtils.arraycopy(buffer2, 0, dest, 0L, 0x10);
                }
                else if ((data.getFlags() & FLAG_0x20) != 0L)
                {
                    buffer2 = new byte[0x20];
                    ii.Read(buffer2, 0, buffer2.Length);
                    for (int j = 0; j < 0x10; j++)
                    {
                        dest[j] = (byte) (buffer2[j] ^ buffer2[j + 0x10]);
                    }
                    num5 = (num3 + (i * data.getBlockSize())) + (num * num2);
                    num6 = (int) data.getBlockSize();
                    if (i == (num - 1))
                    {
                        num6 = (int) (data.getFileLen() % new BigInteger(data.getBlockSize()));
                    }
                }
                else
                {
                    ii.Read(dest, 0, dest.Length);
                    num5 = (num3 + (i * data.getBlockSize())) + (num * num2);
                    num6 = (int) data.getBlockSize();
                    if (i == (num - 1))
                    {
                        num6 = (int) (data.getFileLen() % new BigInteger(data.getBlockSize()));
                    }
                }
                int count = num6;
                num6 = (num6 + 15) & -16;
                Debug.Print("Offset: %016X, len: %08X, realLen: %08X, endCompress: %d\r\n", new object[] { num5, num6, count, num7 });
                ii.Seek(num5, SeekOrigin.Begin);
                byte[] buffer = new byte[num6];
                byte[] buffer5 = new byte[num6];
                ii.Read(buffer, 0, buffer.Length);
                byte[] buffer6 = new byte[0x10];
                byte[] buffer7 = new byte[0x10];
                byte[] buffer8 = this.calculateBlockKey(i, npd);
                ToolsImpl.aesecbEncrypt(rifkey, buffer8, 0, buffer6, 0, buffer8.Length);
                if ((data.getFlags() & FLAG_0x10) != 0L)
                {
                    ToolsImpl.aesecbEncrypt(rifkey, buffer6, 0, buffer7, 0, buffer6.Length);
                }
                else
                {
                    ConversionUtils.arraycopy(buffer6, 0, buffer7, 0L, buffer6.Length);
                }
                int cryptoFlag = ((data.getFlags() & FLAG_0x02) == 0L) ? 2 : 1;
                if ((data.getFlags() & FLAG_0x10) == 0L)
                {
                    num11 = 2;
                }
                else if ((data.getFlags() & FLAG_0x20) == 0L)
                {
                    num11 = 4;
                }
                else
                {
                    num11 = 1;
                }
                if ((data.getFlags() & FLAG_KEYENCRYPTED) != 0L)
                {
                    cryptoFlag |= 0x10000000;
                    num11 |= 0x10000000;
                }
                if ((data.getFlags() & FLAG_DEBUG) != 0L)
                {
                    cryptoFlag |= 0x1000000;
                    num11 |= 0x1000000;
                }
                AppLoader loader = new AppLoader();
                byte[] buffer9 = (npd.getVersion() <= 1L) ? new byte[0x10] : npd.getDigest();
                if (!loader.doAll(num11, cryptoFlag, buffer, 0, buffer5, 0, buffer.Length, buffer6, npd.getDigest(), buffer7, dest, 0))
                {
                    Debug.WriteLine("Error decrypting block " + i);
                }
                if ((data.getFlags() & FLAG_COMPRESSED) == 0L)
                {
                    o.Write(buffer5, 0, count);
                }
            }
            return STATUS_OK;
        }

        public int decryptFile(string inFile, string outFile, byte[] devKLic, byte[] keyFromRif)
        {
            FileStream i = File.Open(inFile, FileMode.Open);
            string[] strArray = i.Name.Split(new char[] { '\\' });
            Console.WriteLine(strArray[strArray.Length - 1]);
            NPD[] npdPtr = new NPD[1];
            int num = this.validateNPD(strArray[strArray.Length - 1], devKLic, npdPtr, i);
            if (num < 0)
            {
                i.Close();
                return num;
            }
            NPD npd = npdPtr[0];
            EDATData data = this.getEDATData(i);
            byte[] raw = this.getKey(npd, data, devKLic, keyFromRif);
            if (raw == null)
            {
                Console.WriteLine("ERROR: Key for decryption is missing");
                i.Close();
                return STATUS_ERROR_MISSINGKEY;
            }
            Console.WriteLine("DECRYPTION KEY: " + ConversionUtils.getHexString(raw));
            num = this.checkHeader(raw, data, npd, i);
            if (num < 0)
            {
                i.Close();
                return num;
            }
            FileStream o = File.Open(outFile, FileMode.Create);
            num = this.decryptData(i, o, npd, data, raw);
            if (num < 0)
            {
                i.Close();
                return num;
            }
            i.Close();
            o.Close();
            Console.WriteLine("COMPLETE: File Written to disk");
            return STATUS_OK;
        }

        private byte[] decryptMetadataSection(byte[] metadata)
        {
            return new byte[] { ((byte) ((metadata[12] ^ metadata[8]) ^ metadata[0x10])), ((byte) ((metadata[13] ^ metadata[9]) ^ metadata[0x11])), ((byte) ((metadata[14] ^ metadata[10]) ^ metadata[0x12])), ((byte) ((metadata[15] ^ metadata[11]) ^ metadata[0x13])), ((byte) ((metadata[4] ^ metadata[8]) ^ metadata[20])), ((byte) ((metadata[5] ^ metadata[9]) ^ metadata[0x15])), ((byte) ((metadata[6] ^ metadata[10]) ^ metadata[0x16])), ((byte) ((metadata[7] ^ metadata[11]) ^ metadata[0x17])), ((byte) ((metadata[12] ^ metadata[0]) ^ metadata[0x18])), ((byte) ((metadata[13] ^ metadata[1]) ^ metadata[0x19])), ((byte) ((metadata[14] ^ metadata[2]) ^ metadata[0x1a])), ((byte) ((metadata[15] ^ metadata[3]) ^ metadata[0x1b])), ((byte) ((metadata[4] ^ metadata[0]) ^ metadata[0x1c])), ((byte) ((metadata[5] ^ metadata[1]) ^ metadata[0x1d])), ((byte) ((metadata[6] ^ metadata[2]) ^ metadata[30])), ((byte) ((metadata[7] ^ metadata[3]) ^ metadata[0x1f])) };
        }

        private int encryptData(FileStream ii, FileStream o, NPD npd, EDATData data, byte[] rifkey)
        {
            int num = (int) (((data.getFileLen() + data.getBlockSize()) - 1) / data.getBlockSize());
            byte[] dest = new byte[num * 0x10];
            byte[] buffer2 = new byte[ii.Length + 15L];
            for (int i = 0; i < num; i++)
            {
                long offset = i * data.getBlockSize();
                ii.Seek(offset, SeekOrigin.Begin);
                int length = (int) data.getBlockSize();
                if (i == (num - 1))
                {
                    length = (int) (data.getFileLen() % new BigInteger(data.getBlockSize()));
                }
                int num5 = length;
                length = (length + 15) & -16;
                byte[] buffer3 = new byte[length];
                byte[] buffer4 = new byte[length];
                for (int j = num5; j > 0; j -= ii.Read(buffer4, num5 - j, j))
                {
                }
                for (int k = num5; k < length; k++)
                {
                    buffer4[k] = 0;
                }
                byte[] buffer5 = new byte[0x10];
                byte[] buffer6 = new byte[0x10];
                byte[] buffer7 = this.calculateBlockKey(i, npd);
                ToolsImpl.aesecbEncrypt(rifkey, buffer7, 0, buffer5, 0, buffer7.Length);
                ConversionUtils.arraycopy(buffer5, 0, buffer6, 0L, buffer5.Length);
                int cryptoFlag = 2;
                int hashFlag = 2;
                AppLoaderReverse reverse = new AppLoaderReverse();
                byte[] iv = npd.getDigest();
                byte[] generatedHash = new byte[0x10];
                reverse.doAll(hashFlag, cryptoFlag, buffer4, 0, buffer3, 0, buffer4.Length, buffer5, iv, buffer6, generatedHash, 0);
                ConversionUtils.arraycopy(buffer3, 0, buffer2, offset, length);
                ConversionUtils.arraycopy(generatedHash, 0, dest, (long) (i * 0x10), 0x10);
            }
            byte[] buffer = ConversionUtils.getByteArray("4D6164652062792052325220546F6F6C");
            o.Write(dest, 0, dest.Length);
            o.Write(buffer2, 0, buffer2.Length - 15);
            o.Write(buffer, 0, buffer.Length);
            return STATUS_OK;
        }

        public int encryptFile(string inFile, string outFile, byte[] devKLic, byte[] keyFromRif, byte[] contentID, byte[] flags, byte[] type, byte[] version)
        {
            int num2;
            int num9;
            FileStream fin = File.Open(inFile, FileMode.Open);
            NPD[] npdPtr = new NPD[1];
            FileStream o = File.Open(outFile, FileMode.Create);
            string[] strArray = o.Name.Split(new char[] { '\\' });
            byte[] buffer = this.writeValidNPD(strArray[strArray.Length - 1], devKLic, npdPtr, fin, contentID, flags, version, type);
            o.Write(buffer, 0, buffer.Length);
            byte[] buffer2 = new byte[] { 0, 0, 0, 0 };
            o.Write(buffer2, 0, 4);
            buffer2[2] = 0x40;
            o.Write(buffer2, 0, 4);
            long length = fin.Length;
            byte[] bytes = BitConverter.GetBytes(length);
            byte[] buffer4 = new byte[8];
            for (num2 = 0; num2 < 8; num2++)
            {
                buffer4[num2] = 0;
            }
            for (num2 = 0; num2 < bytes.Length; num2++)
            {
                buffer4[7 - num2] = bytes[num2];
            }
            o.Write(buffer4, 0, 8);
            buffer2[0] = 0;
            while (o.Length < 0x100L)
            {
                o.Write(buffer2, 0, 1);
            }
            EDATData data = new EDATData {
                flags = 0L,
                blockSize = 0x4000L,
                fileLen = new BigInteger(length)
            };
            byte[] rifkey = this.getKey(npdPtr[0], data, devKLic, keyFromRif);
            int hashFlag = 2;
            this.encryptData(fin, o, npdPtr[0], data, rifkey);
            o.Seek(0x90L, SeekOrigin.Begin);
            AppLoader loader = new AppLoader();
            loader.doInit(hashFlag, 1, new byte[0x10], new byte[0x10], rifkey);
            int num4 = ((data.getFlags() & FLAG_COMPRESSED) != 0L) ? 0x20 : 0x10;
            int num5 = (int) (((data.getFileLen() + data.getBlockSize()) - 11) / data.getBlockSize());
            int num6 = 0;
            int num7 = 0x100;
            for (long i = num4 * num5; i > 0L; i -= num9)
            {
                num9 = (HEADER_MAX_BLOCKSIZE > i) ? ((int) i) : HEADER_MAX_BLOCKSIZE;
                o.Seek((long) (num7 + num6), SeekOrigin.Begin);
                byte[] buffer6 = new byte[num9];
                byte[] buffer7 = new byte[num9];
                o.Read(buffer6, 0, buffer6.Length);
                loader.doUpdate(buffer6, 0, buffer7, 0, num9);
                num6 += num9;
            }
            byte[] generatedHash = new byte[0x10];
            loader.doFinalButGetHash(generatedHash);
            o.Seek(0x90L, SeekOrigin.Begin);
            o.Write(generatedHash, 0, generatedHash.Length);
            o.Seek(0L, SeekOrigin.Begin);
            byte[] buffer9 = new byte[160];
            byte[] buffer10 = new byte[160];
            o.Read(buffer9, 0, buffer9.Length);
            AppLoaderReverse reverse = new AppLoaderReverse();
            byte[] buffer11 = new byte[0x10];
            bool flag = reverse.doAll(hashFlag, 1, buffer9, 0, buffer10, 0, buffer9.Length, new byte[0x10], new byte[0x10], rifkey, buffer11, 0);
            o.Seek(160L, SeekOrigin.Begin);
            o.Write(buffer11, 0, buffer11.Length);
            while (o.Length < 0x100L)
            {
                o.Write(buffer2, 0, 1);
            }
            o.Close();
            fin.Close();
            return STATUS_OK;
        }

        private EDATData getEDATData(FileStream i)
        {
            i.Seek(0x80L, SeekOrigin.Begin);
            byte[] buffer = new byte[0x10];
            i.Read(buffer, 0, buffer.Length);
            return EDATData.createEDATData(buffer);
        }

        private byte[] getKey(NPD npd, EDATData data, byte[] devKLic, byte[] keyFromRif)
        {
            byte[] output = null;
            if ((data.getFlags() & FLAG_SDAT) != 0L)
            {
                output = new byte[0x10];
                ToolsImpl.XOR(output, npd.getDevHash(), EDATKeys.SDATKEY);
                return output;
            }
            if (npd.getLicense() == 3L)
            {
                return devKLic;
            }
            if (npd.getLicense() == 2L)
            {
                output = keyFromRif;
            }
            return output;
        }

        private int validateNPD(string filename, byte[] devKLic, NPD[] npdPtr, FileStream i)
        {
            i.Seek(0L, SeekOrigin.Begin);
            byte[] buffer = new byte[0x80];
            i.Read(buffer, 0, buffer.Length);
            byte[] buffer2 = new byte[4];
            i.Read(buffer2, 0, buffer2.Length);
            if ((ConversionUtils.be32(buffer2, 0) & FLAG_SDAT) != 0L)
            {
                Console.WriteLine("INFO: SDAT detected. NPD header is not validated");
            }
            else
            {
                if (!this.checkNPDHash1(filename, buffer))
                {
                    Console.WriteLine("ERROR: Hashing Title ID Name");
                    return STATUS_ERROR_HASHTITLEIDNAME;
                }
                if (devKLic == null)
                {
                    Console.WriteLine("WARNING: Can not validate devklic header");
                }
                else if (!this.checkNPDHash2(devKLic, buffer))
                {
                    Console.WriteLine("ERROR: Hashing devklic");
                    return STATUS_ERROR_HASHDEVKLIC;
                }
            }
            npdPtr[0] = NPD.createNPD(buffer);
            return STATUS_OK;
        }

        private byte[] writeValidNPD(string filename, byte[] devKLic, NPD[] npdPtr, FileStream fin, byte[] contentID, byte[] flags, byte[] version, byte[] type)
        {
            int num;
            byte[] dest = new byte[0x80];
            dest[0] = 0x4e;
            dest[1] = 80;
            dest[2] = 0x44;
            dest[3] = 0;
            dest[4] = 0;
            dest[5] = 0;
            dest[6] = 0;
            dest[7] = version[0];
            dest[8] = 0;
            dest[9] = 0;
            dest[10] = 0;
            dest[11] = 3;
            dest[12] = 0;
            dest[13] = 0;
            dest[14] = 0;
            dest[15] = type[0];
            for (num = 0; num < 0x30; num++)
            {
                dest[0x10 + num] = contentID[num];
            }
            ConversionUtils.arraycopy(ConversionUtils.charsToByte("FixedLicenseEDAT".ToCharArray()), 0, dest, 0x40L, 0x10);
            ConversionUtils.arraycopy(this.createNPDHash1(filename, dest), 0, dest, 80L, 0x10);
            ConversionUtils.arraycopy(this.createNPDHash2(devKLic, dest), 0, dest, 0x60L, 0x10);
            for (num = 0; num < 0x10; num++)
            {
                dest[0x70 + num] = 0;
            }
            npdPtr[0] = NPD.createNPD(dest);
            return dest;
        }

        public byte[] b0 { get; set; }
    }
}

