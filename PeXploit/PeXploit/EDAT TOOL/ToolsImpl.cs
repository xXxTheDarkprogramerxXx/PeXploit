namespace edatat
{
    using System;
    using System.Diagnostics;
    using System.Numerics;
    using System.Security.Cryptography;

    public class ToolsImpl
    {
        public static int DECRYPT_MODE = 2;
        public static int ENCRYPT_MODE = 1;

        public static void aescbcDecrypt(byte[] key, byte[] iv, byte[] i, int inOffset, byte[] o, int outOffset, int len)
        {
            CipherMode cBC = CipherMode.CBC;
            PaddingMode none = PaddingMode.None;
            int opMode = DECRYPT_MODE;
            crypto(key, cBC, none, iv, opMode, i, inOffset, len, o, outOffset);
        }

        public static void aesecbDecrypt(byte[] key, byte[] i, int inOffset, byte[] o, int outOffset, int len)
        {
            CipherMode eCB = CipherMode.ECB;
            PaddingMode none = PaddingMode.None;
            int opMode = DECRYPT_MODE;
            crypto(key, eCB, none, null, opMode, i, inOffset, len, o, outOffset);
        }

        public static void aesecbEncrypt(byte[] key, byte[] i, int inOffset, byte[] o, int outOffset, int len)
        {
            CipherMode eCB = CipherMode.ECB;
            PaddingMode none = PaddingMode.None;
            int opMode = ENCRYPT_MODE;
            crypto(key, eCB, none, null, opMode, i, inOffset, len, o, outOffset);
        }

        private static void calculateSubkey(byte[] key, byte[] K1, byte[] K2)
        {
            byte[] i = new byte[0x10];
            byte[] o = new byte[0x10];
            aesecbEncrypt(key, i, 0, o, 0, i.Length);
            BigInteger integer = new BigInteger(ConversionUtils.reverseByteWithSizeFIX(o));
            if ((o[0] & 0x80) != 0)
            {
                integer = (integer << 1) ^ new BigInteger(0x87);
            }
            else
            {
                integer = integer << 1;
            }
            byte[] src = ConversionUtils.reverseByteWithSizeFIX(integer.ToByteArray());
            if (src.Length >= 0x10)
            {
                ConversionUtils.arraycopy(src, src.Length - 0x10, K1, 0L, 0x10);
            }
            else
            {
                ConversionUtils.arraycopy(i, 0, K1, 0L, i.Length);
                ConversionUtils.arraycopy(src, 0, K1, (long) (0x10 - src.Length), src.Length);
            }
            integer = new BigInteger(ConversionUtils.reverseByteWithSizeFIX(K1));
            if ((K1[0] & 0x80) != 0)
            {
                integer = (integer << 1) ^ new BigInteger(0x87);
            }
            else
            {
                integer = integer << 1;
            }
            src = ConversionUtils.reverseByteWithSizeFIX(integer.ToByteArray());
            if (src.Length >= 0x10)
            {
                ConversionUtils.arraycopy(src, src.Length - 0x10, K2, 0L, 0x10);
            }
            else
            {
                ConversionUtils.arraycopy(i, 0, K2, 0L, i.Length);
                ConversionUtils.arraycopy(src, 0, K2, (long) (0x10 - src.Length), src.Length);
            }
        }

        public static byte[] CMAC128(byte[] key, byte[] i, int inOffset, int len)
        {
            byte[] buffer = new byte[0x10];
            byte[] buffer2 = new byte[0x10];
            calculateSubkey(key, buffer, buffer2);
            byte[] dest = new byte[0x10];
            byte[] inputB = new byte[0x10];
            int srcPos = inOffset;
            int length = len;
            while (length > 0x10)
            {
                ConversionUtils.arraycopy(i, srcPos, dest, 0L, 0x10);
                XOR(dest, dest, inputB);
                aesecbEncrypt(key, dest, 0, inputB, 0, dest.Length);
                srcPos += 0x10;
                length -= 0x10;
            }
            dest = new byte[0x10];
            ConversionUtils.arraycopy(i, srcPos, dest, 0L, length);
            if (length == 0x10)
            {
                XOR(dest, dest, inputB);
                XOR(dest, dest, buffer);
            }
            else
            {
                dest[length] = 0x80;
                XOR(dest, dest, inputB);
                XOR(dest, dest, buffer2);
            }
            aesecbEncrypt(key, dest, 0, inputB, 0, dest.Length);
            return inputB;
        }

        private static void crypto(byte[] key, CipherMode mode, PaddingMode padding, byte[] iv, int opMode, byte[] i, int inOffset, int len, byte[] o, int outOffset)
        {
            try
            {
                RijndaelManaged managed = new RijndaelManaged {
                    Padding = padding,
                    Mode = mode,
                    KeySize = 0x80,
                    BlockSize = 0x80,
                    Key = key
                };
                if (iv != null)
                {
                    managed.IV = iv;
                }
                byte[] src = null;
                if (opMode == DECRYPT_MODE)
                {
                    src = managed.CreateDecryptor().TransformFinalBlock(i, inOffset, len);
                }
                else if (opMode == ENCRYPT_MODE)
                {
                    src = managed.CreateEncryptor().TransformFinalBlock(i, inOffset, len);
                }
                else
                {
                    fail("NOT SUPPORTED OPMODE");
                }
                ConversionUtils.arraycopy(src, 0, o, (long) outOffset, len);
            }
            catch (Exception exception)
            {
                fail(exception.Message);
            }
        }

        public static void fail(string a)
        {
            Debug.WriteLine(a);
        }

        public static void XOR(byte[] output, byte[] inputA, byte[] inputB)
        {
            for (int i = 0; i < inputA.Length; i++)
            {
                output[i] = (byte) (inputA[i] ^ inputB[i]);
            }
        }
    }
}

