namespace edatat
{
    using System;
    using System.Numerics;

    public class ConversionUtils
    {
        private static byte[] HEX_CHAR_TABLE = new byte[] { 0x30, 0x31, 50, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 100, 0x65, 0x66 };

        public static void arraycopy(byte[] src, int srcPos, byte[] dest, long destPos, int length)
        {
            for (int i = 0; i < length; i++)
            {
                dest[(int) ((IntPtr) (destPos + i))] = src[srcPos + i];
            }
        }

        public static int be16(byte[] buffer, int initOffset)
        {
            int num = 0;
            for (int i = initOffset; i < (initOffset + 2); i++)
            {
                num = (num * 0x100) + (buffer[i] & 0xff);
            }
            return num;
        }

        public static long be32(byte[] buffer, int initOffset)
        {
            long num = 0L;
            for (int i = initOffset; i < (initOffset + 4); i++)
            {
                num = (num * 0x100L) + (buffer[i] & 0xff);
            }
            return num;
        }

        public static BigInteger be64(byte[] buffer, int initOffset)
        {
            BigInteger zero = BigInteger.Zero;
            for (int i = initOffset; i < (initOffset + 8); i++)
            {
                zero *= new BigInteger(0x100);
                zero += new BigInteger(buffer[i] & 0xff);
            }
            return zero;
        }

        public static char[] bytesToChar(byte[] b)
        {
            char[] chArray = new char[b.Length];
            for (int i = 0; i < b.Length; i++)
            {
                chArray[i] = (char) b[i];
            }
            return chArray;
        }

        public static byte[] charsToByte(char[] b)
        {
            byte[] buffer = new byte[b.Length];
            for (int i = 0; i < b.Length; i++)
            {
                buffer[i] = (byte) b[i];
            }
            return buffer;
        }

        public static byte[] decodeHex(char[] data)
        {
            int length = data.Length;
            if ((length & 1) != 0)
            {
                throw new Exception("Odd number of characters.");
            }
            byte[] buffer = new byte[length >> 1];
            int index = 0;
            int num3 = 0;
            while (num3 < length)
            {
                int num4 = toDigit(data[num3], num3) << 4;
                num3++;
                num4 |= toDigit(data[num3], num3);
                num3++;
                buffer[index] = (byte) (num4 & 0xff);
                index++;
            }
            return buffer;
        }

        public static byte[] getByteArray(string hexString)
        {
            return decodeHex(hexString.ToCharArray());
        }

        public static string getHexString(byte[] raw)
        {
            byte[] b = new byte[2 * raw.Length];
            int num = 0;
            foreach (byte num2 in raw)
            {
                uint num3 = (uint) (num2 & 0xff);
                b[num++] = HEX_CHAR_TABLE[num3 >> 4];
                b[num++] = HEX_CHAR_TABLE[(int) ((IntPtr) (num3 & 15))];
            }
            return new string(bytesToChar(b));
        }

        private static int GetIntegerValue(char c, int radix)
        {
            int num = -1;
            if (char.IsDigit(c))
            {
                num = c - '0';
            }
            else if (char.IsLower(c))
            {
                num = (c - 'a') + 10;
            }
            else if (char.IsUpper(c))
            {
                num = (c - 'A') + 10;
            }
            if (num >= radix)
            {
                num = -1;
            }
            return num;
        }

        public static byte[] reverseByteWithSizeFIX(byte[] b)
        {
            byte[] buffer;
            if (b[b.Length - 1] == 0)
            {
                buffer = new byte[b.Length - 1];
            }
            else
            {
                buffer = new byte[b.Length];
            }
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[(buffer.Length - 1) - i] = b[i];
            }
            return buffer;
        }

        protected static int toDigit(char ch, int index)
        {
            int integerValue = GetIntegerValue(ch, 0x10);
            if (integerValue == -1)
            {
                throw new Exception(string.Concat(new object[] { "Illegal hexadecimal character ", ch, " at index ", index }));
            }
            return integerValue;
        }
    }
}

