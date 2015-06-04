namespace edatat
{
    using System;

    public class XOREngine
    {
        public static byte[] XOR(byte[] inByteArray, int offsetPos, int length, byte[] XORKey)
        {
            if (inByteArray.Length < (offsetPos + length))
            {
                throw new Exception("Combination of chosen offset pos. & Length goes outside of the array to be xored.");
            }
            if ((length % XORKey.Length) != 0)
            {
                throw new Exception("Nr bytes to be xored isn't a mutiple of xor key length.");
            }
            int num = length / XORKey.Length;
            byte[] buffer = new byte[length];
            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < XORKey.Length; j++)
                {
                    buffer[(i * XORKey.Length) + j] = (byte) (buffer[(i * XORKey.Length) + j] + ((byte) (inByteArray[(offsetPos + (i * XORKey.Length)) + j] ^ XORKey[j])));
                }
            }
            return buffer;
        }
    }
}

