namespace edatat
{
    using System;
    using System.Numerics;

    internal class CMACGenerator : HashGenerator
    {
        private int hashLen = 0x10;
        private byte[] K1;
        private byte[] K2;
        private byte[] key;
        private byte[] nonProcessed;
        private byte[] previous;

        private void calculateSubkey(byte[] key, byte[] K1, byte[] K2)
        {
            byte[] i = new byte[0x10];
            byte[] o = new byte[0x10];
            ToolsImpl.aesecbEncrypt(key, i, 0, o, 0, i.Length);
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

        public override bool doFinal(byte[] generateHash)
        {
            byte[] dest = new byte[0x10];
            ConversionUtils.arraycopy(this.nonProcessed, 0, dest, 0L, this.nonProcessed.Length);
            if (this.nonProcessed.Length == 0x10)
            {
                ToolsImpl.XOR(dest, dest, this.K1);
            }
            else
            {
                dest[this.nonProcessed.Length] = 0x80;
                ToolsImpl.XOR(dest, dest, this.K2);
            }
            ToolsImpl.XOR(dest, dest, this.previous);
            ToolsImpl.aesecbEncrypt(this.key, dest, 0, generateHash, 0, dest.Length);
            return true;
        }

        public override void doInit(byte[] key)
        {
            this.key = key;
            this.K1 = new byte[0x10];
            this.K2 = new byte[0x10];
            this.calculateSubkey(key, this.K1, this.K2);
            this.nonProcessed = null;
            this.previous = new byte[0x10];
        }

        public override void doUpdate(byte[] i, int inOffset, int len)
        {
            byte[] buffer;
            if (this.nonProcessed != null)
            {
                int num = len + this.nonProcessed.Length;
                buffer = new byte[num];
                ConversionUtils.arraycopy(this.nonProcessed, 0, buffer, 0L, this.nonProcessed.Length);
                ConversionUtils.arraycopy(i, inOffset, buffer, (long) this.nonProcessed.Length, len);
            }
            else
            {
                buffer = new byte[len];
                ConversionUtils.arraycopy(i, inOffset, buffer, 0L, len);
            }
            int srcPos = 0;
            while (srcPos < (buffer.Length - 0x10))
            {
                byte[] dest = new byte[0x10];
                ConversionUtils.arraycopy(buffer, srcPos, dest, 0L, dest.Length);
                ToolsImpl.XOR(dest, dest, this.previous);
                ToolsImpl.aesecbEncrypt(this.key, dest, 0, this.previous, 0, dest.Length);
                srcPos += 0x10;
            }
            this.nonProcessed = new byte[buffer.Length - srcPos];
            ConversionUtils.arraycopy(buffer, srcPos, this.nonProcessed, 0L, this.nonProcessed.Length);
        }

        public override void setHashLen(int len)
        {
            if (len != 0x10)
            {
                throw new Exception("Hash len must be 0x10");
            }
            this.hashLen = len;
        }
    }
}

