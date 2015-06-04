namespace edatat
{
    using System;
    using System.Numerics;

    public class EDATData
    {
        public long blockSize;
        public BigInteger fileLen;
        public long flags;

        public static EDATData createEDATData(byte[] data)
        {
            return new EDATData { flags = ConversionUtils.be32(data, 0), blockSize = ConversionUtils.be32(data, 4), fileLen = ConversionUtils.be64(data, 8) };
        }

        public long getBlockSize()
        {
            return this.blockSize;
        }

        public BigInteger getFileLen()
        {
            return this.fileLen;
        }

        public long getFlags()
        {
            return this.flags;
        }
    }
}

