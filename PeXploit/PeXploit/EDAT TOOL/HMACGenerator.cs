namespace edatat
{
    using System;
    using System.Security.Cryptography;

    internal class HMACGenerator : HashGenerator
    {
        private int hashLen;
        private HMACSHA1 mac;
        private byte[] result;

        public override bool doFinal(byte[] generatedHash)
        {
            ConversionUtils.arraycopy(this.result, 0, generatedHash, 0L, this.result.Length);
            return true;
        }

        public override void doInit(byte[] key)
        {
            try
            {
                this.mac = new HMACSHA1(key);
            }
            catch (Exception exception)
            {
                throw exception;
            }
        }

        public override void doUpdate(byte[] i, int inOffset, int len)
        {
            this.result = this.mac.ComputeHash(i, inOffset, len);
        }

        public override void setHashLen(int len)
        {
            if ((len != 0x10) && (len != 20))
            {
                throw new Exception("Hash len must be 0x10 or 0x14");
            }
            this.hashLen = len;
        }
    }
}

