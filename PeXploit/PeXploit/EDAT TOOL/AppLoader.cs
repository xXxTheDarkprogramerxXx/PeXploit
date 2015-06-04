namespace edatat
{
    using System;
    using System.Diagnostics;

    internal class AppLoader
    {
        private Decryptor dec;
        private Hash hash;
        private bool hashDebug = false;

        public bool doAll(int hashFlag, int cryptoFlag, byte[] i, int inOffset, byte[] o, int outOffset, int len, byte[] key, byte[] iv, byte[] hash, byte[] expectedHash, int hashOffset)
        {
            this.doInit(hashFlag, cryptoFlag, key, iv, hash);
            this.doUpdate(i, inOffset, o, outOffset, len);
            return this.doFinal(expectedHash, hashOffset);
        }

        public bool doFinal(byte[] expectedhash, int hashOffset)
        {
            return this.hash.doFinal(expectedhash, hashOffset, this.hashDebug);
        }

        public bool doFinalButGetHash(byte[] generatedHash)
        {
            return this.hash.doFinalButGetHash(generatedHash);
        }

        public void doInit(int hashFlag, int cryptoFlag, byte[] key, byte[] iv, byte[] hashKey)
        {
            byte[] calculatedKey = new byte[key.Length];
            byte[] calculatedIV = new byte[iv.Length];
            byte[] calculatedHash = new byte[hashKey.Length];
            this.getCryptoKeys(cryptoFlag, calculatedKey, calculatedIV, key, iv);
            this.getHashKeys(hashFlag, calculatedHash, hashKey);
            this.setDecryptor(cryptoFlag);
            this.setHash(hashFlag);
            Debug.WriteLine("ERK:  " + ConversionUtils.getHexString(calculatedKey));
            Debug.WriteLine("IV:   " + ConversionUtils.getHexString(calculatedIV));
            Debug.WriteLine("HASH: " + ConversionUtils.getHexString(calculatedHash));
            this.dec.doInit(calculatedKey, calculatedIV);
            this.hash.doInit(calculatedHash);
        }

        public void doUpdate(byte[] i, int inOffset, byte[] o, int outOffset, int len)
        {
            this.hash.doUpdate(i, inOffset, len);
            this.dec.doUpdate(i, inOffset, o, outOffset, len);
        }

        private void getCryptoKeys(int cryptoFlag, byte[] calculatedKey, byte[] calculatedIV, byte[] key, byte[] iv)
        {
            switch (((uint) (cryptoFlag & -268435456)))
            {
                case 0:
                    ConversionUtils.arraycopy(key, 0, calculatedKey, 0L, calculatedKey.Length);
                    ConversionUtils.arraycopy(iv, 0, calculatedIV, 0L, calculatedIV.Length);
                    Debug.WriteLine("MODE: Unencrypted ERK");
                    break;

                case 0x10000000:
                    ToolsImpl.aescbcDecrypt(EDATKeys.EDATKEY, EDATKeys.EDATIV, key, 0, calculatedKey, 0, calculatedKey.Length);
                    ConversionUtils.arraycopy(iv, 0, calculatedIV, 0L, calculatedIV.Length);
                    Debug.WriteLine("MODE: Encrypted ERK");
                    break;

                case 0x20000000:
                    ConversionUtils.arraycopy(EDATKeys.EDATKEY, 0, calculatedKey, 0L, calculatedKey.Length);
                    ConversionUtils.arraycopy(EDATKeys.EDATIV, 0, calculatedIV, 0L, calculatedIV.Length);
                    Debug.WriteLine("MODE: Default ERK");
                    break;

                default:
                    throw new Exception("Crypto mode is not valid: Undefined keys calculator");
            }
        }

        private void getHashKeys(int hashFlag, byte[] calculatedHash, byte[] hash)
        {
            switch (((uint) (hashFlag & -268435456)))
            {
                case 0:
                    ConversionUtils.arraycopy(hash, 0, calculatedHash, 0L, calculatedHash.Length);
                    Debug.WriteLine("MODE: Unencrypted HASHKEY");
                    break;

                case 0x10000000:
                    ToolsImpl.aescbcDecrypt(EDATKeys.EDATKEY, EDATKeys.EDATIV, hash, 0, calculatedHash, 0, calculatedHash.Length);
                    Debug.WriteLine("MODE: Encrypted HASHKEY");
                    break;

                case 0x20000000:
                    ConversionUtils.arraycopy(EDATKeys.EDATHASH, 0, calculatedHash, 0L, calculatedHash.Length);
                    Debug.WriteLine("MODE: Default HASHKEY");
                    break;

                default:
                    throw new Exception("Hash mode is not valid: Undefined keys calculator");
            }
        }

        private void setDecryptor(int cryptoFlag)
        {
            switch ((cryptoFlag & 0xff))
            {
                case 1:
                    this.dec = new NoCrypt();
                    Debug.WriteLine("MODE: Decryption Algorithm NONE");
                    break;

                case 2:
                    this.dec = new AESCBC128Decrypt();
                    Debug.WriteLine("MODE: Decryption Algorithm AESCBC128");
                    break;

                default:
                    throw new Exception("Crypto mode is not valid: Undefined decryptor");
            }
        }

        private void setHash(int hashFlag)
        {
            switch ((hashFlag & 0xff))
            {
                case 1:
                    this.hash = new HMAC();
                    this.hash.setHashLen(20);
                    Debug.WriteLine("MODE: Hash HMAC Len 0x14");
                    break;

                case 2:
                    this.hash = new CMAC();
                    this.hash.setHashLen(0x10);
                    Debug.WriteLine("MODE: Hash CMAC Len 0x10");
                    break;

                case 4:
                    this.hash = new HMAC();
                    this.hash.setHashLen(0x10);
                    Debug.WriteLine("MODE: Hash HMAC Len 0x10");
                    break;

                default:
                    throw new Exception("Hash mode is not valid: Undefined hash algorithm");
            }
            if ((hashFlag & 0xf000000) != 0)
            {
                this.hashDebug = true;
            }
        }
    }
}

