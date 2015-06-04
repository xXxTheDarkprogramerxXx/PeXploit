namespace edatat
{
    using System;

    internal abstract class Decryptor
    {
        protected Decryptor()
        {
        }

        public virtual void doInit(byte[] key, byte[] iv)
        {
        }

        public virtual void doUpdate(byte[] i, int inOffset, byte[] o, int outOffset, int len)
        {
        }
    }
}

