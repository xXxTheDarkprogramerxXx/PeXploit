namespace edatat
{
    using System;
    using System.Numerics;

    internal class NPD
    {
        private byte[] content_id = new byte[0x30];
        private byte[] devHash = new byte[0x10];
        private byte[] digest = new byte[0x10];
        private long license;
        private byte[] magic = new byte[4];
        private byte[] titleHash = new byte[0x10];
        private long type;
        private BigInteger unknown3;
        private BigInteger unknown4;
        private long version;

        private NPD()
        {
        }

        public static NPD createNPD(byte[] npd)
        {
            NPD npd2 = new NPD();
            ConversionUtils.arraycopy(npd, 0, npd2.magic, 0L, 4);
            npd2.version = ConversionUtils.be32(npd, 4);
            npd2.license = ConversionUtils.be32(npd, 8);
            npd2.type = ConversionUtils.be32(npd, 12);
            ConversionUtils.arraycopy(npd, 0x10, npd2.content_id, 0L, 0x30);
            ConversionUtils.arraycopy(npd, 0x40, npd2.digest, 0L, 0x10);
            ConversionUtils.arraycopy(npd, 80, npd2.titleHash, 0L, 0x10);
            ConversionUtils.arraycopy(npd, 0x60, npd2.devHash, 0L, 0x10);
            npd2.unknown3 = ConversionUtils.be64(npd, 0x70);
            npd2.unknown4 = ConversionUtils.be64(npd, 120);
            if (!npd2.validate())
            {
                npd2 = null;
            }
            return npd2;
        }

        public byte[] getDevHash()
        {
            return this.devHash;
        }

        public byte[] getDigest()
        {
            return this.digest;
        }

        public long getLicense()
        {
            return this.license;
        }

        public long getVersion()
        {
            return this.version;
        }

        private bool validate()
        {
            if ((((this.magic[0] != 0x4e) || (this.magic[1] != 80)) || (this.magic[2] != 0x44)) || (this.magic[3] != 0))
            {
                return false;
            }
            if ((this.unknown3.CompareTo(BigInteger.Zero) != 0) || (this.unknown4.CompareTo(BigInteger.Zero) != 0))
            {
                return false;
            }
            return true;
        }
    }
}

