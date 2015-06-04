namespace edatat
{
    using System;
    using System.IO;
    using System.Reflection;
    using System.Text;

    internal class rap2rif
    {
        private static byte[] ACTDAT_KEY = new byte[] { 0x5e, 6, 0xe0, 0x4f, 0xd9, 0x4a, 0x71, 0xbf, 0, 0, 0, 0, 0, 0, 0, 1 };
        private static int[] indexTable = new int[] { 12, 3, 6, 4, 1, 11, 15, 8, 2, 7, 0, 5, 10, 14, 13, 9 };
        private static byte[] key1 = new byte[] { 0xa9, 0x3e, 0x1f, 0xd6, 0x7c, 0x55, 0xa3, 0x29, 0xb7, 0x5f, 0xdd, 0xa6, 0x2a, 0x95, 0xc7, 0xa5 };
        private static byte[] key2 = new byte[] { 0x67, 0xd4, 0x5d, 0xa3, 0x29, 0x6d, 0, 0x6a, 0x4e, 0x7c, 0x53, 0x7b, 0xf5, 0x53, 140, 0x74 };
        public string outFile;
        private static byte[] rapKey = new byte[] { 0x86, 0x9f, 0x77, 0x45, 0xc1, 0x3f, 0xd8, 0x90, 0xcc, 0xf2, 0x91, 0x88, 0xe3, 0xcc, 0x3e, 0xdf };
        private static byte[] rif_footer = new byte[] { 0, 0, 1, 0x2f, 0x41, 0x5c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static byte[] rif_header = new byte[] { 0, 0, 0, 1, 0, 1, 0, 2 };
        private static byte[] rif_junk = new byte[] { 0x11 };
        private static byte[] RIFKEY = new byte[] { 0xda, 0x7d, 0x4b, 0x5e, 0x49, 0x9a, 0x4f, 0x53, 0xb1, 0xc1, 0xa1, 0x4a, 0x74, 0x84, 0x44, 0x3b };

        private static byte[] decryptACTDAT(string actIn, string IDPSFile)
        {
            FileStream stream = File.Open(actIn, FileMode.Open);
            byte[] buffer = new byte[0x800];
            byte[] o = new byte[buffer.Length];
            stream.Seek(0x10L, SeekOrigin.Begin);
            stream.Read(buffer, 0, buffer.Length);
            stream.Close();
            ToolsImpl.aesecbDecrypt(getPerConsoleKey(IDPSFile), buffer, 0, o, 0, buffer.Length);
            return o;
        }

        public byte[] getKey(string rapFile)
        {
            BinaryReader reader = new BinaryReader(File.OpenRead(rapFile));
            byte[] i = reader.ReadBytes(0x10);
            reader.Close();
            byte[] o = new byte[i.Length];
            ToolsImpl.aesecbDecrypt(rapKey, i, 0, o, 0, i.Length);
            for (int j = 0; j < 5; j++)
            {
                int num3;
                int index = 0;
                while (index < 0x10)
                {
                    num3 = indexTable[index];
                    o[num3] = (byte) (o[num3] ^ key1[num3]);
                    index++;
                }
                index = 15;
                while (index > 0)
                {
                    int num4 = indexTable[index];
                    int num5 = indexTable[index - 1];
                    o[num4] = (byte) (o[num4] ^ o[num5]);
                    index--;
                }
                int num6 = 0;
                for (index = 0; index < 0x10; index++)
                {
                    num3 = indexTable[index];
                    byte num7 = (byte) (o[num3] - num6);
                    o[num3] = num7;
                    if ((num6 != 1) || (num7 != 0xff))
                    {
                        int num8 = num7 & 0xff;
                        int num9 = key2[num3] & 0xff;
                        num6 = (num8 < num9) ? 1 : 0;
                    }
                    o[num3] = (byte) (num7 - key2[num3]);
                }
            }
            return o;
        }

        private static byte[] getPerConsoleKey(string IDPSFile)
        {
            FileStream stream = File.Open(IDPSFile, FileMode.Open);
            byte[] buffer = new byte[0x10];
            stream.Read(buffer, 0, buffer.Length);
            stream.Close();
            byte[] o = new byte[0x10];
            ToolsImpl.aesecbEncrypt(buffer, ACTDAT_KEY, 0, o, 0, ACTDAT_KEY.Length);
            return o;
        }

        public string GetSubstringByString(char a, string b, string c)
        {
            return c.Substring(c.LastIndexOf(a) + 1, (c.LastIndexOf(b) - c.LastIndexOf(a)) - 1);
        }

        public string makerif(string inFile, string outFile)
        {
            if (!File.Exists(inFile))
            {
                Console.WriteLine(inFile + " not found");
                return inFile;
            }
            string directoryName = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetName().CodeBase);
            string str2 = directoryName.Replace(@"file:\", "");
            string str3 = directoryName + "/data/act.dat";
            string str4 = directoryName + "/data/idps";
            string path = str3.Replace(@"file:\", "");
            string iDPSFile = str4.Replace(@"file:\", "");
            FileStream stream = File.Open(path, FileMode.Open);
            byte[] buffer = new byte[8];
            stream.Seek(8L, SeekOrigin.Begin);
            stream.Read(buffer, 0, 8);
            stream.Close();
            string s = this.GetSubstringByString('\\', ".", inFile);
            if (str2 != null)
            {
                outFile = str2 + "/rifs/" + s + ".rif";
            }
            else
            {
                outFile = "rifs/" + s + ".rif";
            }
            byte[] dest = new byte[0x30];
            byte[] o = new byte[0x10];
            byte[] i = new byte[0x10];
            byte[] buffer5 = null;
            byte[] buffer6 = this.getKey(inFile);
            DirectoryInfo info = Directory.CreateDirectory(str2 + "/rifs");
            FileStream stream2 = File.Open(outFile, FileMode.Create);
            stream2.Write(rif_header, 0, 8);
            stream2.Write(buffer, 0, 8);
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            ConversionUtils.arraycopy(bytes, 0, dest, 0L, bytes.Length);
            stream2.Write(dest, 0, 0x30);
            ToolsImpl.aesecbEncrypt(RIFKEY, i, 0, o, 0, 0x10);
            stream2.Write(o, 0, 0x10);
            long num = 0L;
            byte[] src = decryptACTDAT(path, iDPSFile);
            byte[] buffer9 = new byte[0x10];
            buffer5 = new byte[0x10];
            byte[] buffer10 = new byte[40];
            ConversionUtils.arraycopy(src, ((int) num) * 0x10, buffer9, 0L, 0x10);
            ToolsImpl.aesecbEncrypt(buffer9, buffer6, 0, buffer5, 0, 0x10);
            stream2.Write(buffer5, 0, 0x10);
            stream2.Write(rif_footer, 0, 0x10);
            while (stream2.Length < 0x98L)
            {
                stream2.Write(rif_junk, 0, 1);
            }
            stream2.Close();
            return outFile;
        }
    }
}

