namespace edatat
{
    using System;
    using System.IO;
    using System.Reflection;

    internal class rif2rap
    {
        private static byte[] ACTDAT_KEY = new byte[] { 0x5e, 6, 0xe0, 0x4f, 0xd9, 0x4a, 0x71, 0xbf, 0, 0, 0, 0, 0, 0, 0, 1 };
        private int i = 0;
        private static int[] indexTable = new int[] { 12, 3, 6, 4, 1, 11, 15, 8, 2, 7, 0, 5, 10, 14, 13, 9 };
        private static byte[] key1 = new byte[] { 0xa9, 0x3e, 0x1f, 0xd6, 0x7c, 0x55, 0xa3, 0x29, 0xb7, 0x5f, 0xdd, 0xa6, 0x2a, 0x95, 0xc7, 0xa5 };
        private static byte[] key2 = new byte[] { 0x67, 0xd4, 0x5d, 0xa3, 0x29, 0x6d, 0, 0x6a, 0x4e, 0x7c, 0x53, 0x7b, 0xf5, 0x53, 140, 0x74 };
        private static byte[] rapKey = new byte[] { 0x86, 0x9f, 0x77, 0x45, 0xc1, 0x3f, 0xd8, 0x90, 0xcc, 0xf2, 0x91, 0x88, 0xe3, 0xcc, 0x3e, 0xdf };
        public string rif;
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

        public string getKey(string rifIn)
        {
            if (!File.Exists(rifIn))
            {
                Console.WriteLine(rifIn + " not found");
                return rifIn;
            }
            string directoryName = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetName().CodeBase);
            string str2 = directoryName.Replace(@"file:\", "");
            string str3 = directoryName + "/data/act.dat";
            string str4 = directoryName + "/data/idps";
            string actIn = str3.Replace(@"file:\", "");
            string idps = str4.Replace(@"file:\", "");
            byte[] i = this.getrifKey(rifIn, actIn, idps);
            for (int j = 0; j < 5; j++)
            {
                int num4;
                int num2 = 0;
                int index = 0;
                while (index < 0x10)
                {
                    num4 = indexTable[index];
                    byte num5 = (byte) (i[num4] + num2);
                    if ((num2 != 1) || (num5 != 0xff))
                    {
                        int num6 = (num5 + key2[num4]) & 0xff;
                        int num7 = key2[num4] & 0xff;
                        num2 = (num6 < num7) ? 1 : 0;
                        i[num4] = (byte) (num5 + key2[num4]);
                    }
                    else if (num5 == 0xff)
                    {
                        i[num4] = (byte) (num5 + key2[num4]);
                    }
                    else
                    {
                        i[num4] = num5;
                    }
                    index++;
                }
                index = 1;
                while (index < 0x10)
                {
                    int num8 = indexTable[index];
                    int num9 = indexTable[index - 1];
                    i[num8] = (byte) (i[num9] ^ i[num8]);
                    index++;
                }
                for (index = 0; index < 0x10; index++)
                {
                    num4 = indexTable[index];
                    i[num4] = (byte) (key1[num4] ^ i[num4]);
                }
            }
            string str7 = this.GetSubstringByString('\\', ".", rifIn);
            string path = null;
            if (str2 != null)
            {
                path = str2 + "/raps/" + str7 + ".rap";
            }
            else
            {
                path = "raps/" + str7 + ".rap";
            }
            byte[] o = new byte[0x10];
            ToolsImpl.aesecbEncrypt(rapKey, i, 0, o, 0, 0x10);
            DirectoryInfo info = Directory.CreateDirectory("raps");
            FileStream stream = File.Open(path, FileMode.Create);
            stream.Write(o, 0, 0x10);
            stream.Close();
            if (Directory.Exists("temp"))
            {
                Directory.Delete("temp", true);
            }
            return path;
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

        public byte[] getrifKey(string rifIn, string actIn, string idps)
        {
            if ((rifIn == null) || (actIn == null))
            {
                return null;
            }
            byte[] o = null;
            FileStream stream = File.Open(rifIn, FileMode.Open);
            byte[] buffer2 = new byte[0x10];
            byte[] buffer3 = new byte[0x10];
            byte[] buffer = new byte[0x10];
            byte[] buffer5 = new byte[0x10];
            stream.Seek(0x40L, SeekOrigin.Begin);
            stream.Read(buffer, 0, buffer.Length);
            stream.Read(buffer5, 0, buffer5.Length);
            stream.Close();
            ToolsImpl.aesecbDecrypt(RIFKEY, buffer, 0, buffer2, 0, 0x10);
            long num = ConversionUtils.be32(buffer2, 12);
            if (num < 0x80L)
            {
                byte[] src = decryptACTDAT(actIn, idps);
                byte[] dest = new byte[0x10];
                o = new byte[0x10];
                ConversionUtils.arraycopy(src, ((int) num) * 0x10, dest, 0L, 0x10);
                ToolsImpl.aesecbDecrypt(dest, buffer5, 0, o, 0, 0x10);
            }
            return o;
        }

        public string GetSubstringByString(char a, string b, string c)
        {
            return c.Substring(c.LastIndexOf(a) + 1, (c.LastIndexOf(b) - c.LastIndexOf(a)) - 1);
        }

        public string makerap(string rifIn)
        {
            if (!File.Exists(rifIn))
            {
                Console.WriteLine(rifIn + " not found");
                return rifIn;
            }
            string directoryName = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetName().CodeBase);
            string str2 = directoryName.Replace(@"file:\", "");
            string str3 = directoryName + "/data/act.dat";
            string str4 = directoryName + "/data/idps";
            string actIn = str3.Replace(@"file:\", "");
            string idps = str4.Replace(@"file:\", "");
            byte[] i = this.getrifKey(rifIn, actIn, idps);
            for (int j = 0; j < 5; j++)
            {
                int num5;
                int num2 = 0;
                int num3 = 0;
                int index = 0;
                while (index < 0x10)
                {
                    num5 = indexTable[index];
                    byte num6 = (byte) ((i[num5] + num2) + num3);
                    if ((num2 != 1) || (num6 != 0xff))
                    {
                        int num7 = (num6 + key2[num5]) & 0xff;
                        int num8 = key2[num5] & 0xff;
                        int num9 = i[num5];
                        num2 = (num7 < num8) ? 1 : 0;
                        num3 = (num9 == 0xff) ? 1 : 0;
                        i[num5] = (byte) (num6 + key2[num5]);
                    }
                    else if (num6 == 0xff)
                    {
                        i[num5] = (byte) (num6 + key2[num5]);
                    }
                    else
                    {
                        i[num5] = num6;
                    }
                    index++;
                }
                index = 1;
                while (index < 0x10)
                {
                    int num10 = indexTable[index];
                    int num11 = indexTable[index - 1];
                    i[num10] = (byte) (i[num11] ^ i[num10]);
                    index++;
                }
                for (index = 0; index < 0x10; index++)
                {
                    num5 = indexTable[index];
                    i[num5] = (byte) (key1[num5] ^ i[num5]);
                }
            }
            string str7 = this.GetSubstringByString('\\', ".", rifIn);
            string path = null;
            if (str2 != null)
            {
                path = str2 + "/raps/" + str7 + ".rap";
            }
            else
            {
                path = "raps/" + str7 + ".rap";
            }
            byte[] o = new byte[0x10];
            ToolsImpl.aesecbEncrypt(rapKey, i, 0, o, 0, 0x10);
            DirectoryInfo info = Directory.CreateDirectory(str2 + "/raps");
            FileStream stream = File.Open(path, FileMode.Create);
            stream.Write(o, 0, 0x10);
            stream.Close();
            while (this.i == 0)
            {
                string outFile = "test.rif";
                this.rif = new edatat.raptest().makerif(path, outFile);
                this.i++;
            }
            int num12 = 0;
            byte[] buffer3 = this.getrifKey(rifIn, actIn, idps);
            byte[] buffer4 = this.getrifKey(this.rif, actIn, idps);
            if ((((((buffer3[0] != buffer4[0]) || (buffer3[1] != buffer4[1])) || ((buffer3[2] != buffer4[2]) || (buffer3[3] != buffer4[3]))) || (((buffer3[4] != buffer4[4]) || (buffer3[5] != buffer4[5])) || ((buffer3[6] != buffer4[6]) || (buffer3[7] != buffer4[7])))) || ((((buffer3[8] != buffer4[8]) || (buffer3[9] != buffer4[9])) || ((buffer3[10] != buffer4[10]) || (buffer3[11] != buffer4[11]))) || (((buffer3[12] != buffer4[12]) || (buffer3[13] != buffer4[13])) || (buffer3[14] != buffer4[14])))) || (buffer3[15] != buffer4[15]))
            {
                this.getKey(rifIn);
                num12++;
                if (Directory.Exists("temp"))
                {
                    Directory.Delete("temp", true);
                }
            }
            return path;
        }
    }
}

