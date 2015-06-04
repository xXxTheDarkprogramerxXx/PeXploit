namespace edatat
{
    using System;
    using System.IO;
    using System.Reflection;
    using System.Text;

    internal class C00EDAT
    {
        public string C00games;
        private int counter1 = 0;
        public string game;
        public string ip;
        public string line;
        public string line3;
        public string login;
        public string outFile;
        public static byte[] pad = new byte[] { 0x47, 0x4f, 0x4d, 0x41, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        public string password;
        public string rifs;
        public string trash;
        public string trash2;

        public string GetSubstringByString(string a, string b, string c)
        {
            return c.Substring(c.IndexOf(a), c.IndexOf(b) - c.IndexOf(a));
        }

        public string makeedat(string inFile, string outFile)
        {
            if (!File.Exists(inFile))
            {
                Console.WriteLine(inFile + " not found");
                return inFile;
            }
            string str2 = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetName().CodeBase).Replace(@"file:\", "");
            StreamReader reader = new StreamReader(inFile);
            string c = reader.ReadToEnd();
            if (c.Contains("HG\0\0"))
            {
                if (c.Contains("Library"))
                {
                    byte[] buffer = new byte[c.Length];
                    string str5 = this.GetSubstringByString("HG\0\0", "Library", c).Replace("HG\0\0", "");
                    int index = 0;
                    index = str5.IndexOf("\0");
                    int num2 = str5.Length - index;
                    int length = str5.Length - num2;
                    reader.Close();
                    string s = str5.Replace("\0", "");
                    if (length > 0x23)
                    {
                        byte[] bytes = Encoding.UTF8.GetBytes(s);
                        byte[] dest = new byte[0x30];
                        byte[] buffer4 = new byte[length];
                        ConversionUtils.arraycopy(bytes, 0, dest, 0L, bytes.Length);
                        ConversionUtils.arraycopy(bytes, 0, buffer4, 0L, length);
                        string str7 = Encoding.UTF8.GetString(buffer4);
                        if (str2 != null)
                        {
                            outFile = str2 + "/edats/" + str7 + ".edat";
                        }
                        else
                        {
                            outFile = "edats/" + str7 + ".edat";
                        }
                        FileStream stream = File.Open(str7 + ".dat", FileMode.Create);
                        stream.Write(pad, 0, 0x10);
                        stream.Write(dest, 0, dest.Length);
                        stream.Close();
                        string str8 = str7 + ".dat";
                        DirectoryInfo info = Directory.CreateDirectory(str2 + "/edats");
                        byte[] flags = ConversionUtils.getByteArray("0C");
                        byte[] type = ConversionUtils.getByteArray("00");
                        byte[] version = ConversionUtils.getByteArray("02");
                        byte[] devKLic = ConversionUtils.getByteArray("72F990788F9CFF745725F08E4C128387");
                        byte[] keyFromRif = null;
                        new EDAT().encryptFile(str8, outFile, devKLic, keyFromRif, dest, flags, type, version);
                        if (File.Exists(str7 + ".dat"))
                        {
                            File.Delete(str7 + ".dat");
                        }
                        if (str8.EndsWith(".Dec"))
                        {
                            File.Delete(str8);
                        }
                        return (str7 + ".edat");
                    }
                    Console.WriteLine("Content_ID not found.");
                    return "";
                }
                Console.WriteLine("Content_ID not found.");
                return "";
            }
            Console.WriteLine("Content_ID not found.");
            return "";
        }
    }
}

