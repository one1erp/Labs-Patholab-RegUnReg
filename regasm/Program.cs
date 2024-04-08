using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace regasm
{
    class Program
    {
        static string path;
        static void Main(string[] args)
        {

            try
            {


                path = Directory.GetCurrentDirectory();
                regOcx(path);
                regDlls(path);

                Console.WriteLine("Finish");
                Console.ReadLine();
            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }
        }

        private static void regOcx(string path)
        {
            string[] filePaths = Directory.GetFiles(path, "*.ocx");
            foreach (var filePath in filePaths)
            {
                try
                {
                    Registar_UNManaged(filePath);
                }
                catch (Exception e)
                {
                    Console.WriteLine(filePath + " " + e.Message);
                }
            }

        }

        private static void regDlls(string path)
        {
            string[] filePaths = Directory.GetFiles(path, "*.dll");
            foreach (var filePath in filePaths)
            {

                try
                {
                    if (IsManagedAssembly(filePath))
                    {

                        Registar_Managed(filePath);
                    }
                    else
                    {
                        Registar_UNManaged(filePath);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(filePath + " " + e.Message);
                }
            }

        }

        private static void Registar_Managed(string filePath)
        {
            try
            {
                var tlb = filePath.Replace(".dll", ".tlb");
                var b = Directory.GetFiles(path).Contains(tlb);
                if (b)
                {



                    bool bResult;
                    Assembly asm = Assembly.LoadFile(filePath);
                    RegistrationServices regAsm = new RegistrationServices();

                    bResult = regAsm.RegisterAssembly(asm, AssemblyRegistrationFlags.SetCodeBase);

                    Console.WriteLine(filePath + " regAsm  " + bResult);
                }
                else
                {
                    Console.WriteLine(filePath + "Doesn't need Registration");

                }
            }
            catch (Exception ex)
            {


                Console.WriteLine
                (filePath + "\n" + ex.Message);
            }
        }

        public static void Registar_UNManaged(string filePath)
        {
            try
            {
                //'/s' : Specifies regsvr32 to run silently and to not display any message boxes.
                string arg_fileinfo = "/s" + " " + "\"" + filePath + "\"";
                Process reg = new Process();
                //This file registers .dll files as command components in the registry.
                reg.StartInfo.FileName = "regsvr32.exe";
                reg.StartInfo.Arguments = arg_fileinfo;
                reg.StartInfo.UseShellExecute = false;
                reg.StartInfo.CreateNoWindow = false;
                reg.StartInfo.RedirectStandardOutput = false;
                reg.Start();
                reg.WaitForExit();
                reg.Close();
                Console.WriteLine(filePath + " regsvr32  True");
            }
            catch (Exception ex)
            {
                Console.WriteLine
                (ex.Message);
            }
        }

        public static bool IsManagedAssembly(string fileName)
        {
            uint peHeader;
            uint peHeaderSignature;
            ushort machine;
            ushort sections;
            uint timestamp;
            uint pSymbolTable;
            uint noOfSymbol;
            ushort optionalHeaderSize;
            ushort characteristics;
            ushort dataDictionaryStart;
            uint[] dataDictionaryRVA = new uint[16];
            uint[] dataDictionarySize = new uint[16];

            Stream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            BinaryReader reader = new BinaryReader(fs);

            //PE Header starts @ 0x3C (60). Its a 4 byte header.
            fs.Position = 0x3C;
            peHeader = reader.ReadUInt32();

            //Moving to PE Header start location...
            fs.Position = peHeader;
            peHeaderSignature = reader.ReadUInt32();

            //We can also show all these value, but we will be       
            //limiting to the CLI header test.
            machine = reader.ReadUInt16();
            sections = reader.ReadUInt16();
            timestamp = reader.ReadUInt32();
            pSymbolTable = reader.ReadUInt32();
            noOfSymbol = reader.ReadUInt32();
            optionalHeaderSize = reader.ReadUInt16();
            characteristics = reader.ReadUInt16();

            // Now we are at the end of the PE Header and from here, the PE Optional Headers starts... To go directly to the datadictionary, we'll increase the stream’s current position to with 96 (0x60). 96 because, 28 for Standard fields 68 for NT-specific fields From here DataDictionary starts...and its of total 128 bytes. DataDictionay has 16 directories in total, doing simple maths 128/16 = 8. So each directory is of 8 bytes. In this 8 bytes, 4 bytes is of RVA and 4 bytes of Size. btw, the 15th directory consist of CLR header! if its 0, its not a CLR file :)
            dataDictionaryStart = Convert.ToUInt16(Convert.ToUInt16(fs.Position) + 0x60);
            fs.Position = dataDictionaryStart;
            for (int i = 0; i < 15; i++)
            {
                dataDictionaryRVA[i] = reader.ReadUInt32();
                dataDictionarySize[i] = reader.ReadUInt32();
            }
            fs.Close();

            if (dataDictionaryRVA[14] == 0) return false;
            else return true;
        }

    }
}
