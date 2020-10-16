using System;
using Org.BouncyCastle.Math;
using System.IO;
using Lab2;
using System.Diagnostics;

namespace LAB3
{
    class Program
    {
        static void Main(string[] args)
        {
            int action = 0; //действие
            Console.WriteLine("Выберите режим");
            Console.WriteLine("Введите 0 - для создания ЭЦП");
            Console.WriteLine("Введите 1 - для проверки ЭЦП");
            action = Convert.ToInt32(Console.ReadLine());
            RSA test = new RSA(action);
            test.ActionSelection();
        }
    }
    class RSA
    {
        private BigInteger p;
        private BigInteger q;
        public BigInteger n;
        private BigInteger fi;
        public BigInteger e;
        private BigInteger d;
        private Org.BouncyCastle.Security.SecureRandom rnd = new Org.BouncyCastle.Security.SecureRandom();
        private int action;

        public void ActionSelection()
        {
            Stopwatch stopWatch = new Stopwatch();
            switch (this.action)
            {
                case 0:
                    Console.WriteLine("Введите название файла для создания ЭЦП");
                    string MFileName = Console.ReadLine();
                    stopWatch.Start();
                    encrypt(MFileName);
                    TimeSpan ts1 = stopWatch.Elapsed;
                    string elapsedTime1 = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", ts1.Hours, ts1.Minutes, ts1.Seconds, ts1.Milliseconds / 10);
                    Console.WriteLine("Enc RunTime " + elapsedTime1);
                    break;
                case 1:
                    Console.WriteLine("Введите название файла для проверки ЭЦП");
                    string MSFileName = Console.ReadLine();
                    stopWatch.Start();
                    checkSignature(MSFileName);
                    TimeSpan ts2 = stopWatch.Elapsed;
                    string elapsedTime2 = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", ts2.Hours, ts2.Minutes, ts2.Seconds, ts2.Milliseconds / 10);
                    Console.WriteLine("Ckeck RunTime" + elapsedTime2);
                    break;
            }
        }

        private void checkSignature(string MSFileName)
        {
            FileStream MSFile = File.OpenRead(MSFileName);
            byte[] MSData = new byte[MSFile.Length];
            MSFile.Read(MSData, 0, MSData.Length);
            byte[] MData = new byte[MSData.Length - 256];
            byte[] SData = new byte[256];
            Array.Copy(MSData,0, MData,0,MData.Length);
            Array.Copy(MSData, MSData.Length - 256, SData, 0, SData.Length);
            byte[] OData = decrypt(SData);
            byte[] MHash = SHA256.getHash(MData);
            BigInteger MH = new BigInteger(1, MHash);
            BigInteger SH = new BigInteger(1, OData);
            if(MH.Equals(SH))
            {
                Console.WriteLine("Проверка пройдена");
            }
            else
            {
                Console.WriteLine("Проверка не пройдена");
            }
        }

        public RSA(int action)
        {//конструктор класса
            this.action = action;
        }

        private BigInteger SetE(BigInteger fi)
        {
            BigInteger ee = new BigInteger(fi.BitLength-1, 1000, rnd);
            if((ee.Gcd(fi)).Equals(BigInteger.One))
            {
                return ee;
            }
            else
            {
                return SetE(fi);
            }
        }
        private void KeyGen()
        {
            this.p = new BigInteger(1024,1000, rnd);// генерируем простое p
            this.q = new BigInteger(1024,1000, rnd);// генерируем простое q
            this.n = p.Multiply(q);// считаем n = p*q
            BigInteger test = p.Subtract(BigInteger.One);
            BigInteger test2 = q.Subtract(BigInteger.One);
            this.fi = (p.Subtract(BigInteger.One)).Multiply(q.Subtract(BigInteger.One));//считаем фи = (p-1)(q-1) 
            this.e = SetE(fi);// генерируем е, взимнопростое с фи
            WriteIntoFile(e,n,"publicKey.bin");
            this.d = e.ModInverse(fi);//считаем d по модулю e^-1 mod фи
        }
        public void encrypt(string MessageFileName)
        {
            File.Delete("файл с подписью");
            KeyGen();
            byte[] data = HashFromFile(MessageFileName);
            BigInteger OPEN = new BigInteger(1,data,0,data.Length);
            BigInteger s = OPEN.ModPow(d, n);
            byte[] EncData = s.ToByteArray();
            WriteIntoFile(EncData, "файл с подписью");
        }

        public byte[] decrypt(byte [] SData)
        {
            FileStream KeyFile = File.OpenRead("publicKey.bin"); // поток для чтения открытого ключа
            byte[] publicKeyData = new byte[KeyFile.Length];
            KeyFile.Read(publicKeyData, 0, publicKeyData.Length); // считываем е и n
            KeyFile.Close();
            Console.WriteLine(publicKeyData.Length);
            byte[] eData = new byte[256];
            Array.Copy(publicKeyData, 0, eData, 0, 256);
            byte[] nData = new byte[publicKeyData.Length-eData.Length];
            Array.Copy(publicKeyData, eData.Length, nData, 0, publicKeyData.Length- eData.Length);
            BigInteger e = new BigInteger(eData);
            BigInteger n = new BigInteger(nData);

            BigInteger PRIVATE = new BigInteger(1,SData);
            BigInteger m = PRIVATE.ModPow(e, n);
            byte[] OpenData = m.ToByteArray();
            if (OpenData[0]==0)
            {
                byte[] OpenData1 = new byte[OpenData.Length-1];
                Array.Copy(OpenData,1,OpenData1,0,OpenData1.Length);
                return OpenData1;
            }
            else
            {
                return OpenData;
            }
        }
        private byte[] HashFromFile(string FileName)
        {
            FileStream messageFile = File.OpenRead(FileName);
            byte[] MessageData = new byte[messageFile.Length];
            messageFile.Read(MessageData, 0, MessageData.Length);
            messageFile.Close();
            WriteIntoFile(MessageData, "mws.mp3");
            byte[] MessageHash = SHA256.getHash(MessageData);
            //---------------------------------------------
            for (int i = 1; i<1000; i++)
            {
                MessageHash = SHA256.getHash(MessageHash);
            }
            //---------------------------------------------
            return MessageHash;
        }
        private void WriteIntoFile(BigInteger FirstBI, BigInteger SecondBI, string FileName)
        {
            byte[] Text1 = FirstBI.ToByteArray();
            File.Delete(FileName);
            FileStream PublicKeyFile = new FileStream(FileName, FileMode.Append);
            PublicKeyFile.Seek(0, SeekOrigin.End);
            PublicKeyFile.Write(Text1);
            byte[] Text2 = SecondBI.ToByteArray();
            PublicKeyFile.Seek(0, SeekOrigin.End);
            PublicKeyFile.Write(Text2);
            PublicKeyFile.Close();
        }
        private void WriteIntoFile(byte[] data, string FileName)
        {
            FileStream TextFile = new FileStream(FileName, FileMode.Append);
            TextFile.Seek(0, SeekOrigin.End);
            TextFile.Write(data);
            TextFile.Close();
        }
    }
}
