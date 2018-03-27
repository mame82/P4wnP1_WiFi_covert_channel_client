using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace WiFiTest
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
            byte[] test1 = new byte[16];
            byte[] test2 = new byte[256*4+1];
            for (int i = 0; i < test1.Length; i++) test1[i] = 1;
            for (int i = 0; i < test2.Length; i++) test2[i] = 1;
            Console.WriteLine(String.Format("Chk1: {0}", NWiFi.Packet2.simpleChecksum8(test1)));
            Console.WriteLine(String.Format("Chk2: {0}", NWiFi.Packet2.simpleChecksum8(test2)));
            */
            NWiFi.NativeWifi.test();
            Console.Read();
        }
    }
}
