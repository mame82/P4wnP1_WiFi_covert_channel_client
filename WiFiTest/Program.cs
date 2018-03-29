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
            NWiFi.NativeWifi.run();

            //Console.WriteLine("Library exitted");
            //Console.Read();
        }
    }
}
