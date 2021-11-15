using System;
using MJsniffer;
using PortScanner;

namespace PortScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            Worker worker = new Worker();
            worker.run();
        }
    }
}
