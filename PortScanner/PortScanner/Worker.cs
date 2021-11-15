using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MJsniffer
{
    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };


    class Worker
    {
        private Socket mainSocket;                          //The socket which captures all incoming packets
        private byte[] byteData = new byte[4096];
        private bool bContinueCapturing = false;            //A flag to check if packets are to be captured or not
        private ConcurrentDictionary<int, int> countOfPortRequest; //= new ConcurrentDictionary<int, int>();
        private string currentNetInterface = "";
        private Conc<ProtocolData> protocolDatas;
        //private delegate void AddTreeNode(TreeNode node);

        public void run()
        {

            List<String> interfaces = getInterfaces();
            countOfPortRequest = new ConcurrentDictionary<int, int>();
            protocolDatas = new List<ProtocolData>();
        Console.WriteLine("Выберите интерфейс: ");
            interfaces.ForEach(delegate (String inter)
            {
                Console.WriteLine((interfaces.IndexOf(inter) + 1) + ". " + inter);
            });
            int iNum = Int16.Parse(Console.ReadLine());
            currentNetInterface = interfaces[iNum - 1];
            sniffStart();
        }

        public List<String> getInterfaces()
        {
            string strIP = null;
            List<String> resList = new List<String>();


            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    resList.Add(strIP);
                }
            }
            return resList;
        }

        private void sniffStart()
        {
            if (currentNetInterface == "")
            {
                Console.WriteLine("Select an Interface to capture the packets.");
                return;
            }
            try
            {
                if (!bContinueCapturing)
                {
                    //Start capturing the packets...

                    bContinueCapturing = true;

                    //For sniffing the socket to capture the packets has to be a raw socket, with the
                    //address family being of type internetwork, and protocol being IP
                    mainSocket = new Socket(AddressFamily.InterNetwork,
                        SocketType.Raw, ProtocolType.IP);

                    //Bind the socket to the selected IP address
                    mainSocket.Bind(new IPEndPoint(IPAddress.Parse(currentNetInterface), 0));

                    //Set the socket  options
                    mainSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                               SocketOptionName.HeaderIncluded, //Set the include the header
                                               true);                           //option to true

                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                                //of Winsock 2
                                         byTrue,
                                         byOut);

                    //Start receiving the packets asynchronously

                    while (true)
                    {
                        mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                            new AsyncCallback(OnReceive), null);
                        Thread.Sleep(30000);
                        foreach (int key in countOfPortRequest.Keys)
                        {
                            Console.WriteLine("port: " + key + " count of requests: " + countOfPortRequest[key]);
                        }
                    }


                }
                else
                {
                    bContinueCapturing = false;
                    //To stop capturing the packets close the socket
                    mainSocket.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);

                //Analyze the bytes received...

                ParseData(byteData, nReceived);

                if (bContinueCapturing)
                {
                    byteData = new byte[4096];

                    //Another call to BeginReceive so that we continue to receive the incoming
                    //packets
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            
            //Since all protocol packets are encapsulated in the IP datagram
            //so we start by parsing the IP header and see what protocol data
            //is being carried by it
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            TransportProtocolHeader tph = new TransportProtocolHeader();

            //Now according to the protocol being carried by the IP datagram we parse 
            //the data field of the datagram
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    tph = new TCPHeader(ipHeader.Data,              //IPHeader.Data stores the data being 
                                                                                    //carried by the IP datagram
                                                        ipHeader.MessageLength);//Length of the data field                    


                    //If the port is equal to 53 then the underlying protocol is DNS
                    //Note: DNS can use either TCP or UDP thats why the check is done twice
                    if (tph.DestinationPort == "53" || tph.SourcePort == "53")
                    {
                       
                    }

                    break;

                case Protocol.UDP:

                    tph = new UDPHeader(ipHeader.Data,              //IPHeader.Data stores the data being 
                                                                                    //carried by the IP datagram
                                                       (int)ipHeader.MessageLength);//Length of the data field                    

                    
                    //If the port is equal to 53 then the underlying protocol is DNS
                    //Note: DNS can use either TCP or UDP thats why the check is done twice
                    if (tph.DestinationPort == "53" || tph.SourcePort == "53")
                    {

                        
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }

            Console.WriteLine("from " + ipHeader.SourceAddress.ToString() + ":" + tph.SourcePort + " to " +
                ipHeader.DestinationAddress.ToString() + ":" + tph.DestinationPort);
            Console.WriteLine("Protocol: " + ipHeader.ProtocolType.ToString());
            Console.WriteLine("flags: " + tph.Flags);
            Console.WriteLine();
            protocolDatas.Add();
            if (ipHeader.DestinationAddress.ToString() == currentNetInterface)
            {
                countOfPortRequest.AddOrUpdate(Int32.Parse(tph.DestinationPort),1,(key, oldValue) => oldValue + 1);
            }
            
            
        }





        /*private void SnifferForm_Load(object sender, EventArgs e)
        {
            string strIP = null;

            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    cmbInterfaces.Items.Add(strIP);
                }
            }
        }

        private void SnifferForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (bContinueCapturing)
            {
                mainSocket.Close();
            }
        }*/
        }
    }



