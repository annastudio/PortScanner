using System.Net;
using System.Text;
using System;
using System.IO;

namespace MJsniffer
{
    public class UDPHeader:TransportProtocolHeader
    {
        //UDP header fields
        private ushort usSourcePort;            //Sixteen bits for the source port number        
        private ushort usDestinationPort;       //Sixteen bits for the destination port number
        private ushort usLength;                //Length of the UDP header
        private short sChecksum;                //Sixteen bits for the checksum
                                                //(checksum can be negative so taken as short)              
        //End UDP header fields

        private byte[] byUDPData = new byte[4096];  //Data carried by the UDP packet

        public UDPHeader(byte [] byBuffer, int nReceived)
        {
            MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            //The first sixteen bits contain the source port
            setSourcePort((ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16()));

            //The next sixteen bits contain the destination port
            setDestinationPort((ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16()));

            //The next sixteen bits contain the length of the UDP packet
            setLength((ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16()));

            //The next sixteen bits contain the checksum
            setChecksum(IPAddress.NetworkToHostOrder(binaryReader.ReadInt16()));            

            //Copy the data carried by the UDP packet into the data buffer
            Array.Copy(byBuffer, 
                       8,               //The UDP header is of 8 bytes so we start copying after it
                       byUDPData, 
                       0, 
                       nReceived - 8);
        }


    }
}