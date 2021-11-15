using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MJsniffer
{
    class ProtocolData
    {
        private string SourceAddress;
        private int SourcePort;
        private string DestinationAddress;
        private int DestinationPort;
        private string ProtocolType;
        private int Flags;

        ProtocolData(string sA, int sP, string dA, int dP, string pType, ushort f)
        {
            SourceAddress1 = sA;
            SourcePort1 = sP;
            DestinationAddress1 = dA;
            DestinationPort1 = dP;
            ProtocolType1 = pType;
            Flags1 = f;
        }

        ProtocolData(IPHeader ipPacket, TransportProtocolHeader tPacket)
        {
            SourceAddress1 = ipPacket.SourceAddress.ToString();
            SourcePort1 = Int32.Parse(tPacket.SourcePort);
            DestinationAddress1 = ipPacket.DestinationAddress.ToString();
            DestinationPort1 = Int32.Parse(tPacket.DestinationPort);
            ProtocolType1 = ipPacket.ProtocolType.ToString();
            Flags1 = tPacket.Flags;
        }

        public string SourceAddress1 { get => SourceAddress; set => SourceAddress = value; }
        public int SourcePort1 { get => SourcePort; set => SourcePort = value; }
        public string DestinationAddress1 { get => DestinationAddress; set => DestinationAddress = value; }
        public int DestinationPort1 { get => DestinationPort; set => DestinationPort = value; }
        public string ProtocolType1 { get => ProtocolType; set => ProtocolType = value; }
        public int Flags1 { get => Flags; set => Flags = value; }
    }
}
