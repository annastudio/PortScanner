using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MJsniffer
{
    public class TransportProtocolHeader
    {
        //UDP header fields
        private ushort usSourcePort;            //Sixteen bits for the source port number        
        private ushort usDestinationPort;       //Sixteen bits for the destination port number
        private ushort usLength;                //Length of the UDP header
        private short sChecksum;                //Sixteen bits for the checksum
                                                //(checksum can be negative so taken as short)              
                                                //End UDP header fields

        private byte[] byData = new byte[4096];  //Data carried by the UDP packet

        public string SourcePort
        {
            get
            {
                return usSourcePort.ToString();
            }
        }




        public string DestinationPort
        {
            get
            {
                return usDestinationPort.ToString();
            }
        }

        public string Length
        {
            get
            {
                return usLength.ToString();
            }
        }

        public string Checksum
        {
            get
            {
                //Return the checksum in hexadecimal format
                return string.Format("0x{0:x2}", sChecksum);
            }
        }

        public byte[] Data
        {
            get
            {
                return byData;
            }
        }

        public virtual int Flags
        {
            get
            {
                return 0;
            }
        }

        public void setSourcePort(ushort value)
        {
            usSourcePort = value;
        }
        public void setDestinationPort(ushort value)
        {
            usDestinationPort = value;
        }
        public void setLength(ushort value)
        {
            usLength = value;
        }
        public void setChecksum(short value)
        {
            sChecksum = value;
        }
    }
}
