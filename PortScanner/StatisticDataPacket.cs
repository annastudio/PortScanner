using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace MJsniffer
{
    class StatisticDataPacket
    {
        private List<ProtocolData> dataList;
        private ConcurrentDictionary<int,int> countOfPortRequest;

        StatisticDataPacket(List<ProtocolData> data, ConcurrentDictionary<int, int> count)
        {
            dataList = data;
            countOfPortRequest = count;
        }

        string toJson(StatisticDataPacket packet)
        {
            return JsonSerializer.Serialize(this);
        }
    }
}
