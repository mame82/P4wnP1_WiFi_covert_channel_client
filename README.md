# P4wnP1 - WiFi covert channel - Client agent (experimental Proof of Concept) by MaMe82

Experimental client agent for P4wnP1 WiFi covert channel.
The channel communicates via 802.11 Probe Requests and Responses. This means it doesn't depend on the client beeing associated with any WiFi network. Additionally the covert channel doesn't depend on the 802.11 frequency (channel) in use, in case the client is connected to an existing WiFi.
The agent doesn't need elevated user privileges to work, as it utilitzes unprivileged functions of the Win32 Native WiFi API.

The code isn't cleaned so far and is considered **experimental not stable**.

Implementation is done in a NET based dynamic library, to allow easy loading and invocation from an existing PowerShell runspace (has to be loaded from a 32 bit PowerShell).

The PoC binds a SubProcess to the channel (cmd.exe), once it is up and running.

The code includes an executable PE file (WiFiTest), which isn't used by the final payload. The entry method of the DLL is `NWiFi.NativeWifi.run()` !

## This is a PoC - What this is not:

- A production payload which works reliable in every case (code isn't cleaned, comments have to be reworked).
- Supporting multi channel: In theory the protocol supports up to 16 servers with up to 16 clients per server, but it doesn't support multiple channels per client (f.e. to pipe through multiple shells, like shown in the HID covert channel payload)
- An exfiltration channel with high throughput (due to its nature).
- An undetectable channel (pretty easy to spot with monitoring, as data is injected into 802.11 frame payloads, not modulated into RSSI or sth. like that).
- An encrypted channel (if you need it, implement it)
- Tested on a broad range of target hardware.
- Well tested (especially in crowded areas)

## Additional details

- The upstream channel of the system under test (target) are probe requests with data encoded in the Information Element (IE) for SSID and in a vendor specific IE (the latter only if apllicable, the implementation tests for capability of transmitting a vendor IE during connection initialization). The probe requests are forced by issuing active scans.
- The downstream channel from the server to the target are **unicast** probe replies. Beacons aren't used, to keep the channel "more silent", otherwise the SSID encoded data would be shown to any other devices scanning for WiFi networks (the PoC doesn't introduce any encryption).
- As the probe requests are issued using scans, they arrive on all 802.11 WiFi frequencies (of the regulatory). This means the implementation is independent of the WiFi channel in use, covert channel server and target could work on different WiFi channels (in fact, with minor additions the server would be able to change channels during communication to add a layer of obfuscation). 
- Additionally, this allows covert channel communication in both cases: 
	- a) the target is already connected to a WiFi network (even if the 802.11 frequency differs from the one of the server)
	- b) the target isn't connected to a WiFi network at all
 - No elevated privileges (administrator) are needed to issue scans.
 - Probe responses are accepted by the Windows WiFi API (spotted networks are added to the BSS list), **even if the SSID doesn't fit the one specified in the probe request**. This allows encoding data in the SSID of the probe response, which differs from the SSID encoded data in the probe request. (Depending on the target's WiFi interface, a minimum of IEs have to be included in the probe response, to avoid beeing discarded. F.e. Intel Wireless chips accept probe response frames which include *SSID* and *Vendor specific* IE only, while Atheros AR9271 discards probe response frames if no *Supported Rates* and *DS Parameter set* IEs are included)
 - As no beacons are used, the server isn't able to actively send data (which would be seen by the target, only if scans are issued in high frequency, anyway).
 This means the communication follows a REQUEST-REPLY-SCHEME on the lower layer, where the requests are issued by the target.
 - This low level REQUEST-REPLY transfer is constantly happening, by forcing the target to do active scans as fast as possible (could be throttled in future implementations, to account for more covertness and power saving on mobile targets). 
 - Due to the constant data flow, the upper layer has a permanent data carrier present, which is available, as long as the target is in range and the covert channel payload is running.
 - A single scan period takes up to 4 seconds (for Wireless network drivers that meet Windows logo requirements). This means the round trip time is 4 seconds, **if, and only if, the dynamically generated probe responses arrives in timely manner** (before the interface hops to the next 802.11 channel during WiFi scan or the timer started after sending a probe request times out). If the probe response doesn't arrive in time, the round trip time doubles.
 - Current PoC implementation uses the Windows Native WiFi 'WlanScan' function, which only allows active scanning for **a single SSID per scan**. This means, sending multiple probe requests with encoded data during a single scan isn't possible. While this has a impact on throughput of the channel (upstream) as only one data packet "is in flight" at any given time, this ,on the other hand, greatly simplifies the flow control. For every sequence number
 an ack has to be received, before the next packet is send. For the downstream it should be  posibble to send multiple probe responses (or single probe response with multiple packets encoded) and use a sliding window approach to account for packet loss with multiple inbound packets in flight. The latter is out-of-scope for this PoC, although the current protocol uses SEQuence and ACKnowledge numbers. The SEQ/ACK numbers introduced could be used to extend the protocol with flow control improvements (On Windows 10, active scanning for multiple SSIDs at once seems to be possible with another API).
 - The protocol has been changed from using 4 bit sequence numbers, to use 8 bit sequence numbers. The cause was a "lesson learned" when distinguishing inbound packtes on an Atheros chipset wasn't possible anymore, because the BSS list didn't get flushed between scans (and thus multiple packets with same SEQ/ACK have been cached).
 - To keep the round trip time short, dynamically generated probe responses have to be delivered as fast as possible for relevant probe requests, by the server. This is achieved by further modifying (in addition to the already deployed KARMA mod) the firmware and driver stack of the BCM43430a1 SoC on a Raspberry Pi Zero (utilizing nexmon as fast solution for high level language firmware modification).
	- First, the brcmfmac driver has been modified to listen for PROBE_REQUEST events, which are genrated in the firmware by default. A netlink multicast socket is used to propagate these events back from kernelspace to userspace. 
	- Second the driver has been modified, in order to receive unicast netlink based IOCTLs which are used to forward the data for the needed PROBE RESPONSES to the firmware. The firmware received a minor modification to create and deliver probe responses based on these IOCTLs.
 - Thanks to the firmware approach, there's no Access Point or Monitoring/Injection setup needed to bring up the covert channel server. 
 - The server's userland backend is written in python and interfaces with the two netlink sockets. The unoptimized PoC reaches response time (from probe request to probe response)
 roughly below 100ms, which is enough for the scan period on a single channel (nearly every probe requests receives a proper response in time). No tests have been done in crowded area.
 - The communication protocol additionally introduces the concept of client and server IDs, to identify communication partners. This approach was chosen, because the 802.11 Source Address (SA) of a WiFi client could change during scans (especially on mobile devices). The IDs for clients and servers could be compared to host addresses in the IP-Stack, but are limited to 16 (per client and per server).
 - Thanks to the protocols independency from real 802.11 BSSID, SA and DA, the aforementioned addresses could be changed during ongoing communications to suite the attackers needs (for example to line-up with unmalicious devices and cloak the communication further). Another reason for changing the SA (at least in probe responses), is to avoid getting flagged by solutions monitoring for KARMA attacks (mulitple SSIDs for same BSSID would be a strong indicator for such an attack).
 - Noise (non covert channel communication) is filtered by a very simple approach: The SSID of covert channel frames always has to have the maximum length (32 bytes) and the last byte has to be the complement of a 8-bit checksum (complement to avoid all zero SSID). If possible an additional vendor IE (238 bytes in length) is added and a checksum appended, too.
 - In summary, the protocol handles up to 16 clients, doesn't depend on a deciated 802.11 WiFi channel, isn't visible for other WiFi clients and reaches a rough througput of 260 bytes/4 seconds. With some extensions it could allow channel hopping and encryption to circumvent easy monitoring as well as sliding window like approaches, to increase throughput. The Windows payload doesn't need a privileged user.
 - Scanning for networks in high frequency doesn't interrupt active WiFi connections
 of the target, but impacts throughput of valid communication (the radio has to switch channels for scanning, while keeping comms on a single channel alive)
- The communication of the covert channel isn't impacted by de-auth attacks, as no authentication takes place, at all (authentication and association happen after prober request/response).
