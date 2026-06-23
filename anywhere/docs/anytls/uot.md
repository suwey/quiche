Protocol details

Protocol version 1

The client requests the magic address to the upper layer proxy protocol to indicate the request: sp.udp-over-tcp.arpa

Stream format

ATYP	address	port	length	data
u8	variable	u16be	u16be	variable
ATYP / address / port: Uses the SOCKS address format, but with different address types:

ATYP	Address type
0x00	IPv4 Address
0x01	IPv6 Address
0x02	Domain Name
Protocol version 2

Protocol version 2 uses a new magic address: sp.v2.udp-over-tcp.arpa

REQUEST FORMAT

isConnect	ATYP	address	port
u8	u8	variable	u16be
isConnect: Set to 1 to indicates that the stream uses the connect format, 0 to disable.

ATYP / address / port: Request destination, uses the SOCKS address format.

CONNECT STREAM FORMAT

length	data
u16be	variable
NON-CONNECT STREAM FORMAT

As the same as the stream format in protocol version 1.

Important: the Request frame uses SOCKS5 ATYP — 0x01=v4 / 0x03=fqdn / 0x04=v6,
while the associate datagrams use UoT ATYP — 0x00=v4 / 0x01=v6 / 0x02=fqdn. 