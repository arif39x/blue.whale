import asyncio
import logging
import socket
from datetime import datetime
from typing import Dict, List, Optional

from dnslib import DNSRecord, QTYPE, RR, A

logger = logging.getLogger(__name__)

class OASTEvent:
    def __init__(self, protocol: str, remote_addr: str, identifier: str, data: str = ""):
        self.timestamp = datetime.now()
        self.protocol = protocol
        self.remote_addr = remote_addr
        self.identifier = identifier
        self.data = data

class OASTServer:
    def __init__(self, domain: str, public_ip: str):
        self.domain = domain.strip(".")
        self.public_ip = public_ip
        self.events: List[OASTEvent] = []
        self._http_server: Optional[asyncio.AbstractServer] = None
        self._dns_protocol: Optional[asyncio.DatagramTransport] = None

    async def start(self, http_port: int = 80, dns_port: int = 53):
        # Start HTTP server
        try:
            self._http_server = await asyncio.start_server(
                self._handle_http, "0.0.0.0", http_port
            )
            logger.info(f"[OAST] HTTP listener started on port {http_port}")
        except Exception as e:
            logger.error(f"[OAST] Failed to start HTTP listener: {e}")

        # Start DNS server (UDP)
        try:
            loop = asyncio.get_running_loop()
            self._dns_protocol, _ = await loop.create_datagram_endpoint(
                lambda: DNSResponder(self),
                local_addr=("0.0.0.0", dns_port)
            )
            logger.info(f"[OAST] DNS listener started on port {dns_port}")
        except Exception as e:
            logger.error(f"[OAST] Failed to start DNS listener: {e}")

    async def stop(self):
        if self._http_server:
            self._http_server.close()
            await self._http_server.wait_closed()
        if self._dns_protocol:
            self._dns_protocol.close()

    async def _handle_http(self, reader, writer):
        addr = writer.get_extra_info("peername")
        data = await reader.read(4096)
        request = data.decode(errors="replace")
        
        # Extract identifier from Host header or path
        # Assuming identifier is <uuid>.<domain>
        host = ""
        for line in request.splitlines():
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        
        identifier = host.split(".")[0] if host else "unknown"
        
        event = OASTEvent("HTTP", addr[0], identifier, request)
        self.events.append(event)
        logger.warning(f"[OAST] Received HTTP callback from {addr[0]} for {identifier}")
        
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    def register_dns_event(self, addr: str, identifier: str, qname: str):
        event = OASTEvent("DNS", addr, identifier, f"Query for {qname}")
        self.events.append(event)
        logger.warning(f"[OAST] Received DNS callback from {addr} for {identifier}")

class DNSResponder(asyncio.DatagramProtocol):
    def __init__(self, server: OASTServer):
        self.server = server

    def datagram_received(self, data, addr):
        try:
            record = DNSRecord.parse(data)
            qname = str(record.q.qname).strip(".")
            
            # Identifier is the first label: <uuid>.oast.domain.com
            identifier = qname.split(".")[0]
            self.server.register_dns_event(addr[0], identifier, qname)

            reply = record.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.server.public_ip), ttl=60))
            self.transport.sendto(reply.pack(), addr)
        except Exception as e:
            logger.error(f"[OAST] DNS parse error: {e}")
