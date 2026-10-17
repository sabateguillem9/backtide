"""The fake resolver of the T06-1 checks (P5): logs every DNS query that reaches it.

Runs in a throwaway container on the agent's network, which the test's agent gets as its
``--dns``. If Docker's embedded resolver ever forwarded an outside name from a container that
is only on internal networks, the query would land here. Every query is printed as
``query <name>`` (read with ``docker logs``) and answered NXDOMAIN, over UDP and TCP on 53.
Standard library only. Prints READY_LINE once both listen.
"""

import socket
import struct
import threading

READY_LINE = "t06-dns-ready"


def question_name(packet: bytes) -> str:
    labels, offset = [], 12
    while offset < len(packet) and packet[offset] != 0:
        size = packet[offset]
        labels.append(packet[offset + 1 : offset + 1 + size].decode("ascii", "replace"))
        offset += 1 + size
    return ".".join(labels)


def nxdomain(packet: bytes) -> bytes:
    if len(packet) < 12:
        return b""
    (ident,) = struct.unpack("!H", packet[:2])
    end = packet.find(b"\x00", 12)
    question = packet[12 : end + 5] if end > 0 else b""
    count = 1 if question else 0
    # QR=1, opcode 0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    return struct.pack("!HHHHHH", ident, 0x8183, count, 0, 0, 0) + question


def serve_udp(sock: socket.socket) -> None:
    while True:
        packet, peer = sock.recvfrom(4096)
        print(f"query {question_name(packet)} udp from {peer[0]}", flush=True)
        sock.sendto(nxdomain(packet), peer)


def serve_tcp(sock: socket.socket) -> None:
    while True:
        conn, peer = sock.accept()
        with conn:
            conn.settimeout(5)
            try:
                (size,) = struct.unpack("!H", conn.recv(2))
                packet = conn.recv(size)
            except (OSError, struct.error):
                continue
            print(f"query {question_name(packet)} tcp from {peer[0]}", flush=True)
            reply = nxdomain(packet)
            conn.sendall(struct.pack("!H", len(reply)) + reply)


def main() -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 53))  # noqa: S104 - inside a test container
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", 53))  # noqa: S104 - inside a test container
    tcp.listen(16)
    threading.Thread(target=serve_tcp, args=(tcp,), daemon=True).start()
    threading.Thread(target=serve_udp, args=(udp,), daemon=True).start()
    print(READY_LINE, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
