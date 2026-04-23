from __future__ import annotations

import asyncio
import os
from datetime import datetime
from pathlib import Path


LOG_FILE = Path("/var/log/firewall.log")
PORTS = [int(item.strip()) for item in os.getenv("LAB_FIREWALL_PORTS", "2201,2202,2203,2204,2205,2206,2207,2208").split(",") if item.strip()]


def format_line(peer_ip: str, peer_port: int, local_ip: str, local_port: int) -> str:
    ts = datetime.utcnow().strftime("%b %d %H:%M:%S")
    return (
        f"{ts} target kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 "
        f"SRC={peer_ip} DST={local_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=54321 DF "
        f"PROTO=TCP SPT={peer_port} DPT={local_port} WINDOW=64240 RES=0x00 SYN URGP=0"
    )


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    local = writer.get_extra_info("sockname")
    peer_ip, peer_port = peer[0], peer[1]
    local_ip, local_port = local[0], local[1]
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle_out:
        handle_out.write(format_line(peer_ip, peer_port, local_ip, local_port) + "\n")
    writer.close()
    await writer.wait_closed()


async def main() -> None:
    servers = [await asyncio.start_server(handle, host="0.0.0.0", port=port) for port in PORTS]
    async with asyncio.TaskGroup() as task_group:
        for server in servers:
            task_group.create_task(server.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
