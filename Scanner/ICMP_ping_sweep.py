import asyncio
import platform
import subprocess
from ipaddress import ip_network

async def ping(ip: str, timeout=1):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # macOS/linux: send 1 packet, wait timeout seconds
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return await proc.wait() == 0

async def sweep(network_cidr, concurrency=200):
    net = ip_network(network_cidr)
    sem = asyncio.Semaphore(concurrency)
    async def worker(ip):
        async with sem:
            alive = await ping(str(ip))
            if alive:
                print(f"{ip} is UP")

    tasks = [worker(ip) for ip in net.hosts()]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    import sys
    cidr = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    asyncio.run(sweep(cidr))
