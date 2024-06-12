import asyncio
import logging
import subprocess

async def capture_packets(interface='Wi-Fi', filter_expression=None, packet_limit=None):
    process = None
    try:
        command = ["tshark", "-i", interface, "-T", "fields", "-e", "frame.protocols", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport"]
        if filter_expression:
            command.extend(["-f", filter_expression])

        process = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        count = 0
        buffer_size = 1024  # Adjust as needed
        while True:
            data = await process.stdout.read(buffer_size)
            if not data:
                break
            lines = data.decode().splitlines()
            for line in lines:
                packet_data = line.strip().split('\t')
                logging.info("Captured Packet Data: %s", packet_data)
                yield packet_data
                count += 1
                if packet_limit and count >= packet_limit:
                    break
            if packet_limit and count >= packet_limit:
                break

        await process.wait()  # Wait for the subprocess to complete
    except Exception as e:
        logging.error(f"Error capturing packets: {e}")
    finally:
        if process:
            process.stdout.close()
            await process.wait()
