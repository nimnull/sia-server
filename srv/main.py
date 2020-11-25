import asyncio
import logging
import sys

import uvloop

from srv.sia import parse_sia, ack_sia, nack_sia, set_states_sia, get_crc_format

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

log = logging.getLogger()
log.addHandler(logging.StreamHandler(stream=sys.stderr))
log.setLevel(logging.DEBUG)

LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = 8888


async def handle(reader, writer):
    data = await reader.read()

    addr = writer.get_extra_info('peername')
    log.info("Received %r from %r", data, addr)

    sia = parse_sia(data)

    if sia:
        ack = ack_sia(sia)
        if ack:
            # set states only if ACK okay
            set_states_sia(sia)
        else:
            crcformat = get_crc_format(data)
            ack = nack_sia(crcformat)
    else:
        crcformat = get_crc_format(data)
        ack = nack_sia(crcformat)

    writer.write(ack.encode())
    await writer.drain()

    log.info("Close the client socket")
    writer.close()


def create_server(address, port):
    loop = uvloop.new_event_loop()
    coro = asyncio.start_server(handle, address, port)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    log.info('Serving on %s:%s', address, port)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        # Close the server
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


if __name__ == '__main__':
    create_server(LISTEN_ADDR, LISTEN_PORT)
