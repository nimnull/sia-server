import io
import logging
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(init=False)
class Sia:
# undefined
    id: Optional[str] = None
    seq: Optional[str] = None
    lpref: Optional[str] = None
    act: Optional[str] = None
    pad: Optional[str] = None
# defined
    data: Optional[bytes] = None
    lf: Optional[bytes] = None
    len: Optional[int] = None
    crc: Optional[int] = None
    crcformat: Optional[str] = None
    cr: Optional[int] = None
    str: Optional[str] = None
    calc_len: Optional[int] = None
    calc_crc: Optional[int] = None


def parse_sia(message: bytes) -> Any:
    data = message.rstrip(b'0')
    logging.info("Data: %s", data)
    msg_len = len(data) - 1
    sia = Sia()
    # test for \n character at the start and \r at the end of the message
    if data and data[0] == 0x0a and data[msg_len] == 0x0d:
        sia.data = data
        sia.lf = data[0]
        # Check if CRC 2 Byte Binary or 4 Byte HEX
        if data[5] == ord('0') and data[9] == ord('"'):
            str_buffer = data[9:msg_len]
            sia.len = int(data[5:9], 16)
            sia.crc = int(data[1:5], 16)
            sia.crcformat = 'hex'
            logging.debug("Buffer hex: %s", str_buffer)
        # // Lupusec sends the CRC in binary forum
        if data[3] == ord('0') and data[7] == ord('"'):
            str_buffer = data[7:msg_len]
            sia.len = int(data[3:7], 16)
            sia.crc = data[1] * 256 + data[2]
            sia.crcformat = 'bin'
            logging.debug("Buffer bin: %s", str_buffer)

        sia.cr = data[msg_len]  # <cr>
        sia.str = str_buffer.decode()
        sia.calc_len = len(str_buffer)
        sia.calc_crc = crc16(str_buffer)

        logging.debug("parseSIA sia.str : %s", sia.str)
        logging.debug("CRC matched: %s:", sia.calc_crc == sia.crc)
        if sia.calc_len != sia.len or sia.calc_crc != sia.crc:
            return None
    # if (sia.calc_len != sia.len || sia.calc_crc != sia.crc) {
    #   adapter.log.info("CRC or Length different to the caclulated values");
    #   adapter.log.debug("SIA crc= " + sia.crc + ", calc_crc=" + sia.calc_crc);
    #   adapter.log.debug("SIA len= " + sia.len + ", calc_len=" + sia.calc_len);
    #   adapter.log.debug("Message for CRC and LEN calculation" + sia.str);
    #   adapter.log.debug("Message for CRC and LEN calculation (String)" + sia.str.toString());
    #   return undefined;
    #   // sia.calc_len = sia.len;
    #   // sia.calc_crc = sia.crc;
    # }

    required_fields = ['id', 'seq', 'lpref', 'act', 'pad']
    if sia and all([getattr(sia, field) is not None for field in required_fields]):
        return sia

    logging.info("Required SIA fields missing")
    return None


def ack_sia(sia):
    return 'None'


def set_states_sia(sia):
    return 'None'


def get_crc_format(message):
    return 'None'


def nack_sia(crcformat):
    return 'None'


def crc16(data: bytes):
    # CRC table for the CRC-16. The poly is 0x8005 (x^16 + x^15 + x^2 + 1)
    crctab16 = (
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
    )
    data = bytearray(data)
    crc = 0
    for idx, el in enumerate(data):
        crc = (crc >> 8) ^ (crctab16[(crc ^ (data[idx])) & 0xff])
    return crc
