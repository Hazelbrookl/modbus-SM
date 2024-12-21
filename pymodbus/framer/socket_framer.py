import struct
import time
import random
from pymodbus.exceptions import ModbusIOException
from pymodbus.exceptions import InvalidMessageReceivedException
from pymodbus.utilities import hexlify_packets
from pymodbus.framer import ModbusFramer, SOCKET_FRAME_HEADER
from pymodbus.constants import Defaults
from gmssl import sm2, sm3, sm4

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
import logging
_logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Modbus TCP Message
# --------------------------------------------------------------------------- #


class ModbusSocketFramer(ModbusFramer):
    """ Modbus Socket Frame controller

    Before each modbus TCP message is an MBAP header which is used as a
    message frame.  It allows us to easily separate messages as follows::

        [         MBAP Header         ] [ Function Code] [ Data ] \
        [ tid ][ pid ][ length ][ uid ]
          2b     2b     2b        1b           1b           Nb

        while len(message) > 0:
            tid, pid, length`, uid = struct.unpack(">HHHB", message)
            request = message[0:7 + length - 1`]
            message = [7 + length - 1:]

        * length = uid + function code + data
        * The -1 is to account for the uid byte
    """

    def __init__(self, decoder, client=None, private_key=None, public_key=None, sm4_key=None, certificate_key=None):
        """ Initializes a new instance of the framer

        :param decoder: The decoder factory implementation to use
        """
        self._buffer = b''
        self._header = {'tid': 0, 'pid': 0, 'len': 0, 'uid': 0}
        self._hsize = 0x07
        self.decoder = decoder
        self.client = client
        if public_key and private_key:
            self.crypter_sm2 = sm2.CryptSM2(private_key=private_key, public_key=public_key)
        else:
            self.crypter_sm2 = None
        self.sm4_key = sm4_key
        self.crypter_sm4 = sm4.CryptSM4()
        self.certificate_key = certificate_key

    # ----------------------------------------------------------------------- #
    # Private Helper Functions
    # ----------------------------------------------------------------------- #
    def checkFrame(self):
        """
        Check and decode the next frame Return true if we were successful
        """
        if self.isFrameReady():
            (self._header['tid'], self._header['pid'],
             self._header['len'], self._header['uid']) = struct.unpack(
                '>HHHB', self._buffer[0:self._hsize])

            # someone sent us an error? ignore it
            if self._header['len'] < 2:
                self.advanceFrame()
            # we have at least a complete message, continue
            elif len(self._buffer) - self._hsize + 1 >= self._header['len']:
                return True
        # we don't have enough of a message yet, wait
        return False

    def advanceFrame(self):
        """ Skip over the current framed message
        This allows us to skip over the current message after we have processed
        it or determined that it contains an error. It also has to reset the
        current frame header handle
        """
        length = self._hsize + self._header['len'] - 1
        self._buffer = self._buffer[length:]
        self._header = {'tid': 0, 'pid': 0, 'len': 0, 'uid': 0}

    def isFrameReady(self):
        """ Check if we should continue decode logic
        This is meant to be used in a while loop in the decoding phase to let
        the decoder factory know that there is still data in the buffer.

        :returns: True if ready, False otherwise
        """
        return len(self._buffer) > self._hsize

    def addToFrame(self, message):
        """ Adds new packet data to the current frame buffer

        :param message: The most recent packet
        """
        self._buffer += message

    def getFrame(self):
        """ Return the next frame from the buffered data

        :returns: The next full frame buffer
        """
        length = self._hsize + self._header['len'] - 1
        return self._buffer[self._hsize:length]

    def populateResult(self, result):
        """
        Populates the modbus result with the transport specific header
        information (pid, tid, uid, checksum, etc)

        :param result: The response packet
        """
        result.transaction_id = self._header['tid']
        result.protocol_id = self._header['pid']
        result.unit_id = self._header['uid']

    # ----------------------------------------------------------------------- #
    # Public Member Functions
    # ----------------------------------------------------------------------- #
    def decode_data(self, data):
        if len(data) > self._hsize:
            tid, pid, length, uid, fcode = struct.unpack(SOCKET_FRAME_HEADER,
                                                         data[0:self._hsize+1])
            return dict(tid=tid, pid=pid, length=length, unit=uid, fcode=fcode)
        return dict()

    def processIncomingPacket(self, data, callback, unit, **kwargs):
        """
        The new packet processing pattern

        This takes in a new request packet, adds it to the current
        packet stream, and performs framing on it. That is, checks
        for complete messages, and once found, will process all that
        exist.  This handles the case when we read N + 1 or 1 // N
        messages at a time instead of 1.

        The processed and decoded messages are pushed to the callback
        function to process and send.

        :param data: The new packet data
        :param callback: The function to send results to
        :param unit: Process if unit id matches, ignore otherwise (could be a
               list of unit ids (server) or single unit id(client/server)
        :param single: True or False (If True, ignore unit address validation)
        :return:
        """
        if not isinstance(unit, (list, tuple)):
            unit = [unit]
        single = kwargs.get("single", False)
        _logger.debug("Processing: " + hexlify_packets(data))
        self.addToFrame(data)
        while True:
            if self.isFrameReady():
                if self.checkFrame():
                    if self._validate_unit_id(unit, single):
                        self._process(callback)
                    else:
                        _logger.debug("Not a valid unit id - {}, "
                                      "ignoring!!".format(self._header['uid']))
                        self.resetFrame()
                else:
                    _logger.debug("Frame check failed, ignoring!!")
                    self.resetFrame()
            else:
                if len(self._buffer):
                    # Possible error ???
                    if self._header['len'] < 2:
                        self._process(callback, error=True)
                break

    def _process(self, callback, error=False):
        """
        Process incoming packets irrespective error condition
        """
        data = self.getRawFrame() if error else self.getFrame()

        if self.certificate_key:
            # 签名部分
            sign = data[-64:].hex()
            # 数据部分
            data = data[:-64]
            print("Signature:", sign)
            cpr = sm2.CryptSM2(public_key=self.certificate_key, private_key="")
            if not cpr.verify_with_sm3(sign, data):
                raise InvalidMessageReceivedException('Unverified')
            print("Verified")
        
        self.crypter_sm4.set_key(self.sm4_key.encode('utf-8'), sm4.SM4_DECRYPT)
        value = self.crypter_sm4.crypt_cbc(Defaults.iv, data[1:])
        data = data[0].to_bytes(1, 'big') + value

        result = self.decoder.decode(data)
        if result is None:
            raise ModbusIOException("Unable to decode request")
        elif error and result.function_code < 0x80:
            raise InvalidMessageReceivedException(result)
        else:
            self.populateResult(result)
            self.advanceFrame()
            callback(result)  # defer or push to a thread?

    def resetFrame(self):
        """
        Reset the entire message frame.
        This allows us to skip ovver errors that may be in the stream.
        It is hard to know if we are simply out of sync or if there is
        an error in the stream as we have no way to check the start or
        end of the message (python just doesn't have the resolution to
        check for millisecond delays).
        """
        self._buffer = b''
        self._header = {'tid': 0, 'pid': 0, 'len': 0, 'uid': 0}

    def getRawFrame(self):
        """
        Returns the complete buffer
        """
        return self._buffer

    def buildPacket(self, message):
        """
        Creates a ready-to-send Modbus packet.

        :param message: The populated request/response to send.
        :return: The fully constructed and optionally signed Modbus packet.
        """
        # 使用 SM4 加密消息
        self.crypter_sm4.set_key(self.sm4_key.encode('utf-8'), sm4.SM4_ENCRYPT)
        encrypted_data = self.crypter_sm4.crypt_cbc(Defaults.iv, message.encode())

        # 根据是否启用 SM2 签名确定签名长度
        len_sign = 64 if self.crypter_sm2 else 0

        # 构建 Modbus 数据包的头部
        packet_header = struct.pack(
            SOCKET_FRAME_HEADER,
            message.transaction_id,  # 事务标识符
            message.protocol_id,     # 协议标识符
            len(encrypted_data) + len_sign + 2,  # 数据长度 + 签名长度 + 固定长度字段
            message.unit_id,         # 单元标识符
            message.function_code    # 功能码
        )

        # 组装完整的包（头部 + 加密数据）
        packet = packet_header + encrypted_data

        # 如果启用了 SM2 签名功能，对功能码和消息加签
        if self.crypter_sm2:
            # 签名从功能码开始到整个消息的结束部分
            data_to_sign = packet[len(packet_header) - 1:]
            sign = self.crypter_sm2.sign_with_sm3(data_to_sign)  # 使用 SM3 签名
            print("Signature:", sign)
            packet += bytes.fromhex(sign)  # 将签名附加到包的末尾

        return packet


# __END__
