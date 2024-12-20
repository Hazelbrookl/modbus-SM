from pymodbus.client.sync import ModbusTcpClient as ModbusClient
# from pymodbus.client.sync import ModbusUdpClient as ModbusClient
# from pymodbus.client.sync import ModbusSerialClient as ModbusClient
from dataclasses import dataclass
from typing import Dict, Any
import json

# --------------------------------------------------------------------------- #
# this is an example for ModbusTCP Client
# the use is similar to the origin use
# the only difference is that you have to log the setting json
# which have the key you need
# config
# --------------------------------------------------------------------------- #

SERVER_HOST = "localhost"
SERVER_PORT = 502

UNIT = 0x1


@dataclass
class Setting:
    private_key: str
    public_key: str
    client_public_key: str

    @classmethod
    def from_json(cls, path='server_settings.json'):
        with open(path) as f:
            data = json.load(f)
        return cls(**data)


def run_sync_client(settings):

    client = ModbusClient(SERVER_HOST, port=SERVER_PORT, private_key=settings.private_key, public_key=settings.public_key, trusted_key=settings.server_public_key)
    client.connect()

    # ------------------------------------------------------------------------#
    # specify slave to query
    # ------------------------------------------------------------------------#
    # The slave to query is specified in an optional parameter for each
    # individual request. This can be done by specifying the `unit` parameter
    # which defaults to `0x00`
    # ----------------------------------------------------------------------- #
    print("Test 1: Reading single coil at address 1")
    rr = client.read_coils(1, 1, unit=UNIT)

    # ----------------------------------------------------------------------- #
    # example requests
    # ----------------------------------------------------------------------- #
    # simply call the methods that you would like to use. An example session
    # is displayed below along with some assert checks. Note that some modbus
    # implementations differentiate holding/input discrete/coils and as such
    # you will not be able to write to these, therefore the starting values
    # are not known to these tests. Furthermore, some use the same memory
    # blocks for the two sets, so a change to one is a change to the other.
    # Keep both of these cases in mind when testing as the following will
    # _only_ pass with the supplied asynchronous modbus server (script supplied).
    # ----------------------------------------------------------------------- #
    print("Test 2: Writing TRUE to coil at address 0 and verifying the value")
    rq = client.write_coil(0, True, unit=UNIT)
    rr = client.read_coils(0, 1, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.bits[0] == True)          # test the expected value

    print("Test 3: Writing TRUE to 8 consecutive coils starting at address 1 and reading 21 coils")
    rq = client.write_coils(1, [True]*8, unit=UNIT)
    rr = client.read_coils(1, 21, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    resp = [True]*21

    # If the returned output quantity is not a multiple of eight,
    # the remaining bits in the final data byte will be padded with zeros
    # (toward the high order end of the byte).

    resp.extend([False]*3)
    assert(rr.bits == resp)         # test the expected value

    print("Test 4: Writing FALSE to 8 consecutive coils starting at address 1 and verifying values")
    rq = client.write_coils(1, [False]*8, unit=UNIT)
    rr = client.read_coils(1, 8, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.bits == [False]*8)         # test the expectvalue

    print("Test 5: Reading 8 discrete inputs starting from address 0")
    rr = client.read_discrete_inputs(0, 8, unit=UNIT)
    assert(not rr.isError())     # test that we are not an error

    print("Test 6: Writing value 10 to holding register at address 1 and verifying the value")
    rq = client.write_register(1, 10, unit=UNIT)
    rr = client.read_holding_registers(1, 1, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.registers[0] == 10)       # test the expected value

    print("Test 7: Writing value 10 to 8 consecutive holding registers starting at address 1")
    rq = client.write_registers(1, [10]*8, unit=UNIT)
    rr = client.read_holding_registers(1, 8, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.registers == [10]*8)      # test the expected value

    print("Test 8: Reading 8 input registers starting from address 1")
    rr = client.read_input_registers(1, 8, unit=UNIT)
    assert(not rr.isError())     # test that we are not an error

    arguments = {
        'read_address':    1,
        'read_count':      8,
        'write_address':   1,
        'write_registers': [20]*8,
    }
    print("Test 9: Simultaneous read/write operation - writing 20 to 8 registers while reading previous values")
    rq = client.readwrite_registers(unit=UNIT, **arguments)
    rr = client.read_holding_registers(1, 8, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rq.registers == [20]*8)      # test the expected value
    assert(rr.registers == [20]*8)      # test the expected value

    print("-----------------------------------------------All test passed!-----------------------------------------------")
    # ----------------------------------------------------------------------- #
    # close the client
    # ----------------------------------------------------------------------- #
    client.close()


if __name__ == "__main__":
    settings = Setting.from_json('server_settings.json')
    run_sync_client(settings)