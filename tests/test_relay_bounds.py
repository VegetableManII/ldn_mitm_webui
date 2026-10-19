"""Bounded offline routing checks. No real sockets or external packets."""
import importlib.util, ipaddress, json, socket, types
from pathlib import Path
source = Path(__file__).resolve().parents[1] / "vendor/relay_server.py"
spec = importlib.util.spec_from_file_location("audited_relay", source)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
class EndSimulation(Exception): pass
class FakeSocket:
    def __init__(self, packets): self.packets=iter(packets); self.sent=[]
    def setsockopt(self,*args): pass
    def bind(self,*args): pass
    def recvfrom(self,size):
        try: return next(self.packets)
        except StopIteration: raise EndSimulation()
    def sendto(self,data,addr): self.sent.append((data,addr)); return len(data)
def simulate(packets):
    fake=FakeSocket(packets)
    relay.socket=types.SimpleNamespace(**{k:getattr(socket,k) for k in dir(socket) if k!="socket"}, socket=lambda *a,**kw:fake)
    relay.print=lambda *args,**kwargs:None
    try: relay.main(["--port","11544"])
    except EndSimulation as exc:
        frame=exc.__traceback__
        while frame and frame.tb_frame.f_code.co_name!="main": frame=frame.tb_next
        state=frame.tb_frame.f_locals
        return fake, {k:len(state[k]) for k in ["clients","scopes"]}
    raise AssertionError("simulation did not stop")
def frame(src,dst="255.255.255.255",payload=b"sample"):
    h=bytearray(20);h[0]=0x45;h[9]=17
    h[12:16]=ipaddress.IPv4Address(src).packed;h[16:20]=ipaddress.IPv4Address(dst).packed
    udp=b"\x12\x34\x30\x39\x00\x0e\x00\x00"
    return b"\x01"+h+udp+payload

import unittest

class RelayBoundsTests(unittest.TestCase):
    def test_capacity_and_routing(self):
        A=("192.0.2.1",30001); B=("192.0.2.2",30002); C=("192.0.2.3",30003)
        scope=lambda n:b"\x20"+n.to_bytes(4,"big")
        _, c=simulate([(frame(str(ipaddress.IPv4Address(0x0a000001+i))),A) for i in range(300)])
        assert c["clients"]==64,c
        _, c=simulate([(scope(i+1),("192.0.2.1",10000+i)) for i in range(1400)])
        assert c["scopes"]==1024,c
        _, c=simulate([(b"\xff",("192.0.2.1",10000+i)) for i in range(1400)])
        assert c=={"clients":0,"scopes":0},c
        _, c=simulate([(frame(str(ipaddress.IPv4Address(0x0a000001+i)),"10.250.0.1"),("192.0.2.1",10000+i//64)) for i in range(4300)])
        assert c["clients"]==4096,c
        packet=frame("10.13.1.2")
        fake,c=simulate([(scope(42),A),(frame("10.13.1.1"),A),(scope(99),B),(packet,B),(frame("10.13.1.3"),C),(packet,B)])
        assert (packet,C) in fake.sent
        assert (packet,A) not in fake.sent
        unicast=frame("10.13.1.1","10.13.1.2")
        fake,c=simulate([(frame("10.13.1.2"),B),(unicast,A)])
        assert (unicast,B) in fake.sent
        ping=b"\x02abc"
        fake,c=simulate([(ping,A)])
        assert (ping,A) in fake.sent
