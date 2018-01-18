# Python

import json
import sys
from google.protobuf.message import DecodeError
from google.protobuf import json_format
from proto_py import InputClient_pb2
from scapy.all import IP, TCP, sniff
from utils.key_codes import key_codes

req = InputClient_pb2.Request()
res = InputClient_pb2.Response()
val = InputClient_pb2.VariableValue()

print_keystrokes = False
filtered = True
ports = [80, 6666]

# Some notes on the packets structure itself (incomplete packet):
# 00000000  00 00 00 21 01 22 00 00  08 0f c2 02 1c 0a 16 42   ...!.".. .......B
#          |        Header        |  |  Protobuf messages  |
# Header structure seems to be:
# Bytes 1-4: Size of the Protobuf message
# Byte 5: Always 0x1?
# Byte 6: Checksum, all bytes of the header minus checksum byte added up
# Bytes 7-8: Counter


def to_json(proto_msg):
    # MessageToJson contains line breaks, but we want everything to be one line, hence this uglyness
    if type(proto_msg) == dict:
        return json.dumps(proto_msg, sort_keys=True)
    return json.dumps(json_format.MessageToDict(proto_msg), sort_keys=True)


def write_keystroke(req):
    # Only print first key event, ignore unpress event, etc.
    if req.keyActionV2.flags:
        return
    vkey = req.keyActionV2.vkey
    key_name = key_codes.get(vkey, 'Unknown')
    if key_name == 'enter':
        key_name = '(Return)\n'
    elif key_name == 'spacebar':
        key_name = ' '
    elif key_name in ['shift', 'ctrl']:  # don't print those
        return
    elif len(key_name) > 1:
        key_name = "(%s)" % key_name
    sys.stdout.write(key_name)
    sys.stdout.flush()


def parse_request(req):
    if not filtered or req.type not in [req.NETWORK_PING, req.MOUSE_ACTION]:
        # Little workaround for VariableEvent which has an encoded "value" field
        if req.variableEvent.value:
            val.ParseFromString(req.variableEvent.value)
            msg_d = json_format.MessageToDict(req)
            msg_d['variableEvent']['value'] = json_format.MessageToDict(val)
            msg = 'JSON: %s' % to_json(msg_d)
        else:
            msg = 'JSON: %s' % to_json(req)
    else:
        return
    print '[CLIENT->SERVER]', req.RequestType.Name(req.type).ljust(30), '|', msg


def parse_response(res):
    if not filtered or res.type not in [res.CURSOR_HASH, res.NETWORK_PONG]:  # ignore spammy messages
        if res.variableEvent.value:
            val.ParseFromString(res.variableEvent.value)
            msg_d = json_format.MessageToDict(res)
            msg_d['variableEvent']['value'] = json_format.MessageToDict(val)
            msg = 'JSON: %s' % to_json(msg_d)
        else:
            msg = "JSON: %s" % to_json(res)
    else:
        return
    print '[SERVER->CLIENT]', res.ResponseType.Name(res.type).ljust(30), '|', msg


def pkt_callback(pkt):
    # Just some filters to ignore packets that aren't what we're looking for
    if TCP not in pkt:
        return
    if not (pkt[TCP].dport in ports or pkt[TCP].sport in ports):
        return
    if len(pkt[TCP].payload) > 9:
        pl = str(pkt[TCP].payload)
        if pl[8] == '\x08':
            try:
                # Client => Server
                if pkt[TCP].dport in ports:
                    req.ParseFromString(pl[8:])
                    if not print_keystrokes:
                        parse_request(req)
                    elif req.type == req.KEYBOARD_ACTION_V2:
                        write_keystroke(req)
                # Server => Client
                elif pkt[TCP].sport in ports:
                    res.ParseFromString(pl[8:])
                    if not print_keystrokes:
                        parse_response(res)
                else:
                    print "Invalid packet, how did this get here?"
            except DecodeError:
                pass

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--pcap', type=str, help='Read pcap file as input', default='')
    parser.add_argument('-k', '--keylogger', help='Keylogger mode (print keypresses)', action='store_true')
    parser.add_argument('-u', '--unfiltered', help='Print all packets (can be spammy!)', action='store_true')
    args = parser.parse_args()

    if args.keylogger:
        print_keystrokes = True

    if args.unfiltered:
        print "Unfiltered mode enabled, this will print ALL packets including mouse movement, prepare for spam!"
        filtered = False

    if args.pcap:
        print 'Reading from pcap: %s' % args.pcap
        sniff(offline=args.pcap, prn=pkt_callback, store=0)
    else:
        print "Starting sniffing..."
        ports_filter = ' or '.join([str(p) for p in ports])
        sniff(filter="tcp port %s" % ports_filter, prn=pkt_callback, store=0)
