# LiquidSky keylogger PoC

Little proof of concept keylogger for LiquidSky.

LiquidSky is using Protobuf for all communication between the server and client (Video is streamed over RTP).
This tool decodes the protobuf packets and prints them in a human-readable form.
It also has a keylogger mode that will print keypresses as readable text in near real-time.

It currently can sniff on local network interfaces or use a pcap file as input.

## Usage
```
usage: liquidsky_keylogger.py [-h] [-p PCAP] [-k] [-u]

optional arguments:
  -h, --help            show this help message and exit
  -p PCAP, --pcap PCAP  Read pcap file as input
  -k, --keylogger       Keylogger mode (print keypresses)
  -u, --unfiltered      Print all packets (can be spammy!)
```
Keylogger mode will output characters in near real-time, special keys (e.g. Return) will be printed as `(keyname)` instead.

The default mode will print packets in a format similar to this:
```
[CLIENT->SERVER] KEYBOARD_ACTION_V2             | JSON: {"keyActionV2": {"scancode": 33, "vkey": 70}, "type": "KEYBOARD_ACTION_V2"}
```
The unfiltered switch will also cause ping/pongs and mouse movement to be printed, it can be *very* spammy.

## Some more stuff
In [/proto](proto/) you will find the .proto files extracted from the client. The protobuf messages are sent over TCP with what seems to be a proprietary protocol. Some notes on how those packets are built (not necessarily correct) can be found in the [liquidsky_keylogger.py](liquidsky_keylogger.py) file.
