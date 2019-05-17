# (C) Copyright 2016 Comsecuris UG
# https://sourceware.org/gdb/onlinedocs/gdb/Events-In-Python.html#Events-In-Python

from __future__ import print_function
import os
import socket
import struct
import json

GHIDRA_BRIGE_IP = '127.0.0.1'
GHIDRA_BRIDGE_PORT = 2305
GHIDRA_ANSWER_PORT = 2306

INIT_BP_WORKAROUND = False
DEBUG = 1



socket.setdefaulttimeout(0.1)

class GhidraBridge(gdb.Command):
    def __init__(self):
        super (GhidraBridge, self).__init__("ghidrabridge", gdb.COMMAND_USER)
        self._ghidra_ip = GHIDRA_BRIGE_IP
        self._ghidra_port = GHIDRA_BRIDGE_PORT
        self._ghidra_answer_port = GHIDRA_ANSWER_PORT
        self._init_bps = []
        self._img_reloc = False
        self._socket = None
        self._connected = False
        self._arch = None
        self._endian = None
        self._regs = {}

    def connect(self):
        print("connect")
        if self._connected:
            return

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._ghidra_ip, self._ghidra_port))
        self._connected = True
        self.send_hello()
        
    def disconnect(self):
        print("disconnect")
        if self._connected:
            self._socket.close()
            self._connected = False

    def hdl_stop_event(self, event):
        print("hdl_stop_event")
        # in case we want to ignore all breakpoints that were set before the ghidrabridge was launched.
        if isinstance(event, gdb.BreakpointEvent) and event.breakpoint in self._init_bps:
            return
            
        self.update_cursor_to(gdb.selected_frame().pc(), self.get_relocation())
        self._get_register_values()

    def send_hello(self):
        message = json.dumps({
            "type":"HELLO",
            "data":[ {
                "arch":self.get_arch(),
                "endian":self.get_endian(),
                "answerport":str(self._ghidra_answer_port),
                } ], 
            })
        self.tell_ghidra(message)

    def update_cursor_to(self, address, relocate):
        message = json.dumps({
            "type":"CURSOR",
            "data":[ {"address":hex(gdb.selected_frame().pc()), "relocate":relocate } ],
            })
        self.tell_ghidra(message)

    def get_arch(self):
        if not self._arch:
            self._arch = self._query_gdb('show arch', 'architecture', "(currently ", ")")
            
        return self._arch
    
    def get_endian(self):
        if not self._endian:
            self._endian = self._query_gdb('show endian', 'endianess', "(currently ", " endian)")
            
        return self._endian
    
    def _query_gdb(self, cmd, name, extract_begin, extract_end):
        val = gdb.execute(cmd, to_string=True)
        s_text = val.find(extract_begin)
        e_text = val.find(extract_end)
        if s_text == -1:
            print("could not determine %s setting to 'unknown'" % name)
            return 'unknown'
        
        result = val[s_text + len(extract_begin):e_text]
        print("found %s '%s'" % (name, result))
        return result.strip()

    def update_register(self, address, register, value):
        message = json.dumps({
            "type":"REGISTER",
            "data":[{"address":address,"name":register,"value":value}]
            })
        self.tell_ghidra(message)

    def _get_register_values(self):
        print("_get_register_values")
        address = hex(gdb.selected_frame().pc())
        val = gdb.execute("i r", to_string=True)
        for reg, value in map(lambda x: x.split()[:2], val.split("\n")[:-1]):
            if reg in self._regs and self._regs[reg] == value: continue 
            
            self._regs[reg] = value
            
            self.update_register(address, reg, value)


    def get_relocation(self):
        print("get_relocation")
        if self._img_reloc:
            return self._img_reloc
        
        self._img_reloc = self._query_gdb('info proc stat', 'relocation', 'Start of text: ', 'End of text: ')
        
        print("using %s as text relocation\n" %(self._img_reloc))

        return self._img_reloc

    def get_pc(self):
            val = gdb.selected_frame().pc()
            return val
    
    def tell_ghidra(self, message):
        print("tell_ghidra")
        try:
            self.connect()
        except Exception as e:
            self.disconnect()
            self.connect()
        
        self._socket.send(bytes(message + "\n", 'UTF-8'))

    def invoke(self, arg, from_tty):
            argv = arg.split(' ')
            if len(argv) < 1:
                    print("ghidrabridge <ip:port>")
                    return

            target = argv[0].split(':')

            if not '.' in target[0] or len(target) < 2:
                    print("please specify ip:port combination")
                    return

            self._ghidra_ip = target[0]
            self._ghidra_port = int(target[1])
            print("ghidrabridge: using ip: %s port: %d\n" %(self._ghidra_ip, self._ghidra_port))

            self.connect()

            if INIT_BP_WORKAROUND:
                    self._init_bps = gdb.breakpoints()

            gdb.events.stop.connect(self.hdl_stop_event)
    
GhidraBridge()
