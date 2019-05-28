# MIT License                                                                     
#                                                                                 
# Copyright (c) 2019 Comsecuris UG (haftungsbeschränkt)                           
#                                                                               
# Permission is hereby granted, free of charge, to any person obtaining a copy       
# of this software and associated documentation files (the "Software"), to deal   
# in the Software without restriction, including without limitation the rights       
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell          
# copies of the Software, and to permit persons to whom the Software is           
# furnished to do so, subject to the following conditions:                        
#                                                                                 
# The above copyright notice and this permission notice shall be included in all  
# copies or substantial portions of the Software.                                 
#                                                                               
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR         
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,        
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE        
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER          
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,   
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE   
# SOFTWARE.   
# 
# https://sourceware.org/gdb/onlinedocs/gdb/Events-In-Python.html#Events-In-Python

from __future__ import print_function
import os
import socket
import struct
import json
import base64
import gzip
import tempfile
from threading import Thread

GHIDRA_BRIGE_IP = '127.0.0.1'
GHIDRA_BRIDGE_PORT = 2305
GDB_BRIDGE_IP = '127.0.0.1'
GDB_BRIDGE_PORT = 2306

socket.setdefaulttimeout(0.1)

class GhidraBridge():
    def __init__(self, ip, port):
        self._connected = False
        self._socket = None
        self._ghidra_ip = ip
        self._ghidra_port = port
        
    def connect(self):
        if self._connected and not self._socket._closed:
            return
        
        socket.setdefaulttimeout(10)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._ghidra_ip, self._ghidra_port))
        self._connected = True
        
    def disconnect(self):
        if self._connected:
            self._socket.close()
            self._connected = False

    def send_message(self, message):
        try:
            if not self._connected:
                self.connect()
            if not message: return
                
            self._socket.send(bytes(message + "\n", 'UTF-8'))
        except Exception as e:
            print(e)
            self.disconnect()
            self.connect()
            
    def close(self):
        self.disconnect()

class GDBBridge(Thread):
    # this is the connection from GHIDRA -> GDB
    def __init__(self, ip, port, ghidra_bridge):
        Thread.__init__(self)
        self.exit = False
        self._ghidra_bridge = ghidra_bridge
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((ip, port))
        self._sock.listen(1)
        self._sock.settimeout(10)
        
    def run(self):
        while not self.exit:
            try:
                (con, (ghidra_ip, ghidra_port)) = self._sock.accept()
                line = []
                while True:
                    c = con.recv(1)
                    if c == b'\n':
                        msg = json.loads(b"".join(line))
                        if msg["type"] == "BREAKPOINT":
                            self.handle_breakpoint(msg)
                        elif msg['type'] == "REGISTER":
                            self.handle_register(msg)
                        break                 
                    else:
                        line.append(c)
            
            except socket.timeout:
                pass
            
    def handle_register(self, msg):
        data = msg["data"][0]
        if data["action"] == "change":
            r = data["register"]
            v = data["value"]
            print("[GDBBridge] setting register '%s' to '%s'\n" % (r, v))
            GDBUtils.set_register(r, v)
            
    def handle_breakpoint(self, msg):
        data = msg["data"][0]
        for address in data["breakpoints"]:
            if not( "0x" in address):
                print("[GDBBridge] unknown address (missing 0x) '%s'\n" % address) 
                continue
            
            action = data["action"]
            
            if action == "toggle":
                bpnr, bpenabled = GDBUtils.return_breakpoint_at(address)
                if not bpnr:
                    print("[GDBBridge] adding breakpoint at address: %s\n" % address)
                    GDBUtils.query_gdb("break *%s" % address, "set breakpoint")
                    self._ghidra_bridge.send_message( GhidraMessages.breakpoint(address, "enable"))
                    continue
            
                if bpenabled == "y":
                    print("[GDBBridge] disabling breakpoint at address: %s\n" % address)
                    GDBUtils.query_gdb("disable %s" % bpnr, "disable breakpoint")
                    self._ghidra_bridge.send_message( GhidraMessages.breakpoint(address, "disable"))
                    continue
                
                elif bpenabled == "n":
                    print("[GDBBridge] enabling breakpoint at address: %s\n" % address)
                    GDBUtils.query_gdb("enable %s" % bpnr, "enable breakpoint")
                    self._ghidra_bridge.send_message( GhidraMessages.breakpoint(address, "enable"))
                    continue
            elif action == "delete":
                bpnr, bpenabled = GDBUtils.return_breakpoint_at(address)
                
                GDBUtils.query_gdb("delete %s" % bpnr, "delete breakpoint\n")
                self._ghidra_bridge.send_message( GhidraMessages.breakpoint(address, "delete"))
                continue
            else:
                print("[GDBBridge] unknown breakpoint action '%s'\n" % action)
                continue
            
    def close(self):
        self.exit = True
    

class GhidraMessages:
    @staticmethod
    def encode(msg):
        return json.dumps(msg)

    @staticmethod
    def update_cursor_to(address, using_relocation):
        # "data":[ {"address":hex(gdb.selected_frame().pc()), "relocate":relocate } ],
        msg = {
            "type":"CURSOR",
            "data":[ {
                "address":address, 
                "relocate":using_relocation 
            } ],
        }
        return GhidraMessages.encode(msg)
    
    @staticmethod
    def hello(arch, endian, gdb_ip, gdb_port):
        msg = {
            "type":"HELLO",
            "data":[ {
                "arch":arch,
                "endian":endian,
                "answer_ip":gdb_ip,
                "answer_port":str(gdb_port),
            } ], 
        }
        return GhidraMessages.encode(msg)
    
    @staticmethod
    def breakpoint(address, action):
        msg = {
            "type":"BREAKPOINT",
            "data":[ {
                "breakpoint":address,
                "action":action,
            } ], 
        }
        return GhidraMessages.encode(msg)
    
    @staticmethod
    def update_register(address, register, value):
        msg = {
            "type":"REGISTER",
            "data":[{
                "address":address,
                "name":register,
                "value":value
            }]
        }
        return GhidraMessages.encode(msg)
    
    @staticmethod
    def memory(address, mapping, data, read, write, execute):
        if mapping and data:
            msg ={
                "type":"MEMORY",
                "data":[{
                    "address":mapping["begin"], 
                    "name":mapping["name"], 
                    "data":data, 
                    "size":mapping["size"], 
                    "read":str(read), 
                    "write":str(write), 
                    "execute":str(execute)
                }]
            }
            return GhidraMessages.encode(msg)    
        
        return None
        
    
    
            
class GhidraBridgeCommand(gdb.Command):
    def __init__(self):
        super (GhidraBridgeCommand, self).__init__("ghidrabridge", gdb.COMMAND_USER)
        self._register_and_values = {}
        
        self._ghidra_ip = GHIDRA_BRIGE_IP
        self._ghidra_port = GHIDRA_BRIDGE_PORT
        
        self._ghidra_bridge = GhidraBridge(self._ghidra_ip, self._ghidra_port)
        
        self._gdb_ip = GDB_BRIDGE_IP
        self._gdb_port = GDB_BRIDGE_PORT
        
        self._gdb_bridge = GDBBridge(self._gdb_ip, self._gdb_port, self._ghidra_bridge)
        self._gdb_bridge.daemon = True
        self._gdb_bridge.start()
        
        self._ghidra_bridge.send_message( GhidraMessages.hello(GDBUtils.get_arch(), GDBUtils.get_endian(), self._gdb_ip, self._gdb_port) )
        
        

    def hdl_stop_event(self, event):
        self._ghidra_bridge.send_message( GhidraMessages.update_cursor_to( GDBUtils.get_instruction_pointer(), GDBUtils.get_relocation()) )
        self._update_register_values()
        self._ghidra_bridge.send_message( GhidraMessages.memory( GDBUtils.get_instruction_pointer(), GDBUtils.get_mapping("[stack]"), GDBUtils.get_encoded_stack(), True, True, False ))


    def _update_register_values(self):
        address = GDBUtils.get_instruction_pointer()
        
        for register, value in GDBUtils.get_registers_and_values():
            if register in self._register_and_values and self._register_and_values[register] == value: continue
            
            self._register_and_values[register] = value
            self._ghidra_bridge.send_message( GhidraMessages.update_register(address, register, value))
    
    def hdl_exit_event(self, event):
        self.close()

    def invoke(self, arg, from_tty):
            argv = arg.split(' ')
            if len(argv) < 1:
                    print("ghidrabridge <ip:port>\n")
                    return

            target = argv[0].split(':')

            if not '.' in target[0] or len(target) < 2:
                    print("please specify ip:port combination\n")
                    return

            self._ghidra_ip = target[0]
            self._ghidra_port = int(target[1])
            print("ghidrabridge: using ip: %s port: %d\n" %(self._ghidra_ip, self._ghidra_port))

            gdb.events.stop.connect(self.hdl_stop_event)
            gdb.events.exited.connect(self.hdl_exit_event)

    def close(self):
        self._gdb_bridge.close()
        self._gdb_bridge.join(2000)
        self._ghidra_bridge.close()

class GDBUtils:
    @staticmethod
    def get_relocation():
        r = GDBUtils.query_gdb('info proc stat', 'relocation', 'Start of text: ', 'End of text: ')
        if r == "unknown":
            return "0x0"
        
        return r
    
    @staticmethod
    def get_instruction_pointer():
        return hex(gdb.selected_frame().pc())
        
    @staticmethod
    def get_registers_and_values():
        result = []
        query_result = GDBUtils.query_gdb("info registers", "info registers")
        for register, value in map(lambda x: x.split()[:2], query_result.split("\n")[:-1]):
            result.append( [register, value] )
        return result

    @staticmethod
    def query_gdb(cmd, name, extract_begin=None, extract_end=None):
        val = gdb.execute(cmd, to_string=True)
        if not( extract_begin and extract_end ):
            return val
        
        s_text = val.find(extract_begin)
        e_text = val.find(extract_end)
        if s_text == -1:
            print("[GDBGHIDRA] could not determine %s setting to 'unknown'\n" % name)
            return 'unknown'
        result = val[s_text + len(extract_begin):e_text].strip()
        print("[GDBGHIDRA] found %s '%s'\n" % (name, result))
        return result
    
    @staticmethod
    def return_breakpoint_at(address):
        result = GDBUtils.query_gdb("info breakpoints", "info breakpoint").split("\n")
        for line in result:
            tokens = line.split()
            if "0x" in address:
                if address[2:] in line:
                    return ( tokens[0], tokens[3] )
            else:
                if address in line:
                    return ( tokens[0], tokens[3] ) 
        return (None, None)

    @staticmethod
    def get_encoded_memory(address, name, end, size):
        f = tempfile.NamedTemporaryFile(delete=False)
        gdb.execute("dump memory %s %s %s" % (f.name, address, end))
        with open(f.name, "rb") as m:
            data = base64.b64encode(gzip.compress(m.read())).decode('utf-8')
        
        f.delete
        return data


    @staticmethod
    def get_mapping(named):
        m = GDBUtils.query_gdb("info proc mappings", "mappings")
        if "unable to open" in m:
            return None
        
        x = list(filter(lambda e: named in e, m.split("\n")))[0].split()
        return {"begin":x[0], "end":x[1], "size":x[2], "name":named}
        
    @staticmethod
    def get_encoded_stack():
        mapping = GDBUtils.get_mapping("[stack]")
        if mapping:
            return GDBUtils.get_encoded_memory(mapping["begin"], "stack", mapping["end"], mapping["size"])
        return None

    @staticmethod
    def get_arch():
        return GDBUtils.query_gdb('show arch', 'architecture', "(currently ", ")")   
    
    @staticmethod
    def get_endian():
        return GDBUtils.query_gdb('show endian', 'endianess', "(currently ", " endian)")         


    @staticmethod
    def set_register(register, value):
        gdb.execute("set $%s = %s" % (register, value))

GhidraBridgeCommand()