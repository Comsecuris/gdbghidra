/*
MIT License                                                                     
                                                                                
Copyright (c) 2019 Comsecuris UG (haftungsbeschränkt)                           
                                                                                
Permission is hereby granted, free of charge, to any person obtaining a copy       
of this software and associated documentation files (the "Software"), to deal   
in the Software without restriction, including without limitation the rights       
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell          
copies of the Software, and to permit persons to whom the Software is           
furnished to do so, subject to the following conditions:                        
                                                                                
The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.                                 
                                                                                
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR         
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,        
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE        
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER          
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,   
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE   
SOFTWARE.       
 */
package gdbghidra;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.HashMap;

import javax.swing.table.DefaultTableModel;

import org.json.simple.JSONObject;
import gdbghidra.events.BreakpointEvent;
import gdbghidra.events.CursorEvent;
import gdbghidra.events.EventParser;
import gdbghidra.events.HelloEvent;
import gdbghidra.events.MemoryEvent;
import gdbghidra.events.RegisterEvent;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class GDBReceiver implements Runnable{

	private int port;
	private GDBGhidraPlugin plugin;
	private boolean stop;
	private ServerSocket socket;
	private HelloEvent helloEvent;
	private long relocate = 0;
	private Program currentProgram;
	private ProgramLocation currentLocation;
	private HashMap<String, BigInteger> registers;
	private DefaultTableModel model;
	
	public GDBReceiver(int port, GDBGhidraPlugin plugin, DefaultTableModel model) {
		this.port = port;
		this.plugin = plugin;
		this.stop = false;
		this.helloEvent = null;
		this.registers = new HashMap<String, BigInteger>();
		this.model = model;
	}

	@Override
	public void run() {
		this.stop = false;
		
		try { 
			this.socket = new ServerSocket(port);
			while(!this.stop) {
				handleConnection(socket.accept());
			}
		} catch(SocketException e) {
			if(!e.getMessage().contentEquals("Socket closed")) {
				e.printStackTrace();	
			}
			this.stop = true;
			return;
		}catch (IOException|gdbghidra.events.ParseException e) {
			e.printStackTrace();
			this.stop = true;
			return;
		}
		
	}
	
	private void handleConnection(Socket sock) throws IOException, gdbghidra.events.ParseException {
		String msgBuffer;
		try (
				var is = sock.getInputStream();
				var isr = new InputStreamReader(is);
				var read = new BufferedReader(isr);
				var os = sock.getOutputStream();
		) {				
			while(true) {
				msgBuffer = read.readLine();
				if(msgBuffer == null || msgBuffer.length() == 0) {
					continue;
				}
				System.out.println("[GDBGhidra] received message: " + String.valueOf(msgBuffer.length()) + " bytes: '" + msgBuffer + "'\n");

				var tmpEvent = EventParser.fromJsonString(msgBuffer);
				switch(tmpEvent.getType()) {
					case HELLO:
						var helloEvent = (HelloEvent)tmpEvent;
						this.helloEvent = helloEvent;
						break;
					case CURSOR:
						var cursorEvent = (CursorEvent)tmpEvent;
						this.relocate = CursorEvent.handleEvent(cursorEvent, currentProgram, this.plugin);
						
						break;
					case REGISTER:
						var registerEvent = (RegisterEvent)tmpEvent;
						RegisterEvent.handleEvent(registerEvent, currentProgram, this.plugin, currentLocation);
						updateTable(registerEvent);
						
						break;
					case BREAKPOINT:
						var breakpoint = (BreakpointEvent)tmpEvent;
						BreakpointEvent.handleEvent(breakpoint, currentProgram, this.plugin, this.relocate);
						
						break;
					case MEMORY:
						var memEvent = (MemoryEvent)tmpEvent;
						MemoryEvent.handleEvent(memEvent, currentProgram);
						break;
				}				
			}
		} catch (SocketTimeoutException e) {
			return;
		}
	}
	
	private void updateTable(RegisterEvent registerEvent) {
		var k = registerEvent.getName();
		var v = registerEvent.getValue();
		if(this.registers.containsKey(k)) {
			this.registers.replace(k, v);
		}else {
			this.registers.put(k, v);
		}
		int i=0;
		boolean found = false;
		for(i=0; i < this.model.getRowCount(); i++) {
			String key = (String)this.model.getValueAt(i, 0);
			if(key.contentEquals(registerEvent.getName())) {
				this.model.setValueAt(registerEvent.getHexString(), i, 1);								
				found = true;
				break;
			}
		}
		if(!found) {
			this.model.addRow(new Object[] {registerEvent.getName(), registerEvent.getHexString()});
		}		
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void updateState(Program cp, ProgramLocation cl) {
		this.currentProgram = cp;
		this.currentLocation = cl;		
	}

	public void stop() {
		this.stop = true;
		if(this.socket != null) {
			try {
				this.socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public int getPort() {
		return this.port;
	}
	
	public void addBreakpoint(Address address) {
		if(this.helloEvent == null) {
			return;
		}
		
		var response = BreakpointEvent.constructJSONResponse(this.relocate + address.subtract(currentProgram.getImageBase()), "toggle");
		sendResponse(response);
	}

	public void sendResponse(JSONObject response) {
		System.out.println("[GDBGhidra] sending message:\t"+response.toJSONString()+"\n");
		
		try(
				var s = new Socket(this.helloEvent.getAnswerIp(), this.helloEvent.getAnswerPort());
				var dos = new DataOutputStream(s.getOutputStream());
				) {
			dos.write((response.toJSONString() + "\n").getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void deleteBreakpoint(Address address) {
		if(this.helloEvent == null) {
			return;
		}
		
		var response = BreakpointEvent.constructJSONResponse(this.relocate + address.subtract(currentProgram.getImageBase()), "delete");
		sendResponse(response);
	}

	public void restoreBreakpoints() {
		var it = currentProgram.getBookmarkManager().getBookmarksIterator("breakpoint");
		while(it.hasNext()) {
			var bm = it.next();
			
			var response = BreakpointEvent.constructJSONResponse(this.relocate + bm.getAddress().subtract(currentProgram.getImageBase()), "toggle");
			sendResponse(response);	
		}		
	}

	public void ChangeRegister(String register, String newValue) {
		if(this.helloEvent == null) {
			return;
		}
		
		var response = RegisterEvent.constructJSONResponse(register, newValue, "change");
		sendResponse(response);
	}
}
