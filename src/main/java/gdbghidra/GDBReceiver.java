package gdbghidra;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import javax.swing.JTextArea;

import gdbghidra.events.BreakpointEvent;
import gdbghidra.events.CursorEvent;
import gdbghidra.events.EventParser;
import gdbghidra.events.HelloEvent;
import gdbghidra.events.ParseException;
import gdbghidra.events.RegisterEvent;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GoToService;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;


public class GDBReceiver extends GhidraScript implements Runnable{

	private int port;
	private JTextArea textArea;
	private PluginTool tool;
	private boolean stop;
	private ServerSocket socket;

	public GDBReceiver(int port, PluginTool pluginTool) {
		this.port = port;
		this.tool = pluginTool;
		this.stop = false;
	}

	@Override
	public void run() {
		this.stop = false;
		
		try { 
			this.socket = new ServerSocket(port);
			while(!this.stop) {
				handleConnection(socket.accept());
			}
		} catch (IOException|gdbghidra.events.ParseException e) {
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
				var write = new OutputStreamWriter(os);
		) {		
			this.textArea.append("received new connection\n");
		
			while(true) {
				msgBuffer = read.readLine();
				if(msgBuffer == null || msgBuffer.length() == 0) {
					continue;
				}
				textArea.append("read " + String.valueOf(msgBuffer.length()) + " bytes: '" + msgBuffer + "'\n");

				var tmpEvent = EventParser.fromJsonString(msgBuffer);
				switch(tmpEvent.getType()) {
					case HELLO:
						var hello = (HelloEvent)tmpEvent;
						break;
					case CURSOR:
						var cursor = (CursorEvent)tmpEvent;
						var newAddress = currentProgram.getImageBase().add(cursor.getOffset());
						textArea.append("[CURSOR] set to address: " + newAddress + "\n");
						tool.getService(GoToService.class).goTo(newAddress);
						break;
					case REGISTER:
						var registerEvent = (RegisterEvent)tmpEvent;
						var register = currentProgram.getRegister(registerEvent.getName());
						if(register == null) {
							textArea.append("[ERROR] Unknown register: "+registerEvent.getName()+"\n");
							break;
						}
						var address = currentLocation.getAddress();
						System.out.println(address);
						var cmd = new CompoundCmd("Set Register Values");
						
						var regCmd = new SetRegisterCmd(
								register, 
								address, 
								address,
								registerEvent.getValue());
						cmd.add(regCmd);
						tool.execute(cmd, currentProgram);
						break;
					case BREAKPOINT:
						var breakpoint = (BreakpointEvent)tmpEvent;
						break;
				}
			}
		} catch (SocketTimeoutException e) {
			return;
		}
	}
	
	public void setPort(int port) {
		this.port = port;
	}

	public void setArea(JTextArea textArea) {
		this.textArea = textArea;
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

	public void addBreakpoint(Address address) {
		// TODO Auto-generated method stub
		
	}

	public int getPort() {
		return this.port;
	}
}
