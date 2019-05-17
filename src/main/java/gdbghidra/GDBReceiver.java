package gdbghidra;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import javax.swing.JTextArea;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
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
		} catch (IOException e) {
			e.printStackTrace();
			this.stop = true;
			return;
		}
	}
	
	private void handleConnection(Socket sock) throws IOException {
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

				var jp = new JSONParser();
				var r = (JSONObject)jp.parse(msgBuffer);
				if(r != null && r.containsKey("type") && r.get("type").equals("CURSOR")) {
					if(!r.containsKey("data")) { continue; }
					
					var da = (JSONArray)r.get("data");
					
					if(da.size() == 0) { continue; }
					
					var d = (JSONObject)da.get(0);
					
					if(!d.containsKey("CURSOR")) { continue; }
					
					var ca = (JSONObject)d.get("CURSOR");
					
					if(!ca.containsKey("ADDRESS")) { continue; }
					
					var s = (String)ca.get("ADDRESS");
					textArea.append("[CURSOR] set to address: " + s + "\n");
					tool.getService(GoToService.class).goTo(currentProgram.getImageBase().add(Long.decode(s)));
				}
			}
		} catch (SocketTimeoutException e) {
			return;
		} catch (ParseException e) {
			e.printStackTrace();
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
