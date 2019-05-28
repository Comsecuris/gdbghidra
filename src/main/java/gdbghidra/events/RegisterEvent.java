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
package gdbghidra.events;

import java.math.BigInteger;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.lang.RegisterManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class RegisterEvent implements Event {
	private String name;
	private String value;
	private String address;

	public RegisterEvent(String address, String name, String value) {
		this.address = address;
		this.name = name;
		this.value = value;
	}
	
	public String getName() {
		return this.name;
	}
	
	public String getHexString() {
		return this.value;
	}
	
	public BigInteger getValue() {
		if(this.value.startsWith("0x")) {
			return new BigInteger(this.value.substring(2), 16);
		}
		return new BigInteger(this.value, 16);

	}
	
	public String getAddress() {
		return this.address;
	}
	
	@Override
	public EventType getType() {
		return EventType.REGISTER;
	}

	public static void handleEvent(RegisterEvent registerEvent, Program currentProgram, ProgramPlugin plugin, ProgramLocation currentLocation) {
		var register = currentProgram.getRegister(registerEvent.getName());
		if(register == null) {
			register = currentProgram.getRegister(registerEvent.getName().toUpperCase());
			if(register == null) {
				System.err.println("[GDBGHIDRA] Error unknown register: "+registerEvent.getName()+"\n");
				return;
			}
		}
		var address = currentLocation.getAddress();
		var cmd = new CompoundCmd("Set Register Values");
		var regCmd = new SetRegisterCmd(
				register, 
				address, 
				address,
				registerEvent.getValue());
		cmd.add(regCmd);
		plugin.getTool().execute(cmd, currentProgram);
	}

	public static JSONObject constructJSONResponse(String register, String newValue, String action) {
		var response = new JSONObject();
		var datamap = new JSONObject();
		var data = new JSONArray();
		
		response.put("type", "REGISTER");
		datamap.put("register", register);
		datamap.put("value", newValue);
		datamap.put("action", action);
		data.add(datamap);
		response.put("data", data);
		
		return response;
	}

}