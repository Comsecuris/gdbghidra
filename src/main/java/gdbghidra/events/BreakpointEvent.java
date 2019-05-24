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

import java.awt.Color;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class BreakpointEvent implements Event{
	private String address;
	private BreakpointEventAction action;

	public BreakpointEvent(String address, String action) {
		this.address = address;
		this.action = BreakpointEventAction.valueOf(action.toUpperCase());
	}
	
	public String getAddress() {
		return this.address;
	}
	
	public BreakpointEventAction getAction() {
		return this.action;
	}

	@Override
	public EventType getType() {
		return EventType.BREAKPOINT;
	}
	
	public enum BreakpointEventAction {
		ENABLE,
		DISABLE,
		DELETE
	}

	private static Address getBreakpointAddress(BreakpointEvent breakpoint, Program currentProgram, long relocate) {
		return 	currentProgram.getAddressFactory().getAddress(breakpoint.getAddress()).subtract(relocate).add(currentProgram.getImageBase().getOffset());
	}
	
	private static void doBreakpointTransaction(String action, BreakpointEvent breakpoint, Program currentProgram, ProgramPlugin plugin, long relocate) {
		var caddress = getBreakpointAddress(breakpoint, currentProgram, relocate);
		var category = "breakpoint";

		var tx = currentProgram.startTransaction(action);
		
		/*==================== Begin Transaction ====================================*/
		var service = plugin.getTool().getService(ColorizingService.class);
		var bm = currentProgram.getBookmarkManager().getBookmark(caddress, category, category);
		
		switch(breakpoint.getAction()) {
			case ENABLE:
				service.setBackgroundColor(caddress, caddress, Color.RED);
				break;
			case DISABLE:
				service.setBackgroundColor(caddress, caddress, Color.LIGHT_GRAY);
				break;
			case DELETE:
				service.setBackgroundColor(caddress, caddress, Color.WHITE);
				break;
		}

		if(bm != null) {
			if(breakpoint.action == BreakpointEventAction.DELETE) {
				currentProgram.getBookmarkManager().removeBookmark(bm);
				service = plugin.getTool().getService(ColorizingService.class);
			}else {
				bm.set(category, action);
			}
		}else {
			currentProgram.getBookmarkManager().setBookmark(caddress, category, category, action);
		}
		/*==================== END Transaction ====================================*/
		currentProgram.endTransaction(tx, true);
		
	}
	
	public static void handleEvent(BreakpointEvent breakpoint, Program currentProgram, ProgramPlugin plugin, long relocate) {
		switch(breakpoint.getAction()) {
		case ENABLE:		
			doBreakpointTransaction("enabled", breakpoint, currentProgram, plugin, relocate);
			break;
		case DISABLE:
			doBreakpointTransaction("disabled", breakpoint, currentProgram, plugin, relocate);
			break;
			
		case DELETE:
			doBreakpointTransaction("delete", breakpoint, currentProgram, plugin, relocate);
			break;
		}
		
	}

	public static JSONObject constructJSONResponse(long address, String action) {
		var response = new JSONObject();
		var datamap = new JSONObject();
		var data = new JSONArray();
		var jbreakpoints = new JSONArray();
		
		response.put("type", "BREAKPOINT");
		
		jbreakpoints.add("0x"+Long.toHexString(address));
		
		datamap.put("breakpoints", jbreakpoints);
		datamap.put("action", action);
		data.add(datamap);
		response.put("data", data);
		
		return response;
	}
}