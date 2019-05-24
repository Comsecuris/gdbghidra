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

import gdbghidra.GDBGhidraPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GoToService;
import ghidra.program.model.listing.Program;

public class CursorEvent implements Event {
	private String address;
	private String relocate;

	public CursorEvent(String address, String relocate) {
		this.address = address;
		this.relocate = relocate;
	}
	
	public String getAddressString() {
		return this.address;
	}
	
	public long getRelocationAddress() {
		return Long.decode(relocate);
	}
	
	public String getRelocationAddressString() {
		return this.relocate;
	}
	
	public long getOffset() {
		if(relocate == "unknown") {
			return Long.decode(address); 
		}
		
		return Long.decode(address) - Long.decode(relocate);
	}
	
	@Override
	public EventType getType() {
		return EventType.CURSOR;
	}

	public static long handleEvent(CursorEvent cursor, Program currentProgram, GDBGhidraPlugin plugin) {
		var newAddress = currentProgram.getImageBase().add(cursor.getOffset());
		plugin.getTool().getService(GoToService.class).goTo(newAddress);
		
		var tx = currentProgram.startTransaction("change cursor color");
		
		/*==================== Begin Transaction ====================================*/
		var service = plugin.getTool().getService(ColorizingService.class);
		var currentColor = service.getBackgroundColor(newAddress);
		
		var previousAddress = plugin.getProvider().getPreviousAddress();
		
		service.setBackgroundColor(newAddress, newAddress, Color.GREEN);
		
		if(previousAddress != null ) {	
			service.setBackgroundColor(plugin.getProvider().getPreviousAddress(), plugin.getProvider().getPreviousAddress(), plugin.getProvider().getPreviousColor());
		}
		plugin.getProvider().setPreviousAddress(newAddress);
		if(currentColor == null) {
			plugin.getProvider().setPreviousColor(Color.WHITE);
		}else {
			plugin.getProvider().setPreviousColor(currentColor);
		}
		/*==================== END Transaction ====================================*/
		currentProgram.endTransaction(tx, true);
		
		
		if(!cursor.getRelocationAddressString().equals("unknown")) {
			return cursor.getRelocationAddress();
		}
		return 0;
	}

}
