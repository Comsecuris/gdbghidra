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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.util.MarkerLocation;

class DeleteBreakpointAction extends DockingAction {
	private GDBReceiver gdbReceiver;

	DeleteBreakpointAction(GDBGhidraPlugin pl) {
		super("Delete Breakpoint", pl.getName());
		setDescription("Delete breakpoint at current location");
		setPopupMenuData(new MenuData(new String[] {"Delete breakpoint"}, null, "Breakpoint"));
		this.gdbReceiver = null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Address address = getAddress(context);
		if(this.gdbReceiver != null) {
			this.gdbReceiver.deleteBreakpoint(address);
		}
	}
	
	public void setGDBReceiver(GDBReceiver gdbReceiver) {
		this.gdbReceiver = gdbReceiver;
	}
	
	private Address getAddress(ActionContext context) {
		Object contextObject = context.getContextObject();
		if(MarkerLocation.class.isAssignableFrom(contextObject.getClass())) {
			return ((MarkerLocation) contextObject).getAddr();
		} else if (context instanceof ListingActionContext ) {
			return ((ListingActionContext) context).getAddress();
		}
		return null;
	}
	
}
