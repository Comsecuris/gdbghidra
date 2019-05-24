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

class RestoreBreakpointsAction extends DockingAction {
	private GDBReceiver gdbReceiver;

	RestoreBreakpointsAction(GDBGhidraPlugin pl) {
		super("Restore Breakpoints", pl.getName());
		setDescription("Restore all saved breakpoints");
		setPopupMenuData(new MenuData(new String[] {"Restore breakpoints"}, null, "Breakpoint"));
		//setKeyBindingData(new KeyBindingData(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK)); 
		this.gdbReceiver = null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if(this.gdbReceiver != null) {
			this.gdbReceiver.restoreBreakpoints();
		}
	}
	
	public void setGDBReceiver(GDBReceiver gdbReceiver) {
		this.gdbReceiver = gdbReceiver;
	}
	
}
