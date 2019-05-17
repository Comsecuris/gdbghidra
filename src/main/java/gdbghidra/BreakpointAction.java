package gdbghidra;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.util.MarkerLocation;

class BreakpointAction extends DockingAction {
	private GDBReceiver gdbReceiver;

	BreakpointAction(GDBGhidraPlugin pl) {
		super("Toggle Breakpoint", pl.getName());
		setDescription("Add/Remove breakpoint at current location");
		setPopupMenuData(new MenuData(new String[] {"Toggle breakpoint"}, null, "Breakpoint"));
		//setKeyBindingData(new KeyBindingData(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK)); 
		this.gdbReceiver = null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Address address = getAddress(context);
		System.out.println("Setting breakpoint " + address);
		if(this.gdbReceiver != null) {
			this.gdbReceiver.addBreakpoint(address);
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
