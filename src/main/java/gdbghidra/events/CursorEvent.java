package gdbghidra.events;

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

}
