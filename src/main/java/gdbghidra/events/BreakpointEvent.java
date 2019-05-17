package gdbghidra.events;

public class BreakpointEvent implements Event{

	public BreakpointEvent() {
	}

	@Override
	public EventType getType() {
		return EventType.BREAKPOINT;
	}
}
