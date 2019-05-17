package gdbghidra.events;

public class HelloEvent implements Event{
	private String architecture;
	private String answerPort;
	private String endianess;

	public HelloEvent(String architecture, String endianess, String answerPort) {
		this.architecture = architecture;
		this.endianess = endianess;
		this.answerPort = answerPort;
	}
	
	public String getEndianess() {
		return this.endianess;
	}
	
	public String getAnswerPort() {
		return this.answerPort;
	}
	
	public String getArchitecture() {
		return this.architecture;
	}

	@Override
	public EventType getType() {
		return EventType.HELLO;
	}
}
