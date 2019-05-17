package gdbghidra.events;

import java.math.BigInteger;

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
		return this.name.toUpperCase();
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

}
