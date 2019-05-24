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

public class HelloEvent implements Event{
	private String architecture;
	private Integer answerPort;
	private String endianess;
	private String answerIp;

	public HelloEvent(String architecture, String endianess, String answerIp, String answerPort) {
		this.architecture = architecture;
		this.endianess = endianess;
		this.answerIp = answerIp;
		this.answerPort = Integer.valueOf(answerPort);
	}
	
	public String getEndianess() {
		return this.endianess;
	}
	
	public String getAnswerIp() {
		return this.answerIp;
	}
	
	public Integer getAnswerPort() {
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
