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

import java.util.EnumSet;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class EventParser {
	private static String getKeyOrThrow(JSONObject o, String key, String sectionName) throws ParseException {
		if(!o.containsKey(key)) { throw new ParseException("Missing '"+key+"' field in "+sectionName+" section of message."); }
		return (String)o.get(key);
	}
	
	public static Event fromJsonString(String json) throws ParseException {
		var jp = new JSONParser();
		JSONObject r;
		try {
			r = (JSONObject)jp.parse(json);
			if(r == null) { throw new ParseException("Could not initialize json parser"); } 
			
			if(!r.containsKey("type")) { throw new ParseException("Missing type field inside event message"); }
			
			EnumSet<EventType> types = EnumSet.allOf(EventType.class);
			
			var type = EventType.valueOf((String)r.get("type"));
			
			if(!types.contains(type)) { throw new ParseException("Unknown event type. Should be one of: "); }
			
			if(!r.containsKey("data")) { throw new ParseException("Missing 'data' section inside event message."); }
			
			var da = (JSONArray)r.get("data");
			
			if(da.size() == 0) { throw new ParseException("'data' section inside event message should not be empty"); }
			
			var d = (JSONObject)da.get(0);
			
			switch(type) {
				case HELLO:					
					return new HelloEvent(
							getKeyOrThrow(d, "arch", "data"), 
							getKeyOrThrow(d, "endian", "data"), 
							getKeyOrThrow(d, "answer_ip", "data"),
							getKeyOrThrow(d, "answer_port", "data"));
							
				case CURSOR:		
					return new CursorEvent(
							getKeyOrThrow(d, "address", "data"), 
							getKeyOrThrow(d, "relocate", "data"));				
				case REGISTER:					
					return new RegisterEvent(
							getKeyOrThrow(d, "address", "data"), 
							getKeyOrThrow(d, "name", "data"),
							getKeyOrThrow(d, "value", "data"));
				case BREAKPOINT:
					return new BreakpointEvent(	
							getKeyOrThrow(d, "breakpoint", "data" ),
							getKeyOrThrow(d, "action", "data" ));
				case MEMORY:
					return new MemoryEvent(	
							getKeyOrThrow(d, "address", "data" ),
							getKeyOrThrow(d, "name", "data" ),
							getKeyOrThrow(d, "data", "data" ),
							getKeyOrThrow(d, "size", "data" ),
							getKeyOrThrow(d, "read", "data" ).equals("True"),
							getKeyOrThrow(d, "write", "data" ).equals("True"),
							getKeyOrThrow(d, "execute", "data" ).equals("True")
							);
			}
			
			
		} catch (org.json.simple.parser.ParseException e) {
			throw new ParseException(e.getMessage());
		}
		
		// we should never reach this!
		return null;
	}
}
