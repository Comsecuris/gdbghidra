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
							getKeyOrThrow(d, "answerport", "data"));	
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
					return new BreakpointEvent();
			}
			
			
		} catch (org.json.simple.parser.ParseException e) {
			throw new ParseException(e.getMessage());
		}
		
		// we should never reach this!
		return null;
	}
}
