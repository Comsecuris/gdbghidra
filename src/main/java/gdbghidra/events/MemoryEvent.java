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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;

import ch.ethz.ssh2.crypto.Base64;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.mem.MemoryBlock;

public class MemoryEvent implements Event {
	private String name;
	private String address;
	private String data;
	private boolean readPermission;
	private boolean writePermission;
	private boolean executePermission;
	private long size;

	public MemoryEvent(String address, String name, String data, String size, boolean readPermission,
			boolean writePermission, boolean executePermission) {
		this.address = address;
		this.name = name;
		this.data = data;
		this.size = Long.decode(size);
		this.readPermission = readPermission;
		this.writePermission = writePermission;
		this.executePermission = executePermission;
	}

	public String getName() {
		return this.name;
	}

	@Override
	public EventType getType() {
		return EventType.MEMORY;
	}

	public Address getAddress(Program currentProgram) {
		return currentProgram.getAddressFactory().getAddress(address);
	}

	public boolean getReadPermission() {
		return readPermission;
	}

	public boolean getWritePermission() {
		return writePermission;
	}

	public boolean getExecutePermission() {
		return executePermission;
	}

	public InputStream getData() {
		try {
			var decoded = Base64.decode(this.data.toCharArray());
			ByteArrayInputStream bis = new ByteArrayInputStream(decoded);
			return new GZIPInputStream(bis);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public long getDataSize() {
		return this.size;
	}

	public static void handleEvent(MemoryEvent memEvent, Program currentProgram) {
		try {
			var tx = currentProgram.startTransaction("adding memory");
			MessageLog log = new MessageLog();
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(currentProgram, false, memEvent.getName(),
					memEvent.getAddress(currentProgram), memEvent.getData(), memEvent.getDataSize(), "", // comment
					"gdb", memEvent.getReadPermission(), memEvent.getWritePermission(), memEvent.getExecutePermission(),
					log, TaskMonitor.DUMMY);

			if (block == null) {
				var msg = log.toString();
				if (msg.contains("Overwrote memory")) {
					System.out.println("[GDBGhidra] " + msg);
				} else {
					System.err.println("[GDBGhidra] could not write new memory block: " + msg);
				}
			} else {
				System.out.println("[GDBGhidra]" + block.toString());
			}

			currentProgram.endTransaction(tx, true);
		} catch (AddressOverflowException e) {
			e.printStackTrace();
		}
	}
}
