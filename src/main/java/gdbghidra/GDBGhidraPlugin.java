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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "GDBGhidra",
	category = PluginCategoryNames.DEBUGGER,
	shortDescription = "GDB to Ghidra bridge.",
	description = "Syncs the current instruction pointer from a gdbserver session to the current cursor of Ghidra."
)
//@formatter:on
public class GDBGhidraPlugin extends ProgramPlugin {

	GDBGhidraProvider provider;
	
	public GDBGhidraPlugin(PluginTool tool) {
		super(tool, true, true);

		String pluginName = getName();
		provider = new GDBGhidraProvider(this, pluginName);
	}
	
	@Override
	public void init() {
		super.init();
	}
	
	@Override
	public void locationChanged(ProgramLocation loc) {
		provider.locationChanged(currentProgram, loc);
	}

	public GDBGhidraProvider getProvider() {
		return this.provider;
	}
}
