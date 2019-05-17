/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
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
}
