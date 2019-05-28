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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import javax.swing.border.BevelBorder;
import javax.swing.table.DefaultTableModel;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.app.script.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import resources.Icons;

public class GDBGhidraProvider extends ComponentProviderAdapter {
	private JPanel panel;
	private DockingAction action;
	private DockingAction portAction;
	private DockingAction stopAction;
	private ProgramLocation currentLocation;
	private GDBReceiver gdbReceiver;
	private Program currentProgram;
	private GDBGhidraPlugin plugin;
	private Thread gdbReceiverThread = null;
	private DefaultTableModel model = null;
	private JLabel status = new JLabel();
	private Address previousAddress;
	private Color previousColor;
	
	
	public GDBGhidraProvider(GDBGhidraPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.model = new DefaultTableModel( new String[] {"register", "value"}, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				if(column == 0) {
					return false;
				}
				return true;
			}
		};
		this.plugin = plugin;
		buildTable();
		
		this.gdbReceiver = new GDBReceiver(2305, plugin, model);
		
		createActions();
		setWindowGroup("core.GDBGhidra");
		setIntraGroupPosition(WindowPosition.RIGHT);
	}

	public void buildTable() {
		panel = new JPanel(new BorderLayout());
		var table = new GTable(this.model);
		panel.add(new JScrollPane(table));

		var statusPanel = new JPanel();
		statusPanel.setBorder(new BevelBorder(BevelBorder.LOWERED));
		panel.add(statusPanel, BorderLayout.SOUTH);
		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.X_AXIS));

		status.setText("stopped");
		status.setHorizontalAlignment(SwingConstants.LEFT);
		statusPanel.add(status);
		
		var a = new AbstractAction() {
			public void actionPerformed(ActionEvent a) {
				RegisterChangeListener l = (RegisterChangeListener)a.getSource();
				if(l.getColumn() != 1) {
					return;
				}
				gdbReceiver.ChangeRegister((String)table.getValueAt(l.getRow(), 0), (String)l.getNewValue());
			}
		};
		
		new RegisterChangeListener(table, a);
		
		setVisible(true);
	}
	
	private void createActions() {		
		action = new DockingAction("Run", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				System.out.println("[GDBGhidra] Starting server on port " + gdbReceiver.getPort() + "\n");
				gdbReceiverThread = new Thread(gdbReceiver);
				gdbReceiverThread.start();
				status.setText("running");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		stopAction = new DockingAction("Stop", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				System.out.println("[GDBGhidra] Stopping server\n");
				gdbReceiver.stop();
				try {
					if(gdbReceiverThread != null && gdbReceiverThread.isAlive()) {
						gdbReceiverThread.join(2000);
					}
					gdbReceiverThread = null;
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				gdbReceiverThread = null;
				status.setText("stopped");
			}
		};
		stopAction.setToolBarData(new ToolBarData(Icons.STOP_ICON, null));
		stopAction.setEnabled(true);
		stopAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, stopAction);

		portAction = new DockingAction("Configure", "Port") {
			@Override
			public void actionPerformed(ActionContext context) {
				AskDialog<Integer> d = new AskDialog<>("Listener port configuration", "Please enter TCP listener port:", AskDialog.INT, gdbReceiver.getPort());
				if(d.isCanceled()) {
					// WAAAAH!
				}
				gdbReceiver.setPort( Integer.valueOf(d.getValueAsString()).intValue() );
			}
		};
		portAction.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
		portAction.setEnabled(true);
		portAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, portAction);
		
		DeleteBreakpointAction deleteBreakpointAction = new DeleteBreakpointAction(this.plugin);
		deleteBreakpointAction.setEnabled(true);
		deleteBreakpointAction.setGDBReceiver(gdbReceiver);
		dockingTool.addAction(deleteBreakpointAction);
		
		/*
		RestoreBreakpointsAction restoreBreakpointsAction = new RestoreBreakpointsAction(this.plugin);
		 
		restoreBreakpointsAction.setEnabled(true);
		restoreBreakpointsAction.setGDBReceiver(gdbReceiver);
		dockingTool.addAction(restoreBreakpointsAction); */
		
		
		ToggleBreakpointAction breakpointAction = new ToggleBreakpointAction(this.plugin);
		breakpointAction.setEnabled(true);
		breakpointAction.setGDBReceiver(gdbReceiver);
		dockingTool.addAction(breakpointAction);
		
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void locationChanged(Program cp, ProgramLocation loc) {
		this.currentProgram = cp;
		this.currentLocation = loc;		
		
		gdbReceiver.updateState(currentProgram, currentLocation);
	}

	public void setPreviousAddress(Address newAddress) {
		this.previousAddress = newAddress;
	}
	public Address getPreviousAddress() {
		return this.previousAddress;
	}

	public void setPreviousColor(Color previousColor) {
		this.previousColor = previousColor;		
	}

	public Color getPreviousColor() {
		return this.previousColor;
	}
	
}
