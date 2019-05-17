package gdbghidra;

import java.awt.BorderLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.app.script.*;

import resources.Icons;

public class GDBGhidraProvider extends ComponentProvider {
	private JPanel panel;
	private DockingAction action;
	private DockingAction portAction;
	private DockingAction stopAction;
	private JTextArea textArea;
	private ProgramLocation currentLocation;
	private GDBReceiver gdbReceiver;
	private Program currentProgram;
	private GDBGhidraPlugin plugin;

	public GDBGhidraProvider(GDBGhidraPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		buildPanel();
		createActions();
		gdbReceiver = new GDBReceiver(2305, plugin.getTool());	
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		panel.add(new JScrollPane(textArea));
		setVisible(true);
	}

	private void createActions() {		
		action = new DockingAction("Run", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				textArea.append("Starting server on port " + gdbReceiver.getPort() + "\n");
				gdbReceiver.setArea(textArea);
				new Thread(gdbReceiver).start();
			}
		};
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		stopAction = new DockingAction("Run", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				textArea.append("Stopping server\n");
				gdbReceiver.stop();
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
		
		BreakpointAction breakpointAction = new BreakpointAction(this.plugin);
		breakpointAction.setEnabled(true);
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
}
