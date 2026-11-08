package ghidraai;

import javax.swing.JComponent;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/** Docking adapter for the testable Swing presentation. */
public class GhidraAIProvider extends ComponentProviderAdapter {
    private final GhidraAIPanel panel;
    private final GhidraAIPlugin plugin;

    public GhidraAIProvider(PluginTool tool, GhidraAIPlugin plugin) {
        super(tool, "AI Reverse Engineering Assistant", plugin.getName());
        this.plugin = plugin;
        panel = new GhidraAIPanel(plugin::analyzeSelectedFunction, plugin::followCurrentLocation);
        addToTool();
        setVisible(true);
    }

    @Override
    public void componentShown() {
        // Opening the panel must also work when the binary was activated earlier.
        plugin.refreshCurrentProgram();
    }

    public void setProgram(Program program) { panel.setProgram(program); }
    public void selectFunction(Function function) { panel.selectFunction(function); }
    public boolean isFollowingLocation() { return panel.isFollowingLocation(); }
    public Function getSelectedFunction() { return panel.getSelectedFunction(); }
    public String[] getSupportingScriptArguments() { return panel.getSupportingScriptArguments(); }
    public void setAnalysisRunning(boolean running) { panel.setAnalysisRunning(running); }
    public void showOutput(String output) { panel.showOutput(output); }
    public void showError(String message) { panel.showError(message); }

    @Override
    public JComponent getComponent() { return panel; }

    public void dispose() {
        panel.dispose();
        removeFromTool();
    }
}
