package ghidraai;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.SwingUtilities;

import generic.jar.ResourceFile;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "AI Reverse Engineering Assistant",
    description = "AI-assisted function analysis inside Ghidra."
)
public class GhidraAIPlugin extends ProgramPlugin {

    private GhidraAIProvider provider;
    private boolean analysisRunning;

    public GhidraAIPlugin(PluginTool tool) {
        super(tool);

        provider = new GhidraAIProvider(
            tool,
            this
        );
    }

    @Override
    protected void programActivated(Program program) {
        provider.setProgram(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        provider.setProgram(null);
    }

    void followCurrentLocation() {
        locationChanged(currentLocation);
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        if (!provider.isFollowingLocation()) {
            return;
        }
        Function function = null;
        if (currentProgram != null && location != null && location.getAddress() != null) {
            function = currentProgram.getFunctionManager()
                .getFunctionContaining(location.getAddress());
        }
        provider.selectFunction(function);
    }

    void analyzeSelectedFunction() {
        if (analysisRunning) {
            return;
        }
        Function function = provider.getSelectedFunction();
        if (function == null) {
            provider.showOutput("Select a function from the list before analyzing.");
            return;
        }
        Program program = currentProgram;
        if (program == null || function.getProgram() != program || function.isDeleted()) {
            provider.showOutput("The selected function is no longer available in the current program.");
            return;
        }

        GhidraState state = new GhidraState(tool, tool.getProject(), program,
            new ProgramLocation(program, function.getEntryPoint()), null, null);
        String functionName = function.getName();
        Object consumer = new Object();
        if (!program.addConsumer(consumer)) {
            provider.showOutput("The program was closed. Open a program and select a function.");
            return;
        }

        analysisRunning = true;
        provider.setAnalysisRunning(true);
        provider.showOutput("Analyzing: " + functionName + "...");
        try {
            new TaskBuilder("Analyze Function", monitor -> {
                String output = "Analysis stopped before output could be captured.";
                try {
                    output = runAnalysisScript(state, monitor);
                }
                finally {
                    try {
                        program.release(consumer);
                    }
                    finally {
                        String result = output;
                        SwingUtilities.invokeLater(() -> finishAnalysis(result));
                    }
                }
            }).setParent(provider.getComponent())
                .setHasProgress(false)
                .setCanCancel(true)
                .launchNonModal();
        }
        catch (RuntimeException error) {
            program.release(consumer);
            finishAnalysis("Could not start analysis: " + error);
        }
    }

    private String runAnalysisScript(GhidraState state, TaskMonitor monitor) {
        StringWriter output = new StringWriter();
        try (PrintWriter writer = new PrintWriter(output, true)) {
            try {
                writer.println("Program: " + state.getCurrentProgram().getName());
                writer.println("Selected address: " + state.getCurrentAddress());
                monitor.checkCancelled();
                ResourceFile source = GhidraScriptUtil.findScriptByName("AnalyzeCurrentFunction.py");
                if (source == null) {
                    throw new IOException("AnalyzeCurrentFunction.py was not found. Add this project's " +
                        "ghidra_scripts directory to Script Manager's script directories.");
                }
                GhidraScriptProvider scriptProvider = GhidraScriptUtil.getProvider(source);
                if (scriptProvider == null ||
                        !"PyGhidra".equalsIgnoreCase(scriptProvider.getRuntimeEnvironmentName())) {
                    throw new IOException("No PyGhidra provider is available for AnalyzeCurrentFunction.py. " +
                        "Start Ghidra with PyGhidra and keep the script's #@runtime PyGhidra marker.");
                }
                GhidraScript script = scriptProvider.getScriptInstance(source, writer);
                script.execute(state, new ScriptControls(writer, writer, monitor));
            }
            catch (CancelledException error) {
                writer.println("\nAnalysis cancelled.");
            }
            catch (Exception error) {
                writer.println("\nAI analysis failed: " + error);
                error.printStackTrace(writer);
            }
        }
        return output.toString();
    }

    private void finishAnalysis(String output) {
        analysisRunning = false;
        if (provider != null) {
            provider.setAnalysisRunning(false);
            if (output != null) {
                provider.showOutput(output);
            }
        }
    }

    @Override
    protected void dispose() {

        if (provider != null) {
            provider.dispose();
            provider = null;
        }

        super.dispose();
    }
}
