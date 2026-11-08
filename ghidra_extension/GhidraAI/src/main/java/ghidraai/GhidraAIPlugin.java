package ghidraai;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.swing.SwingUtilities;

import generic.jar.ResourceFile;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "AI Reverse Engineering Assistant",
    description = "AI-assisted function analysis inside Ghidra.",
    servicesRequired = { ProgramManager.class }
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
    protected void init() {
        super.init();
        refreshCurrentProgram();
    }

    void refreshCurrentProgram() {
        // The provider can be shown inside its constructor, before this field is assigned.
        if (provider == null) {
            return;
        }
        ProgramManager manager = tool.getService(ProgramManager.class);
        Program activeProgram = manager == null ? currentProgram : manager.getCurrentProgram();
        if (activeProgram != currentProgram) {
            // Keep ProgramPlugin's state in sync too; Analyze uses currentProgram.
            processEvent(new ProgramActivatedPluginEvent(getName(), activeProgram));
        }
        else {
            provider.setProgram(activeProgram);
        }
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
            provider.showError("Select a root function before analyzing.");
            return;
        }
        Program program = currentProgram;
        if (program == null || function.getProgram() != program || function.isDeleted()) {
            provider.showError("The selected function is no longer available in the current program.");
            return;
        }

        GhidraState state = new GhidraState(tool, tool.getProject(), program,
            new ProgramLocation(program, function.getEntryPoint()), null, null);
        String[] scriptArguments = provider.getSupportingScriptArguments();
        Object consumer = new Object();
        if (!program.addConsumer(consumer)) {
            provider.showError("The program was closed. Open a program and select a function.");
            return;
        }

        analysisRunning = true;
        provider.setAnalysisRunning(true);
        try {
            new TaskBuilder("Analyze Function", monitor -> {
                String output = "Analysis stopped before output could be captured.";
                try {
                    output = runAnalysisScript(state, monitor, scriptArguments);
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
            Msg.error(this, "Could not start Ghidra AI analysis", error);
            try {
                program.release(consumer);
            }
            finally {
                finishAnalysis("Could not start analysis: See the Ghidra console for details.");
            }
        }
    }

    static String runAnalysisScript(GhidraState state, TaskMonitor monitor, String[] scriptArguments) {
        StringWriter output = new StringWriter();
        try (PrintWriter writer = new PrintWriter(output, true)) {
            try {
                writer.println("Program: " + state.getCurrentProgram().getName());
                writer.println("Selected address: " + state.getCurrentAddress());
                monitor.checkCancelled();
                ResourceFile source = findAnalysisScript(Application.getModuleRootDir("GhidraAI"));
                if (source == null) {
                    Msg.error(GhidraAIPlugin.class,
                        "The installed GhidraAI extension is missing ghidra_scripts/AnalyzeCurrentFunction.py. " +
                        "Reinstall the matching extension; other Script Manager copies are not used.");
                    writer.println("\nAI analysis failed: The installed GhidraAI extension is incomplete. " +
                        "Reinstall the extension.");
                    return output.toString();
                }
                GhidraScriptProvider scriptProvider = GhidraScriptUtil.getProvider(source);
                if (scriptProvider == null ||
                        !"PyGhidra".equalsIgnoreCase(scriptProvider.getRuntimeEnvironmentName())) {
                    writer.println("\nAI analysis failed: No PyGhidra provider is available. " +
                        "Start Ghidra with PyGhidra to run this script.");
                    return output.toString();
                }
                final GhidraScript script = scriptProvider.getScriptInstance(source, writer);
                // Build the execution array from the EDT selection snapshot, then set and
                // execute this one script instance. Never reread the UI in the task.
                String[] executionArguments = scriptArguments.clone();
                script.setScriptArgs(executionArguments);
                script.execute(state, new ScriptControls(writer, writer, monitor));
            }
            catch (CancelledException error) {
                writer.println("\nAnalysis cancelled.");
            }
            catch (Exception error) {
                Msg.error(GhidraAIPlugin.class, "Ghidra AI analysis failed", error);
                writer.println("\nAI analysis failed: See the Ghidra console for details.");
            }
        }
        return output.toString();
    }

    static ResourceFile findAnalysisScript(ResourceFile moduleRoot) {
        // A global filename lookup can select an older script from another checkout.
        if (moduleRoot == null) {
            return null;
        }
        ResourceFile script = new ResourceFile(moduleRoot, "ghidra_scripts/AnalyzeCurrentFunction.py");
        return script.isFile() ? script : null;
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
