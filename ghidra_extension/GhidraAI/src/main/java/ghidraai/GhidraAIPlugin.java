package ghidraai;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "AI Reverse Engineering Assistant",
    description = "AI-assisted function analysis inside Ghidra."
)
public class GhidraAIPlugin extends ProgramPlugin {

    private GhidraAIProvider provider;

    public GhidraAIPlugin(PluginTool tool) {
        super(tool);

        provider = new GhidraAIProvider(
            tool,
            this
        );
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