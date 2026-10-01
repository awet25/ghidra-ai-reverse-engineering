package ghidraai;

import java.awt.BorderLayout;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;


public class GhidraAIProvider
        extends ComponentProviderAdapter {

    private JPanel mainPanel;

    private JLabel functionLabel;
    private JButton analyzeButton;
    private JTextArea outputArea;


    public GhidraAIProvider(
            PluginTool tool,
            GhidraAIPlugin plugin) {

        super(
            tool,
            "AI Reverse Engineering Assistant",
            plugin.getName()
        );

        buildPanel();

        addToTool();
        setVisible(true);
    }


    private void buildPanel() {

        mainPanel = new JPanel(
            new BorderLayout()
        );

        functionLabel = new JLabel(
            "Selected Function: None"
        );

        analyzeButton = new JButton(
            "Analyze Function"
        );

        outputArea = new JTextArea();

        outputArea.setEditable(false);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);

        JPanel topPanel = new JPanel(
            new BorderLayout()
        );

        topPanel.add(
            functionLabel,
            BorderLayout.CENTER
        );

        topPanel.add(
            analyzeButton,
            BorderLayout.EAST
        );

        mainPanel.add(
            topPanel,
            BorderLayout.NORTH
        );

        mainPanel.add(
            new JScrollPane(outputArea),
            BorderLayout.CENTER
        );
    }


    @Override
    public JComponent getComponent() {
        return mainPanel;
    }


    public void dispose() {
        removeFromTool();
    }
}