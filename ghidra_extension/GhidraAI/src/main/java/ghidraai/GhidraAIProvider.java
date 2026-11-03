package ghidraai;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;


public class GhidraAIProvider
        extends ComponentProviderAdapter {

    private JPanel mainPanel;

    private JLabel functionLabel;
    private JButton analyzeButton;
    private JEditorPane outputArea;
    private final List<Function> functions = new ArrayList<>();
    private final DefaultListModel<Function> functionListModel = new DefaultListModel<>();
    private JList<Function> functionList;
    private JTextField filterField;
    private JCheckBox followLocationCheckBox;
    private Function selectedFunction;


    public GhidraAIProvider(
            PluginTool tool,
            GhidraAIPlugin plugin) {

        super(
            tool,
            "AI Reverse Engineering Assistant",
            plugin.getName()
        );

        buildPanel();

        analyzeButton.addActionListener(event -> plugin.analyzeSelectedFunction());
        followLocationCheckBox.addActionListener(event -> {
            if (isFollowingLocation()) {
                plugin.followCurrentLocation();
            }
        });

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

        outputArea = new JEditorPane("text/html", "");
        outputArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        outputArea.setFont(functionLabel.getFont().deriveFont(Font.PLAIN));
        outputArea.setEditable(false);
        showOutput("Select a function from the list, then click Analyze Function.");

        filterField = new JTextField();
        filterField.setToolTipText("Filter functions by name");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent event) {
                filterFunctions();
            }

            @Override
            public void removeUpdate(DocumentEvent event) {
                filterFunctions();
            }

            @Override
            public void changedUpdate(DocumentEvent event) {
                filterFunctions();
            }
        });

        functionList = new JList<>(functionListModel);
        functionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        functionList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value,
                    int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof Function function) {
                    setText(function.getName() + "  (" + function.getEntryPoint() + ")");
                }
                return this;
            }
        });
        functionList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                setSelectedFunction(functionList.getSelectedValue());
            }
        });

        followLocationCheckBox = new JCheckBox("Follow CodeBrowser location");

        JPanel filterPanel = new JPanel(new BorderLayout());
        filterPanel.add(new JLabel("Filter by name: "), BorderLayout.WEST);
        filterPanel.add(filterField, BorderLayout.CENTER);

        JPanel functionPanel = new JPanel(new BorderLayout());
        functionPanel.add(filterPanel, BorderLayout.NORTH);
        functionPanel.add(new JScrollPane(functionList), BorderLayout.CENTER);
        functionPanel.add(followLocationCheckBox, BorderLayout.SOUTH);

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

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            functionPanel, new JScrollPane(outputArea));
        splitPane.setResizeWeight(0.6);
        mainPanel.add(splitPane, BorderLayout.CENTER);
    }


    public void setProgram(Program program) {
        functions.clear();
        functionListModel.clear();
        setSelectedFunction(null);
        filterField.setText("");
        if (program != null) {
            FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                Function function = iterator.next();
                if (!function.isExternal()) {
                    functions.add(function);
                }
            }
        }
        filterFunctions();
    }


    private void filterFunctions() {
        Function previousSelection = selectedFunction;
        String query = filterField.getText().toLowerCase(Locale.ROOT);
        functionListModel.clear();
        setSelectedFunction(null);
        for (Function function : functions) {
            if (function.getName().toLowerCase(Locale.ROOT).contains(query)) {
                functionListModel.addElement(function);
            }
        }
        if (previousSelection != null && functionListModel.contains(previousSelection)) {
            functionList.setSelectedValue(previousSelection, true);
        }
    }


    public void selectFunction(Function function) {
        if (function != null && functions.contains(function)) {
            if (!functionListModel.contains(function)) {
                filterField.setText("");
            }
            functionList.setSelectedValue(function, true);
        }
        else {
            functionList.clearSelection();
            setSelectedFunction(null);
        }
    }


    public boolean isFollowingLocation() {
        return followLocationCheckBox.isSelected();
    }


    public Function getSelectedFunction() {
        return selectedFunction;
    }


    private void setSelectedFunction(Function function) {
        selectedFunction = function;
        functionLabel.setText(
            "Selected Function: " + (function == null ? "None" : function.getName())
        );
    }

    public void setAnalysisRunning(boolean running) {
        analyzeButton.setEnabled(!running);
    }

    public void showOutput(String output) {
        outputArea.setText(AnalysisOutputFormatter.format(output));
        outputArea.setCaretPosition(0);
    }


    @Override
    public JComponent getComponent() {
        return mainPanel;
    }


    public void dispose() {
        removeFromTool();
    }
}
