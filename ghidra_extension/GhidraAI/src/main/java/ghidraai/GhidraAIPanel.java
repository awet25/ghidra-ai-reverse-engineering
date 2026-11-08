package ghidraai;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.ToolTipManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramEvent;

/** Swing presentation only; analysis remains owned by the plugin and Python backend. */
final class GhidraAIPanel extends JPanel {
    private final List<Function> functions = new ArrayList<>();
    private final DefaultListModel<Function> functionListModel = new DefaultListModel<>();
    private final JList<Function> functionList = new JList<>(functionListModel);
    private final JTextField filterField = new JTextField();
    private final JButton refreshButton = new JButton("Refresh");
    private final JCheckBox followLocation = new JCheckBox("Follow CodeBrowser location");
    private final JLabel functionLabel = new JLabel("None");
    private final JLabel addressLabel = new JLabel(" ");
    private final JLabel status = new JLabel();
    private final JButton analyzeButton = new JButton("Analyze Function");
    private final JEditorPane outputArea = new JEditorPane("text/html", "");
    private final SupportingFunctionsPanel supportingFunctions = new SupportingFunctionsPanel();
    private final DomainObjectListener programListener = this::programChanged;
    private final Timer functionRefreshTimer = new Timer(500, event -> refreshFunctions());
    private Program program;
    private Function selectedFunction;
    private boolean updatingFunctionList;
    private boolean running;
    private String runningName;

    GhidraAIPanel(Runnable analyze, Runnable follow) {
        super(new BorderLayout(0, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        setPreferredSize(new Dimension(620, 800));
        setMinimumSize(new Dimension(320, 480));
        functionRefreshTimer.setRepeats(false);

        filterField.setName("functionFilter");
        filterField.setToolTipText("Filter functions by name");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { filterFunctions(); }
            @Override public void removeUpdate(DocumentEvent event) { filterFunctions(); }
            @Override public void changedUpdate(DocumentEvent event) { filterFunctions(); }
        });
        JPanel search = section("Function search/filter");
        search.add(filterField, BorderLayout.CENTER);
        refreshButton.setName("refreshFunctionsButton");
        refreshButton.setToolTipText("Reload functions from the current program");
        refreshButton.setEnabled(false);
        refreshButton.addActionListener(event -> refreshFunctions());
        search.add(refreshButton, BorderLayout.EAST);

        functionList.setName("rootFunctionList");
        functionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        functionList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value,
                    int index, boolean selected, boolean focus) {
                super.getListCellRendererComponent(list, value, index, selected, focus);
                if (value instanceof Function function) {
                    String text = function.getName() + "  (" + function.getEntryPoint() + ")";
                    setText(text);
                    setToolTipText(text);
                }
                return this;
            }
        });
        ToolTipManager.sharedInstance().registerComponent(functionList);
        functionList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && !updatingFunctionList) {
                setSelectedFunction(functionList.getSelectedValue());
            }
        });
        JScrollPane rootScroll = new JScrollPane(functionList);
        rootScroll.setPreferredSize(new Dimension(540, 160));
        rootScroll.setMinimumSize(new Dimension(120, 70));
        JPanel roots = section("Root functions");
        roots.add(rootScroll, BorderLayout.CENTER);
        followLocation.setName("followCodeBrowser");
        followLocation.addActionListener(event -> {
            if (isFollowingLocation()) {
                follow.run();
            }
        });
        roots.add(followLocation, BorderLayout.SOUTH);

        JPanel identity = section("Selected root function");
        functionLabel.setName("selectedRootFunction");
        functionLabel.setFont(functionLabel.getFont().deriveFont(Font.BOLD));
        // Let labels clip with a tooltip instead of imposing a C++ symbol's width on the panel.
        functionLabel.setPreferredSize(new Dimension(180, functionLabel.getPreferredSize().height));
        functionLabel.setMinimumSize(new Dimension(0, functionLabel.getPreferredSize().height));
        identity.add(functionLabel, BorderLayout.CENTER);
        addressLabel.setName("selectedRootAddress");
        identity.add(addressLabel, BorderLayout.SOUTH);

        JPanel picker = new JPanel(new BorderLayout(0, 6));
        picker.add(search, BorderLayout.NORTH);
        picker.add(roots, BorderLayout.CENTER);
        picker.add(identity, BorderLayout.SOUTH);
        picker.setMinimumSize(new Dimension(180, 200));

        analyzeButton.setName("analyzeFunctionButton");
        analyzeButton.addActionListener(event -> analyze.run());
        status.setName("analysisStatus");
        status.setPreferredSize(new Dimension(180, 24));
        status.setMinimumSize(new Dimension(0, 24));
        JPanel actions = new JPanel(new BorderLayout(10, 0));
        actions.setBorder(BorderFactory.createEmptyBorder(6, 0, 4, 0));
        actions.add(analyzeButton, BorderLayout.WEST);
        actions.add(status, BorderLayout.CENTER);
        JPanel supports = new JPanel(new BorderLayout(0, 4));
        supports.add(supportingFunctions, BorderLayout.CENTER);
        supports.add(actions, BorderLayout.SOUTH);
        supports.setMinimumSize(new Dimension(180, 130));

        outputArea.setName("analysisResults");
        outputArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        outputArea.setFont(filterField.getFont());
        outputArea.setEditable(false);
        JScrollPane resultScroll = new JScrollPane(outputArea);
        resultScroll.setPreferredSize(new Dimension(540, 270));
        resultScroll.setMinimumSize(new Dimension(120, 100));
        JPanel results = section("Analysis Results");
        results.add(resultScroll, BorderLayout.CENTER);
        results.setMinimumSize(new Dimension(180, 130));

        JSplitPane selection = split(picker, supports, 0.6);
        selection.setPreferredSize(new Dimension(560, 450));
        add(split(selection, results, 0.6), BorderLayout.CENTER);
        showMessage("Select a root function, optionally choose supporting functions, then click Analyze Function.");
        updateControls();
    }

    private static JPanel section(String title) {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(3, 4, 4, 4)));
        return panel;
    }

    private static JSplitPane split(Component top, Component bottom, double weight) {
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom);
        split.setResizeWeight(weight);
        split.setContinuousLayout(true);
        split.setBorder(BorderFactory.createEmptyBorder());
        return split;
    }

    void setProgram(Program program) {
        if (this.program == program) {
            // Reopening the panel or replaying activation must preserve the analyst's choices.
            refreshFunctions();
            return;
        }
        detachProgramListener();
        this.program = program;
        // Listen before taking the snapshot so functions added during loading aren't missed.
        if (program != null) {
            program.addListener(programListener);
        }
        refreshButton.setEnabled(program != null);
        supportingFunctions.clear();
        functions.clear();
        functionListModel.clear();
        setSelectedFunction(null);
        filterField.setText("");
        refreshFunctions();
    }

    void refreshFunctions() {
        functionRefreshTimer.stop();
        List<Function> refreshed = new ArrayList<>();
        if (program != null) {
            FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                Function function = iterator.next();
                if (!function.isDeleted() && !function.isExternal()) {
                    refreshed.add(function);
                }
            }
        }
        functions.clear();
        functions.addAll(refreshed);
        filterFunctions();
    }

    private void programChanged(DomainObjectChangedEvent event) {
        if (!event.contains(DomainObjectEvent.RESTORED, ProgramEvent.FUNCTION_ADDED,
                ProgramEvent.FUNCTION_REMOVED, ProgramEvent.FUNCTION_CHANGED,
                ProgramEvent.SYMBOL_RENAMED)) {
            return;
        }
        // DomainObjectChangedEvent is transient; retain only its source for the EDT callback.
        Object source = event.getSource();
        SwingUtilities.invokeLater(() -> {
            if (program == source && !functionRefreshTimer.isRunning()) {
                // Start once per batch rather than postponing forever during continuous analysis.
                functionRefreshTimer.start();
            }
        });
    }

    private void detachProgramListener() {
        functionRefreshTimer.stop();
        if (program != null) {
            program.removeListener(programListener);
        }
    }

    void dispose() {
        detachProgramListener();
        program = null;
    }

    private void filterFunctions() {
        Function previous = selectedFunction;
        String query = filterField.getText().toLowerCase(Locale.ROOT);
        updatingFunctionList = true;
        try {
            List<Function> matches = new ArrayList<>();
            for (Function function : functions) {
                if (!function.isDeleted() &&
                        function.getName().toLowerCase(Locale.ROOT).contains(query)) {
                    matches.add(function);
                }
            }
            functionListModel.clear();
            functionListModel.addAll(matches);
            if (previous != null && functionListModel.contains(previous)) {
                functionList.setSelectedValue(previous, true);
            }
        }
        finally {
            updatingFunctionList = false;
        }
        setSelectedFunction(functionList.getSelectedValue());
    }

    void selectFunction(Function function) {
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

    private void setSelectedFunction(Function function) {
        boolean changed = !Objects.equals(selectedFunction, function);
        selectedFunction = function;
        functionLabel.setText(function == null ? "None" : function.getName());
        functionLabel.setToolTipText(function == null ? null : function.getName());
        addressLabel.setText(function == null ? " " : "Address: " + function.getEntryPoint());
        if (changed) {
            supportingFunctions.setRootFunction(function);
        }
        updateControls();
    }

    boolean isFollowingLocation() { return followLocation.isSelected(); }
    Function getSelectedFunction() { return selectedFunction; }
    String[] getSupportingScriptArguments() { return supportingFunctions.getScriptArguments(); }

    void setAnalysisRunning(boolean running) {
        this.running = running;
        if (running) {
            runningName = selectedFunction == null ? "function" : selectedFunction.getName();
            showMessage("Analysis in progress. Results will appear here.");
        }
        updateControls();
    }

    private void updateControls() {
        analyzeButton.setEnabled(selectedFunction != null && !running);
        String text = running ? "Analyzing " + runningName + "..." :
            selectedFunction == null ? "Select a root function." : "Ready to analyze.";
        status.setText(text);
        status.setToolTipText(text);
    }

    void showOutput(String output) {
        AnalysisOutputFormatter.FormattedResult result = AnalysisOutputFormatter.present(output);
        outputArea.setText(result.html());
        outputArea.setCaretPosition(0);
        if (!running) {
            status.setText(result.status());
            status.setToolTipText(result.status());
        }
    }

    void showMessage(String message) {
        outputArea.setText(AnalysisOutputFormatter.message(message));
        outputArea.setCaretPosition(0);
    }

    void showError(String message) {
        outputArea.setText(AnalysisOutputFormatter.error(message).html());
        outputArea.setCaretPosition(0);
        if (!running) {
            status.setText("Analysis failed.");
            status.setToolTipText(status.getText());
        }
    }
}
