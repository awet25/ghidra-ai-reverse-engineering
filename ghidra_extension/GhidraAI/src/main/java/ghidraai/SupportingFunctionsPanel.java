package ghidraai;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import javax.swing.JLabel;
import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

/** Explicit entry-address choices only; the Python backend validates them again. */
public final class SupportingFunctionsPanel extends JPanel {
    static final int MAX_SELECTED = 5;
    private final List<Function> functions = new ArrayList<>();
    private final Set<Address> included = new HashSet<>();
    private final JLabel countLabel = new JLabel();
    private final JLabel notice = new JLabel(" ");
    private final SupportingTableModel model = new SupportingTableModel();
    private final JTable table = new JTable(model) {
        @Override
        public String getToolTipText(MouseEvent event) {
            int row = rowAtPoint(event.getPoint());
            int column = columnAtPoint(event.getPoint());
            return row >= 0 && column > 0 ? String.valueOf(getValueAt(row, column)) : null;
        }
    };
    private final CardLayout cards = new CardLayout();
    private final JPanel body = new JPanel(cards);
    private final JLabel empty = new JLabel("Select a root function to view direct internal callees.", SwingConstants.CENTER);
    private Function root;

    public SupportingFunctionsPanel() {
        super(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));
        countLabel.setName("supportingFunctionCount");
        countLabel.setFont(countLabel.getFont().deriveFont(Font.BOLD));
        countLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        notice.setName("supportingFunctionNotice");
        empty.setName("supportingFunctionsEmpty");
        table.setName("supportingFunctionsTable");
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(Math.max(24, table.getFontMetrics(table.getFont()).getHeight() + 6));
        table.getTableHeader().setReorderingAllowed(false);
        table.getColumnModel().getColumn(0).setMinWidth(65);
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(1).setMinWidth(120);
        table.getColumnModel().getColumn(1).setPreferredWidth(310);
        table.getColumnModel().getColumn(2).setMinWidth(110);
        table.getColumnModel().getColumn(2).setPreferredWidth(150);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setColumnHeaderView(table.getTableHeader());
        scroll.setMinimumSize(new Dimension(120, 60));
        body.add(scroll, "table");
        body.add(empty, "empty");
        add(countLabel, BorderLayout.NORTH);
        add(body, BorderLayout.CENTER);
        add(notice, BorderLayout.SOUTH);
        setPreferredSize(new Dimension(400, 160));
        updateCount();
        cards.show(body, "empty");
    }

    public void clear() {
        if (table.isEditing()) {
            table.getCellEditor().cancelCellEditing();
        }
        root = null;
        functions.clear();
        included.clear();
        notice.setText(" ");
        notice.setToolTipText(null);
        empty.setText("Select a root function to view direct internal callees.");
        cards.show(body, "empty");
        updateCount();
        model.fireTableDataChanged();
    }

    public void setRootFunction(Function function) {
        if (Objects.equals(root, function)) {
            return;
        }
        clear();
        root = function;
        if (function == null) {
            return;
        }
        try {
            TreeMap<Address, Function> byEntry = new TreeMap<>();
            for (Function callee : function.getCalledFunctions(TaskMonitor.DUMMY)) {
                if (callee.isExternal() || callee.isDeleted()) {
                    continue;
                }
                Function target = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
                if (target == null || target.isExternal() || target.isDeleted() ||
                        target.getEntryPoint().equals(function.getEntryPoint())) {
                    continue;
                }
                // Keep the original called entry, including internal thunk entries.
                byEntry.put(callee.getEntryPoint(), callee);
            }
            functions.addAll(byEntry.values());
            empty.setText("No direct internal callees available.");
        }
        catch (RuntimeException error) {
            functions.clear();
            notice.setText("Select another root and retry.");
            empty.setText("Direct callees are unavailable.");
            Msg.error(this, "Could not list direct supporting functions", error);
            root = null;
        }
        model.fireTableDataChanged();
        cards.show(body, functions.isEmpty() ? "empty" : "table");
    }

    public String[] getScriptArguments() {
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
        return included.stream().sorted()
            .map(entry -> "support=" + entry)
            .toArray(String[]::new);
    }

    private void updateCount() {
        countLabel.setText("Supporting Functions (" + included.size() + " / " + MAX_SELECTED +
            " selected)");
    }

    private final class SupportingTableModel extends AbstractTableModel {
        private final String[] columns = { "Include", "Function", "Address" };

        @Override
        public int getRowCount() {
            return functions.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public Object getValueAt(int row, int column) {
            Function function = functions.get(row);
            return switch (column) {
                case 0 -> included.contains(function.getEntryPoint());
                case 1 -> function.getName();
                default -> function.getEntryPoint().toString();
            };
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column != 0) {
                return;
            }
            Address entry = functions.get(row).getEntryPoint();
            if (Boolean.TRUE.equals(value)) {
                if (!included.contains(entry) && included.size() >= MAX_SELECTED) {
                    notice.setText("Maximum 5 selected. Uncheck a function before adding another.");
                    fireTableCellUpdated(row, column);
                    return;
                }
                included.add(entry);
            }
            else {
                included.remove(entry);
            }
            notice.setText(" ");
            updateCount();
            fireTableCellUpdated(row, column);
        }
    }
}
