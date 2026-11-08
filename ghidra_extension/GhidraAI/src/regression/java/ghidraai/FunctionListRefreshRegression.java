package ghidraai;

import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.EventType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramEvent;

/** Standalone regression runner; uses Ghidra interfaces without starting CodeBrowser. */
public final class FunctionListRefreshRegression {
    private static GhidraAIPanel panel;
    private static JList<?> roots;
    private static JTextField filter;
    private static JButton refresh;

    public static void main(String[] args) throws Exception {
        try {
            runChecks();
            System.out.println("Function list regression checks passed.");
        }
        finally {
            onEdt(() -> { if (panel != null) panel.dispose(); });
        }
    }

    private static void runChecks() throws Exception {
        ProgramFixture first = new ProgramFixture();
        ProgramFixture alreadyOpen = new ProgramFixture();
        FunctionFixture existing = new FunctionFixture("existing_function");
        alreadyOpen.functions.add(existing.function);
        onEdt(() -> {
            panel = new GhidraAIPanel(() -> {}, () -> {});
            roots = (JList<?>) find(panel, "rootFunctionList");
            filter = (JTextField) find(panel, "functionFilter");
            refresh = (JButton) find(panel, "refreshFunctionsButton");
            require(!refresh.isEnabled(), "Refresh must be disabled without a program");

            // Opening the panel for an already analyzed binary must load immediately.
            panel.setProgram(alreadyOpen.program);
            require(roots.getModel().getSize() == 1, "Existing functions must load on panel opening");
            require(refresh.isEnabled(), "An already open program must enable Refresh");
            panel.selectFunction(existing.function);
            filter.setText("existing");
            panel.setProgram(alreadyOpen.program);
            require(panel.getSelectedFunction() == existing.function,
                "Showing the panel again must preserve the selected root");
            require(filter.getText().equals("existing"), "Showing again must preserve the filter");
            require(alreadyOpen.listeners.size() == 1, "Showing again must not duplicate listeners");

            panel.setProgram(first.program);
            require(roots.getModel().getSize() == 0, "Program should initially have no functions");
            require(filter.getText().isEmpty(), "Switching programs must clear the old filter");
            require(alreadyOpen.listeners.isEmpty(), "Switching must detach the already open program");
        });
        require(first.listeners.size() == 1, "Panel must listen to the active program");

        // Reproduce the bug: auto-analysis creates functions after program activation.
        FunctionFixture late = new FunctionFixture("late_function");
        onEdt(() -> first.functions.add(late.function));
        first.fire(ProgramEvent.FUNCTION_ADDED);
        awaitUi(() -> roots.getModel().getSize() == 1);
        onEdt(() -> {
            panel.selectFunction(late.function);
            filter.setText("late");
        });

        FunctionFixture another = new FunctionFixture("late_helper");
        onEdt(() -> first.functions.add(another.function));
        for (int i = 0; i < 20; i++) first.fire(ProgramEvent.FUNCTION_ADDED);
        awaitUi(() -> roots.getModel().getSize() == 2);
        onEdt(() -> {
            require(filter.getText().equals("late"), "Automatic refresh must preserve the filter");
            require(panel.getSelectedFunction() == late.function, "Refresh must preserve the root");
            filter.setText("renamed");
            late.name = "renamed_function";
        });
        first.fire(ProgramEvent.SYMBOL_RENAMED);
        awaitUi(() -> roots.getModel().getSize() == 1);

        onEdt(() -> {
            panel.selectFunction(late.function);
            first.functions.remove(late.function);
            late.deleted = true;
        });
        first.fire(ProgramEvent.FUNCTION_REMOVED);
        awaitUi(() -> roots.getModel().getSize() == 0 && panel.getSelectedFunction() == null);

        onEdt(() -> {
            filter.setText("");
            first.functions.clear();
        });
        first.fire(DomainObjectEvent.RESTORED);
        awaitUi(() -> roots.getModel().getSize() == 0);

        onEdt(() -> {
            first.functions.add(another.function);
            refresh.doClick();
            require(roots.getModel().getSize() == 1, "Manual refresh must reload functions");
        });

        // A queued event from a former program must not reload the newly activated program.
        ProgramFixture second = new ProgramFixture();
        DomainObjectListener oldListener = first.listeners.get(0);
        first.fire(ProgramEvent.FUNCTION_ADDED);
        onEdt(() -> panel.setProgram(second.program));
        require(first.listeners.isEmpty(), "Switching programs must remove the old listener");
        require(second.listeners.size() == 1, "New program must have one listener");
        oldListener.domainObjectChanged(first.event(ProgramEvent.FUNCTION_ADDED));
        onEdt(() -> {});
        // Let any accidentally retained timer fire before checking snapshot counts.
        CountDownLatch settled = new CountDownLatch(1);
        onEdt(() -> {
            Timer timer = new Timer(800, event -> settled.countDown());
            timer.setRepeats(false);
            timer.start();
        });
        require(settled.await(5, TimeUnit.SECONDS), "EDT did not settle");
        onEdt(() -> {
            require(second.reads == 1, "Old program events must not refresh the new program");
            panel.setProgram(null);
            require(!refresh.isEnabled(), "Closing a program must disable Refresh");
        });
        require(second.listeners.isEmpty(), "Closing must detach the listener");
        onEdt(() -> {
            panel.setProgram(second.program);
            panel.dispose();
        });
        require(second.listeners.isEmpty(), "Disposing the panel must detach the listener");
    }

    private static void awaitUi(BooleanSupplier condition) throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        Timer[] poll = new Timer[1];
        onEdt(() -> {
            poll[0] = new Timer(25, event -> {
                if (condition.getAsBoolean()) ready.countDown();
            });
            poll[0].start();
        });
        try {
            require(ready.await(5, TimeUnit.SECONDS), "Timed out waiting for the function list");
        }
        finally {
            onEdt(() -> poll[0].stop());
        }
    }

    private static void onEdt(Runnable action) throws Exception {
        SwingUtilities.invokeAndWait(action);
    }

    private static Component find(Container parent, String name) {
        for (Component child : parent.getComponents()) {
            if (name.equals(child.getName())) return child;
            if (child instanceof Container container) {
                Component found = find(container, name);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class ProgramFixture {
        final List<Function> functions = new ArrayList<>();
        final List<DomainObjectListener> listeners = new ArrayList<>();
        int reads;
        final FunctionManager manager = proxy(FunctionManager.class, (object, method, args) -> {
            if (method.getName().equals("getFunctions")) {
                reads++;
                Iterator<Function> iterator = List.copyOf(functions).iterator();
                return proxy(FunctionIterator.class, (it, call, values) -> switch (call.getName()) {
                    case "hasNext" -> iterator.hasNext();
                    case "next" -> iterator.next();
                    case "iterator" -> it;
                    default -> throw new UnsupportedOperationException(call.getName());
                });
            }
            throw new UnsupportedOperationException(method.getName());
        });
        final Program program = proxy(Program.class, (object, method, args) -> switch (method.getName()) {
            case "getFunctionManager" -> manager;
            case "addListener" -> { listeners.add((DomainObjectListener) args[0]); yield null; }
            case "removeListener" -> { listeners.remove(args[0]); yield null; }
            case "toString" -> "ProgramFixture";
            default -> throw new UnsupportedOperationException(method.getName());
        });

        DomainObjectChangedEvent event(EventType type) {
            return new DomainObjectChangedEvent(program, List.of(new DomainObjectChangeRecord(type)));
        }

        void fire(EventType type) {
            for (DomainObjectListener listener : List.copyOf(listeners)) {
                listener.domainObjectChanged(event(type));
            }
        }
    }

    private static final class FunctionFixture {
        String name;
        boolean deleted;
        final Function function = proxy(Function.class, (object, method, args) -> switch (method.getName()) {
            case "getName", "toString" -> name;
            case "isDeleted" -> deleted;
            case "isExternal" -> false;
            case "getEntryPoint" -> null;
            case "getCalledFunctions" -> Set.of();
            case "equals" -> object == args[0];
            case "hashCode" -> System.identityHashCode(object);
            default -> throw new UnsupportedOperationException(method.getName());
        });

        FunctionFixture(String name) { this.name = name; }
    }

    private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler));
    }
}
