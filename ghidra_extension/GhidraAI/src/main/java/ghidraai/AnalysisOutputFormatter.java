package ghidraai;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Only the script's known result sections belong in the analyst's result view. */
final class AnalysisOutputFormatter {
    private static final List<String> HEADINGS = List.of(
        "Function", "Address", "Vulnerability Classification", "Vulnerable Code Isolation",
        "Root Cause & Impact Analysis", "Remediation & Patch Verification");
    private static final String FAILURE =
        "Analysis could not be completed. See the Ghidra console for details.";

    record FormattedResult(String html, String status) {}

    private AnalysisOutputFormatter() {}

    static String format(String output) { return present(output).html(); }

    static FormattedResult present(String output) {
        if (output == null || output.isBlank()) {
            return error("Analysis returned no result. See the Ghidra console for details.");
        }
        List<String> lines = output.lines().map(String::strip).toList();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (line.equals("Analysis cancelled.")) {
                return new FormattedResult(message("Analysis cancelled."), "Analysis cancelled.");
            }
            for (String prefix : List.of("AI analysis failed:", "Could not start analysis:")) {
                if (line.startsWith(prefix)) {
                    String detail = line.substring(prefix.length()).strip();
                    if (detail.isEmpty()) {
                        detail = lines.subList(index + 1, lines.size()).stream()
                            .filter(value -> !value.isBlank()).findFirst().orElse("");
                    }
                    return error(friendlyError(detail));
                }
            }
            if (line.equals("Traceback (most recent call last):") ||
                    line.matches("at [\\w.$]+\\([^)]*\\.java[^)]*\\)")) {
                return error(FAILURE);
            }
        }
        if (!lines.contains("===== ANALYSIS RESULT =====")) {
            return error("No complete analysis result was received. See the Ghidra console for details.");
        }

        Map<String, List<String>> sections = new LinkedHashMap<>();
        String current = null;
        String program = null;
        boolean resultStarted = false;
        for (String line : lines) {
            if (line.equals("===== ANALYSIS RESULT =====")) {
                resultStarted = true;
                current = null;
                continue;
            }
            if (!resultStarted) {
                if (line.startsWith("Program: ") && current == null) {
                    program = line.substring("Program: ".length());
                }
                else if (line.equals("Function:") || line.equals("Address:")) {
                    current = line.substring(0, line.length() - 1);
                    sections.put(current, new ArrayList<>());
                }
                else if (current != null && sections.get(current).isEmpty() &&
                        !line.isBlank() && !isDebugLine(line)) {
                    sections.get(current).add(line);
                }
                continue;
            }
            if (HEADINGS.stream().anyMatch(heading -> line.equals(heading + ":"))) {
                current = line.substring(0, line.length() - 1);
                sections.put(current, new ArrayList<>());
            }
            else if (current != null && !isDebugLine(line)) {
                sections.get(current).add(line);
            }
        }
        if (!sections.keySet().containsAll(HEADINGS)) {
            return error("The analysis response was incomplete. Try again; details are in the Ghidra console.");
        }
        StringBuilder body = new StringBuilder();
        if (program != null) {
            body.append("<p><b>Program:</b> ").append(text(program)).append("</p>");
        }
        for (String heading : HEADINGS) {
            body.append("<h3>").append(heading).append("</h3>");
            String value = String.join("\n", sections.get(heading)).strip();
            if (heading.equals("Vulnerable Code Isolation")) {
                body.append("<pre>").append(escapedText(value.isEmpty() ? "Not provided." : value))
                    .append("</pre>");
            }
            else {
                body.append("<p>").append(text(value.isEmpty() ? "Not provided." : value)).append("</p>");
            }
        }
        return new FormattedResult(page(body.toString()), "Analysis complete.");
    }

    private static boolean isDebugLine(String line) {
        return line.matches("=+") || line.equals("AI FUNCTION ANALYSIS") ||
            line.equals("Sending function to Qwen...") ||
            line.equals("Sending function to the local model...") ||
            line.matches("(?:DEBUG|INFO|WARNING|ERROR)(?::.*| \\[[^]]+\\].*)") ||
            line.matches("File \".*\", line [0-9]+.*");
    }

    private static String friendlyError(String detail) {
        String lower = detail.toLowerCase(Locale.ROOT);
        if (lower.contains("timed out") || lower.contains("timeout")) {
            return "The model request timed out. Check Ollama and try again.";
        }
        if (lower.contains("connectionpool") || lower.contains("connection refused") ||
                lower.contains("failed to establish a new connection")) {
            return "Could not reach the analysis service. Check that Ollama is running.";
        }
        if ((lower.contains("script") || lower.contains("analyzecurrentfunction.py")) && lower.contains("not found")) {
            return "Analysis script not found. Add the project's ghidra_scripts directory in Script Manager.";
        }
        if (lower.contains("pyghidra")) {
            return "Start Ghidra with PyGhidra to run the analysis script.";
        }
        if (lower.contains("four-section markdown report") ||
                lower.contains("required report heading") ||
                lower.contains("duplicate report heading") ||
                lower.contains("report headings are out of order") ||
                lower.contains("ai response section")) {
            return "The model response was incomplete or did not match the four-section report. Try again.";
        }
        if (lower.contains("output limit") || lower.contains("output-token limit")) {
            return "The model response reached its output limit. Reduce the report or increase num_predict.";
        }
        return FAILURE;
    }

    static FormattedResult error(String message) {
        return new FormattedResult(page("<h3>Analysis failed</h3><p>" + text(message) + "</p>"), "Analysis failed.");
    }

    static String message(String message) { return page("<p>" + text(message) + "</p>"); }

    private static String text(String value) {
        return escapedText(value).replace("\r\n", "\n").replace("\n", "<br>");
    }

    private static String escapedText(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String page(String body) {
        return "<html><head><style>body { margin: 12px; } " +
            "h3 { margin-top: 14px; margin-bottom: 5px; } " +
            "p { margin-top: 0; margin-bottom: 10px; } " +
            "pre { white-space: pre-wrap; overflow-wrap: anywhere; }" +
            "</style></head><body>" + body + "</body></html>";
    }
}
