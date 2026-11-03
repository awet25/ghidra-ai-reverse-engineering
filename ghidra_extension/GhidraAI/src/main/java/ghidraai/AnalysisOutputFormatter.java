package ghidraai;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Formats the existing script's labeled console output for the Swing result view. */
final class AnalysisOutputFormatter {
    private static final List<String> HEADINGS = List.of(
        "Function", "Address", "Summary", "Suggested Name", "Suspicious Behaviors",
        "Evidence", "Confidence", "Limitations");
    private static final Set<String> LIST_HEADINGS = Set.of(
        "Suspicious Behaviors", "Evidence", "Limitations");

    private AnalysisOutputFormatter() {
    }

    static String format(String output) {
        if (output == null || output.isBlank()) {
            return page("");
        }
        List<String> lines = output.lines().map(String::strip).toList();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            for (String prefix : List.of("AI analysis failed:", "Could not start analysis:")) {
                if (line.startsWith(prefix)) {
                    String message = line.substring(prefix.length()).strip();
                    if (message.isEmpty()) {
                        message = lines.subList(i + 1, lines.size()).stream()
                            .filter(value -> !value.isEmpty()).findFirst()
                            .orElse("No error details were provided.");
                    }
                    return page("<h3>Analysis failed</h3><p>" + text(message) + "</p>");
                }
            }
            if (line.equals("Traceback (most recent call last):")) {
                String message = lines.stream().filter(value -> !value.isEmpty())
                    .reduce((first, last) -> last).orElse("Python script failed.");
                return page("<h3>Analysis failed</h3><p>" + text(message) + "</p>");
            }
            if (line.equals("Analysis cancelled.")) {
                return page("<p>Analysis cancelled.</p>");
            }
        }
        if (!lines.contains("===== ANALYSIS RESULT =====")) {
            return page("<p>" + text(output.strip()) + "</p>");
        }

        Map<String, List<String>> sections = new LinkedHashMap<>();
        String current = null;
        String program = null;
        for (String line : lines) {
            if (line.startsWith("Program: ") && current == null) {
                program = line.substring("Program: ".length());
            }
            else if (HEADINGS.stream().anyMatch(heading -> line.equals(heading + ":"))) {
                current = line.substring(0, line.length() - 1);
                sections.put(current, new ArrayList<>());
            }
            else if (current != null && !line.matches("=+") &&
                    !line.equals("AI FUNCTION ANALYSIS") &&
                    !line.equals("===== ANALYSIS RESULT =====") &&
                    !line.equals("Sending function to Qwen...")) {
                sections.get(current).add(line);
            }
        }
        // Retain unfamiliar output rather than silently discarding script diagnostics.
        if (!sections.keySet().containsAll(HEADINGS)) {
            return page("<p>" + text(output.strip()) + "</p>");
        }
        StringBuilder body = new StringBuilder();
        if (program != null) {
            body.append("<p><b>Program:</b> ").append(text(program)).append("</p>");
        }
        for (String heading : HEADINGS) {
            body.append("<h3>").append(heading).append("</h3>");
            String value = String.join("\n", sections.get(heading)).strip();
            if (LIST_HEADINGS.contains(heading)) {
                appendList(body, value);
            }
            else {
                body.append("<p>").append(text(value.isEmpty() ? "Not provided." : value))
                    .append("</p>");
            }
        }
        return page(body.toString());
    }

    private static void appendList(StringBuilder body, String value) {
        if (value.isEmpty() || value.equals("None")) {
            body.append("<p>None</p>");
            return;
        }
        body.append("<ul>");
        StringBuilder item = new StringBuilder();
        for (String line : value.lines().toList()) {
            if (line.startsWith("- ") || line.startsWith("\u2022 ")) {
                if (!item.isEmpty()) {
                    body.append("<li>").append(text(item.toString().strip())).append("</li>");
                    item.setLength(0);
                }
                item.append(line.substring(2));
            }
            else {
                if (!item.isEmpty()) {
                    item.append('\n');
                }
                item.append(line);
            }
        }
        if (!item.isEmpty()) {
            body.append("<li>").append(text(item.toString().strip())).append("</li>");
        }
        body.append("</ul>");
    }

    private static String text(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\r\n", "\n").replace("\n", "<br>");
    }

    private static String page(String body) {
        return "<html><head><style>body { margin: 10px; } " +
            "h3 { margin-top: 12px; margin-bottom: 4px; } " +
            "p { margin-top: 0; margin-bottom: 8px; } ul { margin-top: 0; }" +
            "</style></head><body>" + body + "</body></html>";
    }
}
