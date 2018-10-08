package de.sergejgerlach.security.servlet.control;

import java.io.PrintWriter;

public class HtmlWriter {

    public static void writePage(PrintWriter writer, String header, String body) {
        writer.println("<html>");
        writer.println("  <head><title>Servlet</title></head>");
        writer.println("  <body>");
        writer.println("    <h1>" + header + "</h1>");
        writer.println("    <p>");
        writer.print(body);
        writer.println("    </p>");
        writer.println("  </body>");
        writer.println("</html>");
    }
}
