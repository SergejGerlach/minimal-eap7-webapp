package de.sergejgerlach.security.servlet.boundary;

import de.sergejgerlach.security.servlet.control.HtmlWriter;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.annotation.HttpMethodConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A simple secured HTTP servlet.
 *
 */
@WebServlet("/secured")
@ServletSecurity(httpMethodConstraints = { @HttpMethodConstraint(value = "GET", rolesAllowed = { "SuperUser" }) })
public class SecuredServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(SecuredServlet.class.getName());

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        log.config("=== entry ===");
        try (PrintWriter writer = resp.getWriter()) {
            Principal user = req.getUserPrincipal();
            String body = "Current Principal '" + (user != null ? user.getName() : "NO AUTHENTICATED USER") + "'";
            HtmlWriter.writePage(writer, "Secured Servlet", body);
        }
    }

}
