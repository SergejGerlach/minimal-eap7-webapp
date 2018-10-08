/*
 */
package de.sergejgerlach.security.rest;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.logging.Logger;

@Path("")
@Produces(MediaType.APPLICATION_JSON)
@PermitAll
@Stateless
public class RestApi {

    private static final Logger log = Logger.getLogger(RestApi.class.getName());

    @GET
    @Path("/info")
    public String info() {
        log.config("=== entry info ===");
        return "=== Shared Info ===";
    }

    @GET
    @Path("/echo/{echo}")
    @RolesAllowed("SuperUser")
    public String echo(@PathParam("echo") String param) {
        log.config("=== entry echo ===");
        return "=== " + param + " ===";
    }
}
