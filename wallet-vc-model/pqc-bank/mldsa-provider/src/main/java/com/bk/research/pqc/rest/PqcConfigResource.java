package com.bk.research.pqc.rest;

import com.bk.research.pqc.HybridConfig;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import java.util.logging.Logger;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.HashMap;

public class PqcConfigResource implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(PqcConfigResource.class.getName());
    
    private final KeycloakSession session;

    public PqcConfigResource(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("config")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConfig() {
        Map<String, String> response = new HashMap<>();
        response.put("algorithm", HybridConfig.getAlgorithm().getValue());
        return Response.ok(response).build();
    }

    @POST
    @Path("config")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setConfig(Map<String, String> request) {
        String alg = request.get("algorithm");
        if (alg == null || alg.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing 'algorithm' parameter").build();
        }

        HybridConfig.PqcAlgorithm pqcAlg = HybridConfig.PqcAlgorithm.fromString(alg);
        HybridConfig.setAlgorithm(pqcAlg);

        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        response.put("algorithm", pqcAlg.getValue());
        
        logger.info("PQC Algorithm updated via API to: " + pqcAlg.getValue());
        
        return Response.ok(response).build();
    }

    @Override
    public void close() {
    }
}
