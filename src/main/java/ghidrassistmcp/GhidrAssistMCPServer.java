/* 
 * 
 */
package ghidrassistmcp;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.function.BiFunction;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.resources.McpResource;

/**
 * Refactored MCP Server implementation that uses the backend architecture.
 * This class handles HTTP transport and delegates business logic to McpBackend.
 */
public class GhidrAssistMCPServer {

    private static final String AUTH_REALM = "GhidrAssistMCP";
    private static final String BASIC_AUTH_HEADER_PREFIX = "Basic ";
    private static final String BEARER_AUTH_HEADER_PREFIX = "Bearer ";
    
    private final McpBackend backend;
    private final GhidrAssistMCPProvider provider;
    private Server jettyServer;
    private final String host;
    private final int port;
    private final AuthConfig.AuthMode authMode;
    private final String authUsername;
    private final String authPasswordHash;
    private final String oauthIssuer;
    private final String oauthJwksUrl;
    private final String oauthAudience;
    private final String oauthRequiredScope;
    private final String oauthPublicBaseUrl;
    private final boolean oauthTrustForwardedHeaders;
    private final String oauthCallbackId;
    private final ObjectMapper objectMapper;
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend) {
        this(host, port, backend, null, AuthConfig.AuthMode.NONE, "", "", "", "", "", "", "", false, "");
    }

    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this(host, port, backend, provider, AuthConfig.AuthMode.NONE, "", "", "", "", "", "", "", false, "");
    }

    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider,
                                AuthConfig.AuthMode authMode, String authUsername, String authPasswordHash,
                                String oauthIssuer, String oauthJwksUrl, String oauthAudience, String oauthRequiredScope,
                                String oauthPublicBaseUrl, boolean oauthTrustForwardedHeaders,
                                String oauthCallbackId) {
        this.host = host;
        this.port = port;
        this.backend = backend;
        this.provider = provider;
        this.authMode = authMode != null ? authMode : AuthConfig.AuthMode.NONE;
        this.authUsername = authUsername != null ? authUsername : "";
        this.authPasswordHash = authPasswordHash != null ? authPasswordHash : "";
        this.oauthIssuer = oauthIssuer != null ? oauthIssuer : "";
        this.oauthJwksUrl = oauthJwksUrl != null ? oauthJwksUrl : "";
        this.oauthAudience = oauthAudience != null ? oauthAudience : "";
        this.oauthRequiredScope = oauthRequiredScope != null ? oauthRequiredScope : "";
        this.oauthPublicBaseUrl = oauthPublicBaseUrl != null ? oauthPublicBaseUrl : "";
        this.oauthTrustForwardedHeaders = oauthTrustForwardedHeaders;
        this.oauthCallbackId = oauthCallbackId != null ? oauthCallbackId : "";
        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }
    
    public void start() throws Exception {
        Msg.info(this, "Starting MCP Server initialization...");
        
        try {
            // Create Jetty server
            Msg.info(this, "Creating Jetty server on port " + port);
            jettyServer = new Server();
            
            ServerConnector connector = new ServerConnector(jettyServer);
            connector.setHost(host);
            connector.setPort(port);
            jettyServer.addConnector(connector);

            // Create servlet context
            Msg.info(this, "Setting up servlet context");
            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            jettyServer.setHandler(context);

            // Create MCP transport provider using custom ObjectMapper that ignores unknown properties
            Msg.info(this, "Creating MCP transport provider");
            JacksonMcpJsonMapper mapper = new JacksonMcpJsonMapper(objectMapper);
            String messageEndpoint = "/message";
            String mcpEndpoint = "/mcp";

            AuthStrategy authStrategy = createAuthStrategy();
            if (!(authStrategy instanceof NoAuthStrategy)) {
                FilterHolder authFilterHolder = new FilterHolder(new AuthFilter(authStrategy));
                context.addFilter(authFilterHolder, "/sse", null);
                context.addFilter(authFilterHolder, messageEndpoint, null);
                context.addFilter(authFilterHolder, mcpEndpoint, null);
                context.addFilter(authFilterHolder, "/mcp/*", null);
                Msg.info(this, "Auth mode " + authMode.persistedValue() + " enabled for MCP endpoints");
            }

            if (authMode == AuthConfig.AuthMode.OAUTH) {
                OAuthMetadataServlet oauthMetadataServlet = new OAuthMetadataServlet(
                    host, port, oauthIssuer, oauthJwksUrl, oauthAudience, oauthRequiredScope,
                    oauthPublicBaseUrl, oauthTrustForwardedHeaders, objectMapper);
                ServletHolder oauthMetadataHolder = new ServletHolder("oauth-metadata", oauthMetadataServlet);
                context.addServlet(oauthMetadataHolder, "/.well-known/oauth-protected-resource");
                context.addServlet(oauthMetadataHolder, "/.well-known/oauth-protected-resource/mcp");
                context.addServlet(oauthMetadataHolder, "/.well-known/oauth-authorization-server");
                context.addServlet(oauthMetadataHolder, "/mcp/.well-known/oauth-authorization-server");
            }

            HttpServletSseServerTransportProvider sseTransportProvider =
                HttpServletSseServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .messageEndpoint(messageEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            HttpServletStreamableServerTransportProvider streamableTransportProvider =
                HttpServletStreamableServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .mcpEndpoint(mcpEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            // Build MCP server using backend for configuration
            Msg.info(this, "Building MCP server with backend tools");
            var sseServerBuilder = McpServer.sync(sseTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities());

            var streamableServerBuilder = McpServer.sync(streamableTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities());

            // Register each tool individually with its own handler
            for (McpSchema.Tool toolSchema : backend.getAvailableTools()) {
                String toolName = toolSchema.name();
                BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> toolHandler =
                    (exchange, request) -> {
                        // The backend now handles all logging through event listeners
                        Map<String, Object> params = request.arguments();
                        return backend.callTool(toolName, params);
                    };

                sseServerBuilder.toolCall(toolSchema, toolHandler);
                streamableServerBuilder.toolCall(toolSchema, toolHandler);
                Msg.info(this, "Registered tool with MCP server: " + toolName);
            }

            // Register MCP resources and prompts if backend supports them
            if (backend instanceof GhidrAssistMCPBackend) {
                GhidrAssistMCPBackend ghidraBackend = (GhidrAssistMCPBackend) backend;
                registerResources(sseServerBuilder, streamableServerBuilder, ghidraBackend);
                registerPrompts(sseServerBuilder, streamableServerBuilder, ghidraBackend);
            }

            sseServerBuilder.build();
            streamableServerBuilder.build();
            
            // Register MCP servlet - use root path since transport provider handles routing internally
            Msg.info(this, "Registering MCP servlet");
            
            try {
                ServletHolder mcpSseServletHolder = new ServletHolder("mcp-sse-transport", sseTransportProvider);
                mcpSseServletHolder.setAsyncSupported(true);
                context.addServlet(mcpSseServletHolder, "/sse");
                context.addServlet(mcpSseServletHolder, messageEndpoint);

                ServletHolder mcpStreamableServletHolder = new ServletHolder("mcp-streamable-transport", streamableTransportProvider);
                mcpStreamableServletHolder.setAsyncSupported(true);
                context.addServlet(mcpStreamableServletHolder, mcpEndpoint);
                context.addServlet(mcpStreamableServletHolder, "/mcp/*");
                Msg.info(this, "Registered MCP SSE servlet mapping: /*");
                Msg.info(this, "Registered MCP Streamable servlet mapping: /mcp/*");
                
                // Log configuration
                Msg.info(this, "Transport provider class: " + sseTransportProvider.getClass().getName());
                Msg.info(this, "Message endpoint configured as: " + messageEndpoint);
                Msg.info(this, "SSE endpoint will be: /sse (default)");
                Msg.info(this, "Expected client URLs:");
                Msg.info(this, "  SSE: http://" + host + ":" + port + "/sse");
                Msg.info(this, "  Messages: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "Streamable HTTP transport provider class: " + streamableTransportProvider.getClass().getName());
                Msg.info(this, "Streamable MCP endpoint: http://" + host + ":" + port + mcpEndpoint);
                
            } catch (Exception e) {
                Msg.error(this, "Failed to register MCP servlet", e);
            }
            
            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();
            
            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP SSE endpoint: http://" + host + ":" + port + "/sse");
                Msg.info(this, "MCP message endpoint: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "MCP Streamable endpoint: http://" + host + ":" + port + mcpEndpoint);
                Msg.info(this, "Server state: " + jettyServer.getState());
                
                // Log all registered servlets
                var servletHandler = context.getServletHandler();
                var servletMappings = servletHandler.getServletMappings();
                Msg.info(this, "Registered servlet mappings:");
                for (var mapping : servletMappings) {
                    Msg.info(this, "  " + mapping.getServletName() + " -> " + String.join(", ", mapping.getPathSpecs()));
                }
                
                // Log server startup to UI
                if (provider != null) {
                    provider.logSession("Jetty server listening on port " + port);
                    provider.logSession("Registered " + backend.getAvailableTools().size() + " MCP tools");
                    provider.logSession("Ready for MCP client connections");
                }
            } else {
                Msg.error(this, "Failed to start Jetty server - server not in started state");
            }
            
        } catch (Exception e) {
            Msg.error(this, "Exception during MCP Server startup: " + e.getMessage(), e);
            throw e;
        }
    }

    private AuthStrategy createAuthStrategy() {
        if (authMode == AuthConfig.AuthMode.BASIC) {
            return new BasicAuthStrategy(authUsername, authPasswordHash);
        }
        if (authMode == AuthConfig.AuthMode.OAUTH) {
            return new BearerAuthStrategy(oauthIssuer, oauthJwksUrl, oauthAudience, oauthRequiredScope,
                oauthPublicBaseUrl, oauthTrustForwardedHeaders,
                new JwtBearerTokenValidator(oauthIssuer, oauthJwksUrl, oauthAudience, oauthRequiredScope, objectMapper));
        }
        return new NoAuthStrategy();
    }
    
    public void stop() throws Exception {
        if (jettyServer != null) {
            jettyServer.stop();
            Msg.info(this, "GhidrAssistMCP Server stopped");
        }
    }
    
    public void setCurrentProgram(Program program) {
        backend.onProgramActivated(program);
    }

    /**
     * Register MCP prompts with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerPrompts(McpServer.SyncSpecification sseServerBuilder,
                                  McpServer.SyncSpecification streamableServerBuilder,
                                  GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpPrompt> prompts = ghidraBackend.getAvailablePrompts();
            java.util.List<McpServerFeatures.SyncPromptSpecification> promptSpecs = new java.util.ArrayList<>();

            for (McpPrompt prompt : prompts) {
                // Create McpSchema.Prompt for each prompt
                McpSchema.Prompt mcpPrompt = new McpSchema.Prompt(
                    prompt.getName(),
                    prompt.getDescription(),
                    prompt.getArguments()
                );

                // Create handler for getting the prompt
                BiFunction<McpSyncServerExchange, McpSchema.GetPromptRequest, McpSchema.GetPromptResult> promptHandler =
                    (exchange, request) -> {
                        Map<String, Object> rawArgs = request.arguments();
                        Map<String, String> args = new java.util.HashMap<>();
                        if (rawArgs != null) {
                            for (Map.Entry<String, Object> entry : rawArgs.entrySet()) {
                                args.put(entry.getKey(), entry.getValue() != null ? entry.getValue().toString() : null);
                            }
                        }
                        Program program = ghidraBackend.getCurrentProgram();
                        return prompt.generatePrompt(args, program);
                    };

                // Create specification
                McpServerFeatures.SyncPromptSpecification spec =
                    new McpServerFeatures.SyncPromptSpecification(mcpPrompt, promptHandler);
                promptSpecs.add(spec);
                Msg.info(this, "Prepared prompt for registration: " + prompt.getName());
            }

            // Register all prompts with both builders
            if (!promptSpecs.isEmpty()) {
                sseServerBuilder.prompts(promptSpecs);
                streamableServerBuilder.prompts(promptSpecs);
                Msg.info(this, "Registered " + promptSpecs.size() + " MCP prompts");
            }

        } catch (Exception e) {
            Msg.warn(this, "Failed to register MCP prompts: " + e.getMessage(), e);
        }
    }

    /**
     * Register MCP resources with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerResources(McpServer.SyncSpecification sseServerBuilder,
                                   McpServer.SyncSpecification streamableServerBuilder,
                                   GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpResource> resources = ghidraBackend.getAvailableResources();
            java.util.List<McpServerFeatures.SyncResourceSpecification> resourceSpecs = new java.util.ArrayList<>();

            for (McpResource resource : resources) {
                // Create McpSchema.Resource for each resource
                McpSchema.Resource mcpResource = McpSchema.Resource.builder()
                    .uri(resource.getUriPattern())
                    .name(resource.getName())
                    .description(resource.getDescription())
                    .mimeType(resource.getMimeType())
                    .build();

                // Create handler for reading the resource
                BiFunction<McpSyncServerExchange, McpSchema.ReadResourceRequest, McpSchema.ReadResourceResult> readHandler =
                    (exchange, request) -> {
                        String uri = request.uri();
                        String content = ghidraBackend.readResource(uri);

                        if (content == null) {
                            content = "{\"error\": \"Resource not found: " + uri + "\"}";
                        }

                        McpSchema.ResourceContents contents = new McpSchema.TextResourceContents(
                            uri,
                            resource.getMimeType(),
                            content
                        );

                        return new McpSchema.ReadResourceResult(List.of(contents));
                    };

                // Create specification
                McpServerFeatures.SyncResourceSpecification spec =
                    new McpServerFeatures.SyncResourceSpecification(mcpResource, readHandler);
                resourceSpecs.add(spec);
                Msg.info(this, "Prepared resource for registration: " + resource.getName());
            }

            // Register all resources with both builders
            if (!resourceSpecs.isEmpty()) {
                sseServerBuilder.resources(resourceSpecs);
                streamableServerBuilder.resources(resourceSpecs);
                Msg.info(this, "Registered " + resourceSpecs.size() + " MCP resources");
            }

        } catch (Exception e) {
            Msg.warn(this, "Failed to register MCP resources: " + e.getMessage(), e);
        }
    }
    private static class AuthFilter implements Filter {

        private final AuthStrategy authStrategy;

        AuthFilter(AuthStrategy authStrategy) {
            this.authStrategy = authStrategy;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws java.io.IOException, ServletException {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            if (!authStrategy.authorize(httpRequest, httpResponse)) {
                return;
            }

            chain.doFilter(request, response);
        }
    }

    private interface AuthStrategy {
        boolean authorize(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException;
    }

    private static class NoAuthStrategy implements AuthStrategy {
        @Override
        public boolean authorize(HttpServletRequest request, HttpServletResponse response) {
            return true;
        }
    }

    private static class BasicAuthStrategy implements AuthStrategy {

        private final String expectedUsername;
        private final String expectedPasswordHash;

        BasicAuthStrategy(String expectedUsername, String expectedPasswordHash) {
            this.expectedUsername = expectedUsername != null ? expectedUsername : "";
            this.expectedPasswordHash = expectedPasswordHash != null ? expectedPasswordHash : "";
        }

        @Override
        public boolean authorize(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
            String authorizationHeader = request.getHeader("Authorization");
            if (!isAuthorized(authorizationHeader)) {
                response.setHeader("WWW-Authenticate", "Basic realm=\"" + AUTH_REALM + "\"");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                return false;
            }
            return true;
        }

        private boolean isAuthorized(String authorizationHeader) {
            if (authorizationHeader == null || !authorizationHeader.startsWith(BASIC_AUTH_HEADER_PREFIX)) {
                return false;
            }

            String encodedCredentials = authorizationHeader.substring(BASIC_AUTH_HEADER_PREFIX.length());
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(encodedCredentials);
            } catch (IllegalArgumentException e) {
                return false;
            }

            String credentials = new String(decoded, StandardCharsets.UTF_8);
            int separatorIndex = credentials.indexOf(':');
            if (separatorIndex < 0) {
                return false;
            }

            String suppliedUsername = credentials.substring(0, separatorIndex);
            String suppliedPassword = credentials.substring(separatorIndex + 1);

            boolean usernameMatches = PasswordVerifier.constantTimeEquals(
                suppliedUsername.getBytes(StandardCharsets.UTF_8),
                expectedUsername.getBytes(StandardCharsets.UTF_8));
            boolean passwordMatches = PasswordVerifier.verifyPassword(suppliedPassword, expectedPasswordHash);
            return usernameMatches && passwordMatches;
        }
    }

    private interface BearerTokenValidator {
        boolean validate(String token, HttpServletRequest request);
    }

    private static class JwtBearerTokenValidator implements BearerTokenValidator {
        private final String issuer;
        private final String jwksUrl;
        private final String audience;
        private final String requiredScope;
        private final ObjectMapper objectMapper;
        private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

        JwtBearerTokenValidator(String issuer, String jwksUrl, String audience, String requiredScope, ObjectMapper objectMapper) {
            this.issuer = issuer != null ? issuer.trim() : "";
            this.jwksUrl = jwksUrl != null ? jwksUrl.trim() : "";
            this.audience = audience != null ? audience.trim() : "";
            this.requiredScope = requiredScope != null ? requiredScope.trim() : "";
            this.objectMapper = objectMapper;
        }

        @Override
        public boolean validate(String token, HttpServletRequest request) {
            if (issuer.isEmpty() || audience.isEmpty()) {
                return false;
            }
            try {
                ConfigurableJWTProcessor<SecurityContext> processor = getOrCreateProcessor();
                JWTClaimsSet claims = processor.process(token, null);
                if (!requiredScope.isEmpty() && !hasScope(claims, requiredScope)) {
                    return false;
                }
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        private ConfigurableJWTProcessor<SecurityContext> getOrCreateProcessor() throws Exception {
            if (jwtProcessor == null) {
                synchronized (this) {
                    if (jwtProcessor == null) {
                        jwtProcessor = buildJwtProcessor();
                    }
                }
            }
            return jwtProcessor;
        }

        private ConfigurableJWTProcessor<SecurityContext> buildJwtProcessor() throws Exception {
            String resolvedJwks = resolveJwksUrl();
            if (resolvedJwks.isEmpty()) {
                throw new IllegalStateException("Unable to resolve OAuth JWKS URL");
            }

            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new java.net.URL(resolvedJwks));
            processor.setJWSKeySelector(JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(jwkSource));

            JWTClaimsSet.Builder expectedClaimsBuilder = new JWTClaimsSet.Builder();
            if (!issuer.isEmpty()) {
                expectedClaimsBuilder.issuer(issuer);
            }
            Set<String> exactAudienceMatch = audience.isEmpty() ? null : Set.of(audience);
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<SecurityContext>(
                exactAudienceMatch,
                expectedClaimsBuilder.build(),
                null,
                null));
            return processor;
        }

        private String resolveJwksUrl() {
            if (!jwksUrl.isEmpty()) {
                return jwksUrl;
            }
            if (issuer.isEmpty()) {
                return "";
            }
            List<String> metadataUrls = List.of(
                trimSlash(issuer) + "/.well-known/openid-configuration",
                trimSlash(issuer) + "/.well-known/oauth-authorization-server");
            for (String metadataUrl : metadataUrls) {
                String resolved = resolveJwksFromMetadata(metadataUrl);
                if (!resolved.isEmpty()) {
                    return resolved;
                }
            }
            return "";
        }

        private String resolveJwksFromMetadata(String metadataUrl) {
            try {
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(metadataUrl))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
                java.net.http.HttpResponse<String> response = java.net.http.HttpClient.newHttpClient().send(
                    request, java.net.http.HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() / 100 != 2) {
                    return "";
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> metadata = objectMapper.readValue(response.body(), Map.class);
                Object value = metadata.get("jwks_uri");
                return value instanceof String ? (String) value : "";
            } catch (Exception e) {
                return "";
            }
        }

        private boolean hasScope(JWTClaimsSet claims, String scope) {
            Object scopeClaim = claims.getClaim("scope");
            if (scopeClaim instanceof String) {
                for (String tokenScope : ((String) scopeClaim).split("\\s+")) {
                    if (scope.equals(tokenScope)) {
                        return true;
                    }
                }
            }
            Object scpClaim = claims.getClaim("scp");
            if (scpClaim instanceof List<?>) {
                for (Object item : (List<?>) scpClaim) {
                    if (scope.equals(String.valueOf(item))) {
                        return true;
                    }
                }
            }
            return false;
        }

        private String trimSlash(String value) {
            return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        }
    }

    private static class OAuthMetadataServlet extends HttpServlet {
        private final String host;
        private final int port;
        private final String issuer;
        private final String jwksUrl;
        private final String audience;
        private final String requiredScope;
        private final String publicBaseUrl;
        private final boolean trustForwardedHeaders;
        private final ObjectMapper objectMapper;

        OAuthMetadataServlet(String host, int port, String issuer, String jwksUrl, String audience,
                String requiredScope, String publicBaseUrl, boolean trustForwardedHeaders,
                ObjectMapper objectMapper) {
            this.host = host;
            this.port = port;
            this.issuer = issuer != null ? issuer : "";
            this.jwksUrl = jwksUrl != null ? jwksUrl : "";
            this.audience = audience != null ? audience : "";
            this.requiredScope = requiredScope != null ? requiredScope : "";
            this.publicBaseUrl = publicBaseUrl != null ? publicBaseUrl : "";
            this.trustForwardedHeaders = trustForwardedHeaders;
            this.objectMapper = objectMapper;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
            response.setContentType("application/json");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());

            String uri = request.getRequestURI();
            String resolvedBaseUrl = resolveBaseUrl(request);
            if ("/.well-known/oauth-protected-resource".equals(uri) || "/.well-known/oauth-protected-resource/mcp".equals(uri)) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("resource", resolvedBaseUrl);
                if (!issuer.isEmpty()) {
                    metadata.put("authorization_servers", List.of(issuer));
                    metadata.put("bearer_methods_supported", List.of("header"));
                }
                if (!requiredScope.isEmpty()) {
                    metadata.put("scopes_supported", List.of(requiredScope));
                }
                objectMapper.writeValue(response.getWriter(), metadata);
                return;
            }

            if ("/.well-known/oauth-authorization-server".equals(uri) || "/mcp/.well-known/oauth-authorization-server".equals(uri)) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("issuer", issuer);
                if (!jwksUrl.isEmpty()) {
                    metadata.put("jwks_uri", jwksUrl);
                }
                if (!audience.isEmpty()) {
                    metadata.put("resource", audience);
                }
                if (!requiredScope.isEmpty()) {
                    metadata.put("scopes_supported", List.of(requiredScope));
                }
                objectMapper.writeValue(response.getWriter(), metadata);
                return;
            }

            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }

        private String resolveBaseUrl(HttpServletRequest request) {
            if (!publicBaseUrl.isBlank()) {
                return trimSlash(publicBaseUrl);
            }
            if (trustForwardedHeaders) {
                String forwardedUrl = deriveFromForwardedHeaders(request);
                if (!forwardedUrl.isEmpty()) {
                    return forwardedUrl;
                }
            }
            return "http://" + host + ":" + port;
        }

        private String deriveFromForwardedHeaders(HttpServletRequest request) {
            String forwardedProto = firstHeaderValue(request.getHeader("X-Forwarded-Proto"));
            String forwardedHost = firstHeaderValue(request.getHeader("X-Forwarded-Host"));
            if (forwardedProto == null || forwardedProto.isBlank() || forwardedHost == null || forwardedHost.isBlank()) {
                return "";
            }
            return trimSlash(forwardedProto.trim().toLowerCase()) + "://" + trimSlash(forwardedHost.trim());
        }

        private String firstHeaderValue(String value) {
            if (value == null || value.isBlank()) {
                return "";
            }
            int commaIndex = value.indexOf(',');
            String first = commaIndex >= 0 ? value.substring(0, commaIndex) : value;
            return first.trim();
        }

        private String trimSlash(String value) {
            return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        }
    }

    private static class BearerAuthStrategy implements AuthStrategy {

        private final String issuer;
        private final String jwksUrl;
        private final String audience;
        private final String requiredScope;
        private final String publicBaseUrl;
        private final boolean trustForwardedHeaders;
        private final BearerTokenValidator tokenValidator;

        BearerAuthStrategy(String issuer, String jwksUrl, String audience, String requiredScope,
                String publicBaseUrl, boolean trustForwardedHeaders,
                BearerTokenValidator tokenValidator) {
            this.issuer = issuer != null ? issuer : "";
            this.jwksUrl = jwksUrl != null ? jwksUrl : "";
            this.audience = audience != null ? audience : "";
            this.requiredScope = requiredScope != null ? requiredScope : "";
            this.publicBaseUrl = publicBaseUrl != null ? publicBaseUrl : "";
            this.trustForwardedHeaders = trustForwardedHeaders;
            this.tokenValidator = tokenValidator;
        }

        @Override
        public boolean authorize(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_AUTH_HEADER_PREFIX)) {
                sendBearerChallenge(request, response, "invalid_request", "Missing Bearer token");
                return false;
            }

            String token = authorizationHeader.substring(BEARER_AUTH_HEADER_PREFIX.length()).trim();
            if (token.isEmpty()) {
                sendBearerChallenge(request, response, "invalid_request", "Missing Bearer token");
                return false;
            }

            if (!tokenValidator.validate(token, request)) {
                sendBearerChallenge(request, response, "invalid_token", "Invalid access token");
                return false;
            }

            return true;
        }

        private void sendBearerChallenge(HttpServletRequest request, HttpServletResponse response,
                String errorCode, String description)
                throws java.io.IOException {
            StringJoiner challenge = new StringJoiner(", ", "Bearer ", "");
            challenge.add("realm=\"" + AUTH_REALM + "\"");
            challenge.add("error=\"" + errorCode + "\"");
            challenge.add("error_description=\"" + description + "\"");
            String resourceMetadataUrl = buildResourceMetadataUrl(request);
            if (!resourceMetadataUrl.isEmpty()) {
                challenge.add("resource_metadata=\"" + resourceMetadataUrl + "\"");
            }
            if (!issuer.isEmpty()) {
                challenge.add("issuer=\"" + issuer + "\"");
            }
            if (!audience.isEmpty()) {
                challenge.add("audience=\"" + audience + "\"");
            }
            if (!jwksUrl.isEmpty()) {
                challenge.add("jwks_uri=\"" + jwksUrl + "\"");
            }
            if (!requiredScope.isEmpty()) {
                challenge.add("scope=\"" + requiredScope + "\"");
            }

            response.setHeader("WWW-Authenticate", challenge.toString());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }

        private String buildResourceMetadataUrl(HttpServletRequest request) {
            if (!publicBaseUrl.isBlank()) {
                return trimTrailingSlash(publicBaseUrl) + "/.well-known/oauth-protected-resource";
            }
            if (trustForwardedHeaders) {
                String forwardedProto = firstHeaderValue(request.getHeader("X-Forwarded-Proto"));
                String forwardedHost = firstHeaderValue(request.getHeader("X-Forwarded-Host"));
                if (!forwardedProto.isBlank() && !forwardedHost.isBlank()) {
                    return forwardedProto.toLowerCase() + "://" + forwardedHost + "/.well-known/oauth-protected-resource";
                }
            }

            String hostHeader = request.getHeader("Host");
            if (hostHeader == null || hostHeader.isBlank()) {
                return "";
            }
            String scheme = request.getScheme();
            String normalizedScheme = (scheme == null || scheme.isBlank()) ? "http" : scheme;
            return normalizedScheme + "://" + firstHeaderValue(hostHeader) + "/.well-known/oauth-protected-resource";
        }

        private String firstHeaderValue(String value) {
            if (value == null || value.isBlank()) {
                return "";
            }
            int commaIndex = value.indexOf(',');
            String first = commaIndex >= 0 ? value.substring(0, commaIndex) : value;
            return first.trim();
        }

        private String trimTrailingSlash(String value) {
            return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        }
    }
}
