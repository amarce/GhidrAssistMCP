/* 
 * 
 */
package ghidrassistmcp;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.function.BiFunction;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend) {
        this(host, port, backend, null, AuthConfig.AuthMode.NONE, "", "", "", "", "", "");
    }

    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this(host, port, backend, provider, AuthConfig.AuthMode.NONE, "", "", "", "", "", "");
    }

    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider,
                                AuthConfig.AuthMode authMode, String authUsername, String authPasswordHash,
                                String oauthIssuer, String oauthJwksUrl, String oauthAudience, String oauthRequiredScope) {
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
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            JacksonMcpJsonMapper mapper = new JacksonMcpJsonMapper(objectMapper);
            String messageEndpoint = "/message";
            String mcpEndpoint = "/mcp";

            AuthStrategy authStrategy = createAuthStrategy();
            if (!(authStrategy instanceof NoAuthStrategy)) {
                FilterHolder authFilterHolder = new FilterHolder(new AuthFilter(authStrategy));
                context.addFilter(authFilterHolder, "/sse", null);
                context.addFilter(authFilterHolder, messageEndpoint, null);
                context.addFilter(authFilterHolder, "/mcp/*", null);
                Msg.info(this, "Auth mode " + authMode.persistedValue() + " enabled for MCP endpoints");
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
                new NoOpBearerTokenValidator());
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

    private static class StaticBearerTokenValidator implements BearerTokenValidator {
        private final String expectedTokenHash;

        StaticBearerTokenValidator(String expectedTokenHash) {
            this.expectedTokenHash = expectedTokenHash != null ? expectedTokenHash : "";
        }

        @Override
        public boolean validate(String token, HttpServletRequest request) {
            return !expectedTokenHash.isEmpty() && PasswordVerifier.verifyPassword(token, expectedTokenHash);
        }
    }

    private static class NoOpBearerTokenValidator implements BearerTokenValidator {
        @Override
        public boolean validate(String token, HttpServletRequest request) {
            return true;
        }
    }

    private static class BearerAuthStrategy implements AuthStrategy {

        private final String issuer;
        private final String jwksUrl;
        private final String audience;
        private final String requiredScope;
        private final BearerTokenValidator tokenValidator;

        BearerAuthStrategy(String issuer, String jwksUrl, String audience, String requiredScope,
                BearerTokenValidator tokenValidator) {
            this.issuer = issuer != null ? issuer : "";
            this.jwksUrl = jwksUrl != null ? jwksUrl : "";
            this.audience = audience != null ? audience : "";
            this.requiredScope = requiredScope != null ? requiredScope : "";
            this.tokenValidator = tokenValidator;
        }

        @Override
        public boolean authorize(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_AUTH_HEADER_PREFIX)) {
                sendBearerChallenge(response, "invalid_request", "Missing Bearer token");
                return false;
            }

            String token = authorizationHeader.substring(BEARER_AUTH_HEADER_PREFIX.length()).trim();
            if (token.isEmpty()) {
                sendBearerChallenge(response, "invalid_request", "Missing Bearer token");
                return false;
            }

            if (!tokenValidator.validate(token, request)) {
                sendBearerChallenge(response, "invalid_token", "Invalid access token");
                return false;
            }

            return true;
        }

        private void sendBearerChallenge(HttpServletResponse response, String errorCode, String description)
                throws java.io.IOException {
            StringJoiner challenge = new StringJoiner(", ", "Bearer ", "");
            challenge.add("realm=\"" + AUTH_REALM + "\"");
            challenge.add("error=\"" + errorCode + "\"");
            challenge.add("error_description=\"" + description + "\"");
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
    }
}
