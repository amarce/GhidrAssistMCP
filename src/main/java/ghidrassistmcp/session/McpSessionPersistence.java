/*
 * File-based MCP session persistence with monthly cleanup.
 */
package ghidrassistmcp.session;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpNotificationHandler;
import io.modelcontextprotocol.server.McpRequestHandler;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.DefaultMcpStreamableServerSessionFactory;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpStreamableServerSession;

/**
 * Manages persistence of MCP Streamable HTTP sessions to disk.
 *
 * Sessions are stored as individual JSON files in a configurable directory.
 * On server startup, persisted sessions are restored into the transport
 * provider's session map so clients can reconnect without re-initializing.
 *
 * Sessions older than 30 days are automatically cleaned up.
 */
public class McpSessionPersistence {

    private static final String SESSION_FILE_SUFFIX = ".json";
    private static final long MAX_SESSION_AGE_DAYS = 30;
    private static final long SYNC_INTERVAL_SECONDS = 30;
    private static final long CLEANUP_INTERVAL_HOURS = 24;

    private final Path storageDir;
    private final ObjectMapper objectMapper;
    private final ScheduledExecutorService scheduler;

    // Cached references obtained via reflection
    private ConcurrentHashMap<String, McpStreamableServerSession> sessionsMap;
    private Map<String, McpRequestHandler<?>> requestHandlers;
    private Map<String, McpNotificationHandler> notificationHandlers;
    private Duration requestTimeout;

    public McpSessionPersistence(Path storageDir) {
        this.storageDir = storageDir;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MCP-Session-Persistence");
            t.setDaemon(true);
            return t;
        });

        try {
            Files.createDirectories(storageDir);
        } catch (IOException e) {
            Msg.error(this, "Failed to create session storage directory: " + storageDir, e);
        }
    }

    /**
     * Initialize persistence by extracting internal references from the transport
     * provider via reflection, restoring persisted sessions, and starting the
     * periodic sync/cleanup scheduler.
     *
     * Must be called AFTER McpServer.sync(transportProvider) has built, since the
     * build phase sets the session factory which contains the request handlers.
     */
    @SuppressWarnings("unchecked")
    public void initialize(HttpServletStreamableServerTransportProvider transportProvider) {
        try {
            // Extract the sessions map from the transport provider
            Field sessionsField = HttpServletStreamableServerTransportProvider.class.getDeclaredField("sessions");
            sessionsField.setAccessible(true);
            sessionsMap = (ConcurrentHashMap<String, McpStreamableServerSession>) sessionsField.get(transportProvider);

            // Extract the session factory
            Field factoryField = HttpServletStreamableServerTransportProvider.class.getDeclaredField("sessionFactory");
            factoryField.setAccessible(true);
            Object factory = factoryField.get(transportProvider);

            if (factory instanceof DefaultMcpStreamableServerSessionFactory defaultFactory) {
                // Extract handler maps and timeout from the factory
                Field handlersField = DefaultMcpStreamableServerSessionFactory.class.getDeclaredField("requestHandlers");
                handlersField.setAccessible(true);
                requestHandlers = (Map<String, McpRequestHandler<?>>) handlersField.get(defaultFactory);

                Field notifField = DefaultMcpStreamableServerSessionFactory.class.getDeclaredField("notificationHandlers");
                notifField.setAccessible(true);
                notificationHandlers = (Map<String, McpNotificationHandler>) notifField.get(defaultFactory);

                Field timeoutField = DefaultMcpStreamableServerSessionFactory.class.getDeclaredField("requestTimeout");
                timeoutField.setAccessible(true);
                requestTimeout = (Duration) timeoutField.get(defaultFactory);
            } else {
                Msg.warn(this, "Session factory is not DefaultMcpStreamableServerSessionFactory, " +
                    "session restoration will be unavailable. Factory type: " +
                    (factory != null ? factory.getClass().getName() : "null"));
            }

            Msg.info(this, "Session persistence initialized, storage: " + storageDir);

        } catch (NoSuchFieldException | IllegalAccessException e) {
            Msg.error(this, "Failed to extract transport internals via reflection. " +
                "Session persistence will only save metadata, not restore sessions. " +
                "This may happen if the MCP SDK version changed.", e);
        }

        // Restore persisted sessions
        int restored = restoreSessions();
        if (restored > 0) {
            Msg.info(this, "Restored " + restored + " persisted session(s)");
        }

        // Clean up old sessions on startup
        int cleaned = cleanupOldSessions();
        if (cleaned > 0) {
            Msg.info(this, "Cleaned up " + cleaned + " expired session(s) (older than " + MAX_SESSION_AGE_DAYS + " days)");
        }

        // Schedule periodic sync and cleanup
        scheduler.scheduleAtFixedRate(this::syncSessionsToDisk, SYNC_INTERVAL_SECONDS, SYNC_INTERVAL_SECONDS, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::cleanupOldSessions, CLEANUP_INTERVAL_HOURS, CLEANUP_INTERVAL_HOURS, TimeUnit.HOURS);
    }

    /**
     * Save a single session's metadata to disk.
     */
    public void saveSession(McpSessionMetadata metadata) {
        Path file = storageDir.resolve(metadata.getSessionId() + SESSION_FILE_SUFFIX);
        try {
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), metadata);
        } catch (IOException e) {
            Msg.error(this, "Failed to persist session " + metadata.getSessionId(), e);
        }
    }

    /**
     * Load all persisted session metadata from disk.
     */
    public List<McpSessionMetadata> loadAllSessions() {
        List<McpSessionMetadata> sessions = new ArrayList<>();
        if (!Files.isDirectory(storageDir)) {
            return sessions;
        }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(storageDir, "*" + SESSION_FILE_SUFFIX)) {
            for (Path file : stream) {
                try {
                    McpSessionMetadata metadata = objectMapper.readValue(file.toFile(), McpSessionMetadata.class);
                    if (metadata.getSessionId() != null) {
                        sessions.add(metadata);
                    }
                } catch (IOException e) {
                    Msg.warn(this, "Failed to read session file: " + file + " - " + e.getMessage());
                }
            }
        } catch (IOException e) {
            Msg.error(this, "Failed to list session files", e);
        }

        return sessions;
    }

    /**
     * Delete a persisted session from disk.
     */
    public void deleteSession(String sessionId) {
        Path file = storageDir.resolve(sessionId + SESSION_FILE_SUFFIX);
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            Msg.warn(this, "Failed to delete session file: " + file, e);
        }
    }

    /**
     * Restore persisted sessions into the transport provider's session map.
     * Creates new McpStreamableServerSession objects with the persisted IDs
     * and the current server's request handlers.
     *
     * @return number of sessions successfully restored
     */
    private int restoreSessions() {
        if (sessionsMap == null || requestHandlers == null || notificationHandlers == null) {
            Msg.info(this, "Cannot restore sessions: transport internals not available");
            return 0;
        }

        List<McpSessionMetadata> persisted = loadAllSessions();
        int restored = 0;

        for (McpSessionMetadata metadata : persisted) {
            try {
                // Skip sessions that are already active (shouldn't happen on fresh start)
                if (sessionsMap.containsKey(metadata.getSessionId())) {
                    continue;
                }

                // Reconstruct client info from persisted metadata
                McpSchema.ClientCapabilities clientCapabilities =
                    McpSchema.ClientCapabilities.builder().build();
                McpSchema.Implementation clientInfo = new McpSchema.Implementation(
                    metadata.getClientName() != null ? metadata.getClientName() : "unknown",
                    metadata.getClientVersion() != null ? metadata.getClientVersion() : "unknown"
                );

                // Create a new session with the persisted ID and current handlers
                McpStreamableServerSession session = new McpStreamableServerSession(
                    metadata.getSessionId(),
                    clientCapabilities,
                    clientInfo,
                    requestTimeout != null ? requestTimeout : Duration.ofSeconds(30),
                    requestHandlers,
                    notificationHandlers
                );

                sessionsMap.put(metadata.getSessionId(), session);
                restored++;

                Msg.info(this, "Restored session: " + metadata.getSessionId() +
                    " (client: " + metadata.getClientName() + "/" + metadata.getClientVersion() + ")");

            } catch (Exception e) {
                Msg.warn(this, "Failed to restore session " + metadata.getSessionId() + ": " + e.getMessage());
                // Remove corrupted session file
                deleteSession(metadata.getSessionId());
            }
        }

        return restored;
    }

    /**
     * Sync current active sessions to disk.
     * Persists any new sessions and removes files for sessions no longer active.
     */
    private void syncSessionsToDisk() {
        if (sessionsMap == null) {
            return;
        }

        try {
            long now = System.currentTimeMillis();

            // Persist active sessions that aren't yet on disk
            for (Map.Entry<String, McpStreamableServerSession> entry : sessionsMap.entrySet()) {
                String sessionId = entry.getKey();
                McpStreamableServerSession session = entry.getValue();
                Path file = storageDir.resolve(sessionId + SESSION_FILE_SUFFIX);

                if (!Files.exists(file)) {
                    // New session - persist it
                    McpSessionMetadata metadata = extractMetadata(sessionId, session, now);
                    saveSession(metadata);
                    Msg.info(this, "Persisted new session: " + sessionId);
                } else {
                    // Existing session - update lastAccessedAt
                    try {
                        McpSessionMetadata metadata = objectMapper.readValue(file.toFile(), McpSessionMetadata.class);
                        metadata.setLastAccessedAt(now);
                        saveSession(metadata);
                    } catch (IOException e) {
                        // Recreate if corrupted
                        McpSessionMetadata metadata = extractMetadata(sessionId, session, now);
                        saveSession(metadata);
                    }
                }
            }

            // Remove persisted sessions that are no longer active
            // (session was terminated by client via DELETE or server-side close)
            List<McpSessionMetadata> persisted = loadAllSessions();
            for (McpSessionMetadata metadata : persisted) {
                if (!sessionsMap.containsKey(metadata.getSessionId())) {
                    deleteSession(metadata.getSessionId());
                    Msg.info(this, "Removed stale session file: " + metadata.getSessionId());
                }
            }

        } catch (Exception e) {
            Msg.warn(this, "Error during session sync: " + e.getMessage());
        }
    }

    /**
     * Clean up sessions older than MAX_SESSION_AGE_DAYS.
     *
     * @return number of sessions cleaned up
     */
    private int cleanupOldSessions() {
        long cutoff = Instant.now().minus(MAX_SESSION_AGE_DAYS, java.time.temporal.ChronoUnit.DAYS).toEpochMilli();
        List<McpSessionMetadata> persisted = loadAllSessions();
        int cleaned = 0;

        for (McpSessionMetadata metadata : persisted) {
            if (metadata.getCreatedAt() > 0 && metadata.getCreatedAt() < cutoff) {
                deleteSession(metadata.getSessionId());
                // Also remove from active sessions if present
                if (sessionsMap != null) {
                    McpStreamableServerSession removed = sessionsMap.remove(metadata.getSessionId());
                    if (removed != null) {
                        try {
                            removed.closeGracefully().block(Duration.ofSeconds(5));
                        } catch (Exception e) {
                            Msg.warn(this, "Error closing expired session: " + e.getMessage());
                        }
                    }
                }
                cleaned++;
                Msg.info(this, "Cleaned up expired session: " + metadata.getSessionId() +
                    " (created: " + Instant.ofEpochMilli(metadata.getCreatedAt()) + ")");
            }
        }

        return cleaned;
    }

    /**
     * Extract metadata from a live session object.
     */
    private McpSessionMetadata extractMetadata(String sessionId, McpStreamableServerSession session, long now) {
        String clientName = "unknown";
        String clientVersion = "unknown";

        try {
            Field clientInfoField = McpStreamableServerSession.class.getDeclaredField("clientInfo");
            clientInfoField.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.concurrent.atomic.AtomicReference<McpSchema.Implementation> clientInfoRef =
                (java.util.concurrent.atomic.AtomicReference<McpSchema.Implementation>) clientInfoField.get(session);
            McpSchema.Implementation impl = clientInfoRef.get();
            if (impl != null) {
                clientName = impl.name();
                clientVersion = impl.version();
            }
        } catch (Exception e) {
            // Fall back to defaults
        }

        return new McpSessionMetadata(sessionId, McpSchema.LATEST_PROTOCOL_VERSION,
            clientName, clientVersion, now, now);
    }

    /**
     * Persist all active sessions before shutdown.
     */
    public void persistBeforeShutdown() {
        if (sessionsMap == null) {
            return;
        }

        long now = System.currentTimeMillis();
        int persisted = 0;

        for (Map.Entry<String, McpStreamableServerSession> entry : sessionsMap.entrySet()) {
            try {
                McpSessionMetadata metadata = extractMetadata(entry.getKey(), entry.getValue(), now);
                saveSession(metadata);
                persisted++;
            } catch (Exception e) {
                Msg.warn(this, "Failed to persist session on shutdown: " + entry.getKey(), e);
            }
        }

        if (persisted > 0) {
            Msg.info(this, "Persisted " + persisted + " session(s) before shutdown");
        }
    }

    /**
     * Shut down the persistence scheduler.
     */
    public void shutdown() {
        persistBeforeShutdown();
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        Msg.info(this, "Session persistence shut down");
    }
}
