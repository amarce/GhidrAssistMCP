/*
 * Metadata for a persisted MCP session.
 */
package ghidrassistmcp.session;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Serializable metadata for an MCP Streamable HTTP session.
 * Stored as JSON files on disk to survive server restarts.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class McpSessionMetadata {

    private String sessionId;
    private String protocolVersion;
    private String clientName;
    private String clientVersion;
    private long createdAt;       // epoch millis
    private long lastAccessedAt;  // epoch millis

    public McpSessionMetadata() {
    }

    public McpSessionMetadata(String sessionId, String protocolVersion,
                               String clientName, String clientVersion,
                               long createdAt, long lastAccessedAt) {
        this.sessionId = sessionId;
        this.protocolVersion = protocolVersion;
        this.clientName = clientName;
        this.clientVersion = clientVersion;
        this.createdAt = createdAt;
        this.lastAccessedAt = lastAccessedAt;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(String protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getClientVersion() {
        return clientVersion;
    }

    public void setClientVersion(String clientVersion) {
        this.clientVersion = clientVersion;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getLastAccessedAt() {
        return lastAccessedAt;
    }

    public void setLastAccessedAt(long lastAccessedAt) {
        this.lastAccessedAt = lastAccessedAt;
    }

    @Override
    public String toString() {
        return "McpSessionMetadata{id=" + sessionId +
            ", client=" + clientName + "/" + clientVersion +
            ", protocol=" + protocolVersion + "}";
    }
}
