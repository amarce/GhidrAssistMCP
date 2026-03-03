/* 
 * 
 */
package ghidrassistmcp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * UI Provider for the GhidrAssistMCP plugin featuring configuration and logging tabs.
 */
public class GhidrAssistMCPProvider extends ComponentProvider implements McpEventListener {
    
    private static final String NAME = "GhidrAssistMCP";
    private static final String OWNER = "GhidrAssistMCPPlugin";
    
    // Settings constants
    private static final String SETTINGS_CATEGORY = "GhidrAssistMCP";
    private static final String HOST_SETTING = "Server Host";
    private static final String PORT_SETTING = "Server Port";
    private static final String ENABLED_SETTING = "Server Enabled";
    private static final String ASYNC_ENABLED_SETTING = "Async Execution Enabled";
    private static final String ALLOW_DESTRUCTIVE_TOOLS_SETTING = "Allow Destructive Tools";
    private static final String TOOL_PREFIX = "Tool.";
    
    // Default values
    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 8080;
    private static final boolean DEFAULT_ENABLED = true;
    private static final boolean DEFAULT_ASYNC_ENABLED = true;
    private static final boolean DEFAULT_ALLOW_DESTRUCTIVE_TOOLS = false;
    private static final String DEFAULT_AUTH_USERNAME = AuthConfig.DEFAULT_BASIC_USERNAME;
    
    private final PluginTool tool;
    private final GhidrAssistMCPPlugin plugin;
    private JTabbedPane tabbedPane;
    
    // Configuration tab components
    private JTextField hostField = new JTextField(DEFAULT_HOST, 20);
    private JSpinner portSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_PORT, 1, 65535, 1));
    private JCheckBox enabledCheckBox = new JCheckBox("Enable MCP Server", DEFAULT_ENABLED);
    private JCheckBox asyncEnabledCheckBox = new JCheckBox("Enable async tool execution", DEFAULT_ASYNC_ENABLED);
    private JCheckBox allowDestructiveToolsCheckBox = new JCheckBox("Allow destructive tools globally", DEFAULT_ALLOW_DESTRUCTIVE_TOOLS);
    private JComboBox<AuthConfig.AuthMode> authModeComboBox = new JComboBox<>(AuthConfig.AuthMode.values());
    private JPanel basicAuthPanel = new JPanel();
    private JPanel oauthPanel = new JPanel();
    private JTextField authUsernameField = new JTextField(DEFAULT_AUTH_USERNAME, 20);
    private JPasswordField authPasswordField = new JPasswordField("", 20);
    private JTextField oauthIssuerField = new JTextField("", 20);
    private JTextField oauthJwksUrlField = new JTextField("", 20);
    private JTextField oauthAudienceField = new JTextField("", 20);
    private JTextField oauthRequiredScopeField = new JTextField("", 20);
    private JTextField oauthCallbackIdField = new JTextField("", 20);
    private JTable toolsTable;
    private DefaultTableModel toolsTableModel;
    private JButton saveButton;
    private Map<String, Boolean> toolEnabledStates;
    private String currentBasicAuthPasswordHash = "";
    
    // Log tab components
    private JTextArea logTextArea;
    private JButton clearButton;
    private SimpleDateFormat dateFormat;
    
    public GhidrAssistMCPProvider(PluginTool tool, GhidrAssistMCPPlugin plugin) {
        super(tool, NAME, OWNER);
        this.tool = tool;
        this.plugin = plugin;
        this.toolEnabledStates = new HashMap<>();
        this.dateFormat = new SimpleDateFormat("HH:mm:ss");
        
        buildComponent();
        createActions();
        // Don't load settings yet - wait for backend to be ready
        
        setHelpLocation(new HelpLocation("GhidrAssistMCP", "GhidrAssistMCP_Provider"));
        setVisible(true);
        
        // Add focus listener to refresh tools when window receives focus
        addFocusListener();
    }
    
    private void buildComponent() {
        tabbedPane = new JTabbedPane();
        
        // Configuration tab
        JPanel configPanel = createConfigurationPanel();
        tabbedPane.addTab("Configuration", configPanel);
        
        // Log tab
        JPanel logPanel = createLogPanel();
        tabbedPane.addTab("Log", logPanel);
        
        // Component will be returned by getComponent() method
    }
    
    private JPanel createConfigurationPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Server settings panel
        JPanel serverPanel = new JPanel(new GridBagLayout());
        serverPanel.setBorder(BorderFactory.createTitledBorder("Server Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Host setting
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        serverPanel.add(new JLabel("Host:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        hostField = new JTextField(DEFAULT_HOST, 20);
        serverPanel.add(hostField, gbc);
        
        // Port setting
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        serverPanel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        portSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_PORT, 1, 65535, 1));
        serverPanel.add(portSpinner, gbc);
        
        // Enabled setting
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE;
        enabledCheckBox = new JCheckBox("Enable MCP Server", DEFAULT_ENABLED);
        serverPanel.add(enabledCheckBox, gbc);
        
        // Async execution setting
        gbc.gridy = 3;
        asyncEnabledCheckBox = new JCheckBox("Enable async tool execution", DEFAULT_ASYNC_ENABLED);
        asyncEnabledCheckBox.setToolTipText("When enabled, long-running tools execute asynchronously and return a task ID. When disabled, all tools execute synchronously.");
        serverPanel.add(asyncEnabledCheckBox, gbc);
        
        // Destructive policy setting
        gbc.gridy = 4;
        allowDestructiveToolsCheckBox = new JCheckBox("Allow destructive tools globally", DEFAULT_ALLOW_DESTRUCTIVE_TOOLS);
        allowDestructiveToolsCheckBox.setToolTipText("When disabled, destructive tool calls require confirm_destructive=true per request.");
        serverPanel.add(allowDestructiveToolsCheckBox, gbc);

        // Auth mode setting
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        serverPanel.add(new JLabel("Auth Mode:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        authModeComboBox = new JComboBox<>(AuthConfig.AuthMode.values());
        authModeComboBox.setToolTipText("none: no auth, basic: username/password, oauth: bearer token. Some clients (including OpenAI-hosted tools) require OAuth for authenticated MCP servers.");
        serverPanel.add(authModeComboBox, gbc);

        gbc.gridy = 6;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JLabel authCompatibilityNote = new JLabel("Note: Some clients (including OpenAI-hosted tools) require OAuth for authenticated MCP servers.");
        authCompatibilityNote.setForeground(new Color(180, 110, 0));
        serverPanel.add(authCompatibilityNote, gbc);

        gbc.gridy = 7;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        basicAuthPanel = createBasicAuthPanel();
        serverPanel.add(basicAuthPanel, gbc);

        gbc.gridy = 8;
        oauthPanel = createOauthPanel();
        serverPanel.add(oauthPanel, gbc);

        authModeComboBox.addActionListener(e -> updateAuthFieldVisibility());

        panel.add(serverPanel, BorderLayout.NORTH);
        
        // Tools panel
        JPanel toolsPanel = new JPanel(new BorderLayout());
        toolsPanel.setBorder(BorderFactory.createTitledBorder("MCP Tools"));
        
        // Tools table
        String[] columnNames = {"Enabled", "Tool Name", "Description"};
        toolsTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 0 ? Boolean.class : String.class;
            }
            
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // Only the checkbox column is editable
            }
        };
        
        toolsTable = new JTable(toolsTableModel);
        toolsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        toolsTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        toolsTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        
        JScrollPane scrollPane = new JScrollPane(toolsTable);
        scrollPane.setPreferredSize(new Dimension(500, 200));
        toolsPanel.add(scrollPane, BorderLayout.CENTER);
        
        panel.add(toolsPanel, BorderLayout.CENTER);
        
        // Save button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(new SaveConfigurationListener());
        buttonPanel.add(saveButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createBasicAuthPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Basic Authentication"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        authUsernameField = new JTextField(DEFAULT_AUTH_USERNAME, 20);
        panel.add(authUsernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        authPasswordField = new JPasswordField("", 20);
        panel.add(authPasswordField, gbc);

        return panel;
    }

    private JPanel createOauthPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("OAuth / Bearer Settings"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel("Issuer URL:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        oauthIssuerField = new JTextField("", 20);
        panel.add(oauthIssuerField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("JWKS URL (optional):"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        oauthJwksUrlField = new JTextField("", 20);
        panel.add(oauthJwksUrlField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Audience:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        oauthJwksUrlField = new JTextField("", 20);
        panel.add(oauthJwksUrlField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Required Scope (optional):"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        oauthRequiredScopeField = new JTextField("", 20);
        panel.add(oauthRequiredScopeField, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Callback ID (optional):"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        oauthCallbackIdField = new JTextField("", 20);
        oauthCallbackIdField.setToolTipText("Some clients may require callback_id for OAuth connector setup.");
        panel.add(oauthCallbackIdField, gbc);

        return panel;
    }

    private void updateAuthFieldVisibility() {
        AuthConfig.AuthMode selectedMode = (AuthConfig.AuthMode) authModeComboBox.getSelectedItem();
        boolean showBasic = selectedMode == AuthConfig.AuthMode.BASIC;
        boolean showOauth = selectedMode == AuthConfig.AuthMode.OAUTH;
        basicAuthPanel.setVisible(showBasic);
        oauthPanel.setVisible(showOauth);
        basicAuthPanel.revalidate();
        oauthPanel.revalidate();
    }

    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Log text area
        logTextArea = new JTextArea(20, 60);
        logTextArea.setEditable(false);
        logTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logTextArea.setBackground(Color.BLACK);
        logTextArea.setForeground(Color.GREEN);
        JScrollPane scrollPane = new JScrollPane(logTextArea);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Clear button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        clearButton = new JButton("Clear Log");
        clearButton.addActionListener(e -> clearLog());
        buttonPanel.add(clearButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void createActions() {
        DockingAction refreshAction = new DockingAction("Refresh", OWNER) {
            @Override
            public void actionPerformed(ActionContext context) {
                refreshToolsList();
            }
        };
        refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        refreshAction.setDescription("Refresh tools list");
        refreshAction.setHelpLocation(new HelpLocation("GhidrAssistMCP", "Refresh"));
        
        addLocalAction(refreshAction);
    }
    
    private void addFocusListener() {
        // Add focus listener to the main component to refresh tools when window receives focus
        tabbedPane.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                // Notify manager that this tool's window gained focus
                if (plugin != null && plugin.getManager() != null) {
                    plugin.getManager().setActiveTool(tool);
                }
                // Refresh tools list when the window receives focus
                refreshToolsList();
            }

            @Override
            public void focusLost(FocusEvent e) {
                // No action needed when focus is lost
            }
        });
    }
    
    public void refreshToolsList() {
        // Clear existing rows
        toolsTableModel.setRowCount(0);
        
        // Get tools from backend
        if (plugin != null && plugin.getBackend() != null) {
            try {
                // Get all tools (including disabled ones) for configuration display
                var tools = plugin.getBackend().getAllTools();
                
                // Sync enabled states with backend
                var backendStates = plugin.getBackend().getToolEnabledStates();
                toolEnabledStates.putAll(backendStates);
                
                for (var tool1 : tools) {
                    String toolName = tool1.name();
                    boolean enabled = toolEnabledStates.getOrDefault(toolName, true);
                    String description = tool1.description();
                    
                    // Truncate long descriptions
                    if (description != null && description.length() > 80) {
                        description = description.substring(0, 77) + "...";
                    }
                    
                    toolsTableModel.addRow(new Object[]{enabled, toolName, description});
                }
                logMessage("Refreshed tools list: " + tools.size() + " tools available");
            } catch (Exception e) {
                logMessage("Error refreshing tools list: " + e.getMessage());
            }
        } else {
            logMessage("Backend not available yet - tools list empty");
        }
    }
    
    private void loadSettings() {
        // Load server settings from Ghidra's global preferences
        String host = Preferences.getProperty(SETTINGS_CATEGORY + "." + HOST_SETTING, DEFAULT_HOST);
        String portStr = Preferences.getProperty(SETTINGS_CATEGORY + "." + PORT_SETTING, String.valueOf(DEFAULT_PORT));
        String enabledStr = Preferences.getProperty(SETTINGS_CATEGORY + "." + ENABLED_SETTING, String.valueOf(DEFAULT_ENABLED));
        String asyncEnabledStr = Preferences.getProperty(SETTINGS_CATEGORY + "." + ASYNC_ENABLED_SETTING, String.valueOf(DEFAULT_ASYNC_ENABLED));
        String allowDestructiveStr = Preferences.getProperty(SETTINGS_CATEGORY + "." + ALLOW_DESTRUCTIVE_TOOLS_SETTING, String.valueOf(DEFAULT_ALLOW_DESTRUCTIVE_TOOLS));
        AuthConfig.AuthMode authMode = AuthConfig.AuthMode.fromPersisted(
            Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.AUTH_MODE_SETTING), "none"));
        String authUsername = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.BASIC_USERNAME_SETTING), DEFAULT_AUTH_USERNAME);
        String oauthIssuer = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.OAUTH_ISSUER_SETTING), "");
        String oauthJwksUrl = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.OAUTH_JWKS_URL_SETTING), "");
        String oauthAudience = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.OAUTH_AUDIENCE_SETTING), "");
        String oauthRequiredScope = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.OAUTH_REQUIRED_SCOPE_SETTING), "");
        String oauthCallbackId = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.OAUTH_CALLBACK_ID_SETTING), "");

        currentBasicAuthPasswordHash = AuthConfig.resolveBasicPasswordHash();
        String legacyBasicPassword = Preferences.getProperty(AuthConfig.getQualifiedKey(AuthConfig.BASIC_PASSWORD_SETTING), "");
        String authPassword = (!legacyBasicPassword.isEmpty() && currentBasicAuthPasswordHash.isEmpty())
            ? legacyBasicPassword
            : "";

        int port = DEFAULT_PORT;
        boolean enabled = DEFAULT_ENABLED;
        boolean asyncEnabled = DEFAULT_ASYNC_ENABLED;
        boolean allowDestructiveTools = DEFAULT_ALLOW_DESTRUCTIVE_TOOLS;
        try {
            port = Integer.parseInt(portStr);
            enabled = Boolean.parseBoolean(enabledStr);
            asyncEnabled = Boolean.parseBoolean(asyncEnabledStr);
            allowDestructiveTools = Boolean.parseBoolean(allowDestructiveStr);
        } catch (NumberFormatException e) {
            logMessage("Warning: Failed to parse preferences, using defaults");
        }

        hostField.setText(host);
        portSpinner.setValue(port);
        enabledCheckBox.setSelected(enabled);
        asyncEnabledCheckBox.setSelected(asyncEnabled);
        allowDestructiveToolsCheckBox.setSelected(allowDestructiveTools);
        authModeComboBox.setSelectedItem(authMode);
        authUsernameField.setText(authUsername);
        authPasswordField.setText(authPassword);
        oauthIssuerField.setText(oauthIssuer);
        oauthJwksUrlField.setText(oauthJwksUrl);
        oauthAudienceField.setText(oauthAudience);
        oauthRequiredScopeField.setText(oauthRequiredScope);
        oauthCallbackIdField.setText(oauthCallbackId);
        updateAuthFieldVisibility();

        // Load tool enabled states from tool options
        Options options = tool.getOptions(SETTINGS_CATEGORY);

        toolEnabledStates.clear();
        if (plugin != null && plugin.getBackend() != null) {
            try {
                var tools = plugin.getBackend().getAllTools();
                int loadedCount = 0;
                for (var tool1 : tools) {
                    String toolName = tool1.name();
                    boolean toolEnabled = options.getBoolean(TOOL_PREFIX + toolName, true);
                    toolEnabledStates.put(toolName, toolEnabled);
                    loadedCount++;
                }
                // Update backend with loaded settings
                plugin.getBackend().updateToolEnabledStates(toolEnabledStates);
                logMessage("Loaded tool states from settings: " + loadedCount + " tools configured");
            } catch (Exception e) {
                logMessage("Error loading tool states: " + e.getMessage());
            }
        } else {
            logMessage("Backend not available - skipping tool state loading");
        }
    }
    
    private void saveSettings() {
        // Save server settings to Ghidra's global preferences
        Preferences.setProperty(SETTINGS_CATEGORY + "." + HOST_SETTING, hostField.getText());
        Preferences.setProperty(SETTINGS_CATEGORY + "." + PORT_SETTING, String.valueOf(portSpinner.getValue()));
        Preferences.setProperty(SETTINGS_CATEGORY + "." + ENABLED_SETTING, String.valueOf(enabledCheckBox.isSelected()));
        Preferences.setProperty(SETTINGS_CATEGORY + "." + ASYNC_ENABLED_SETTING, String.valueOf(asyncEnabledCheckBox.isSelected()));
        Preferences.setProperty(SETTINGS_CATEGORY + "." + ALLOW_DESTRUCTIVE_TOOLS_SETTING, String.valueOf(allowDestructiveToolsCheckBox.isSelected()));
        AuthConfig.AuthMode authMode = (AuthConfig.AuthMode) authModeComboBox.getSelectedItem();
        String enteredPassword = new String(authPasswordField.getPassword());
        currentBasicAuthPasswordHash = AuthConfig.chooseHashForSave(enteredPassword, currentBasicAuthPasswordHash);

        AuthConfig.persistAuthSettings(authMode, authUsernameField.getText(), currentBasicAuthPasswordHash,
            oauthIssuerField.getText(), oauthJwksUrlField.getText(), oauthAudienceField.getText(),
            oauthRequiredScopeField.getText(), oauthCallbackIdField.getText(), "", "");

        // Force preferences to be saved to disk
        Preferences.store();

        // Save tool enabled states to tool options
        Options options = tool.getOptions(SETTINGS_CATEGORY);
        int savedCount = 0;
        for (int i = 0; i < toolsTableModel.getRowCount(); i++) {
            String toolName = (String) toolsTableModel.getValueAt(i, 1);
            boolean enabled = (Boolean) toolsTableModel.getValueAt(i, 0);
            toolEnabledStates.put(toolName, enabled);
            options.setBoolean(TOOL_PREFIX + toolName, enabled);
            savedCount++;
        }
        
        logMessage("Saved configuration to Ghidra options: server + " + savedCount + " tools");

        // Apply changes to the plugin
        plugin.applyConfiguration(hostField.getText(), (Integer) portSpinner.getValue(),
                                enabledCheckBox.isSelected(), asyncEnabledCheckBox.isSelected(),
                                allowDestructiveToolsCheckBox.isSelected(), authMode,
                                authUsernameField.getText(), enteredPassword,
                                oauthIssuerField.getText(), oauthJwksUrlField.getText(), oauthAudienceField.getText(),
                                oauthRequiredScopeField.getText(), oauthCallbackIdField.getText(),
                                toolEnabledStates);
    }
    
    public void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = dateFormat.format(new Date());
            String logEntry = "[" + timestamp + "] " + sanitizeLogMessage(message) + "\n";
            logTextArea.append(logEntry);
            logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
        });
    }

    private String sanitizeLogMessage(String message) {
        if (message == null) {
            return "";
        }

        return message
            .replaceAll("(?i)(authorization\\s*[:=]\\s*)(basic\\s+[A-Za-z0-9+/=._-]+)", "$1[REDACTED]")
            .replaceAll("(?i)(password\\s*[:=]\\s*)([^,\\s]+)", "$1[REDACTED]")
            .replaceAll("(?i)(username\\s*[:=]\\s*)([^,\\s]+)", "$1[REDACTED]");
    }
    
    public void logRequest(String method, String params) {
        String truncatedParams = params.length() > 60 ? params.substring(0, 77) + "..." : params;
        logMessage("REQ: " + method + " " + truncatedParams.replace("\n", "\\n"));
    }
    
    public void logResponse(String method, String response) {
        String truncatedResponse = response.length() > 60 ? response.substring(0, 77) + "..." : response;
        logMessage("RES: " + method + " " + truncatedResponse.replace("\n", "\\n"));
    }
    
    public void logSession(String event) {
        logMessage("SESSION: " + event);
    }
    
    private void clearLog() {
        logTextArea.setText("");
    }
    
    // Add the required getComponent method
    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }
    
    private class SaveConfigurationListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            saveSettings();
            logMessage("Configuration saved");
        }
    }
    
    // Getters for current configuration
    public String getHost() {
        return hostField.getText();
    }
    
    public int getPort() {
        return (Integer) portSpinner.getValue();
    }
    
    public boolean isServerEnabled() {
        return enabledCheckBox.isSelected();
    }
    
    public boolean isAsyncEnabled() {
        return asyncEnabledCheckBox.isSelected();
    }

    public boolean isAllowDestructiveToolsEnabled() {
        return allowDestructiveToolsCheckBox.isSelected();
    }
    
    public AuthConfig.AuthMode getAuthMode() {
        return (AuthConfig.AuthMode) authModeComboBox.getSelectedItem();
    }

    public String getAuthUsername() {
        return authUsernameField.getText();
    }

    public String getAuthPassword() {
        return new String(authPasswordField.getPassword());
    }

    public Map<String, Boolean> getToolEnabledStates() {
        return new HashMap<>(toolEnabledStates);
    }
    
    /**
     * Public method to refresh tools list - can be called when backend becomes available
     */
    public void onBackendReady() {
        // Load settings now that backend is ready
        loadSettings();
        refreshToolsList();
        logMessage("Backend ready - settings loaded and tools list refreshed");
    }
    
    // McpEventListener implementation
    @Override
    public void onToolRequest(String toolName, String parameters) {
        logRequest(toolName, parameters);
    }
    
    @Override
    public void onToolResponse(String toolName, String response) {
        logResponse(toolName, response);
    }
    
    @Override
    public void onSessionEvent(String event) {
        logSession(event);
    }
    
    @Override
    public void onLogMessage(String message) {
        logMessage(message);
    }
}
