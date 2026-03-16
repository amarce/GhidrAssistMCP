/*
 *
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

/**
 * GhidrAssistMCP Plugin - Provides an MCP (Model Context Protocol) server for Ghidra analysis capabilities.
 *
 * Extends Plugin (not ProgramPlugin) so the MCP server starts as soon as the tool opens,
 * before any program/file is loaded. Program events are tracked manually via processEvent().
 */
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "MCP Server for Ghidra",
	description = "Provides a configurable MCP (Model Context Protocol) server for Ghidra analysis capabilities with tool management and logging.",
	eventsConsumed = {
		ProgramActivatedPluginEvent.class,
		ProgramOpenedPluginEvent.class,
		ProgramClosedPluginEvent.class,
		ProgramLocationPluginEvent.class
	}
)
public class GhidrAssistMCPPlugin extends Plugin {

	private GhidrAssistMCPProvider provider;
	private GhidrAssistMCPManager manager;
	private boolean isServerOwner = false;

	// Manual program tracking (replaces ProgramPlugin's built-in tracking)
	private volatile Program currentProgram;
	private volatile ProgramLocation currentLocation1;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidrAssistMCPPlugin(PluginTool tool) {
		super(tool);

		// Create the UI provider but don't register it yet
		provider = new GhidrAssistMCPProvider(tool, this);
	}

	@Override
	public void init() {
		super.init();

		// Get the singleton manager
		manager = GhidrAssistMCPManager.getInstance();

		// Register the UI provider with the tool first
		if (provider != null) {
			try {
				tool.addComponentProvider(provider, true);
				Msg.info(this, "Successfully registered UI provider");
			} catch (IllegalArgumentException e) {
				if (e.getMessage() != null && e.getMessage().contains("was already added")) {
					Msg.info(this, "UI provider already registered, continuing");
				} else {
					Msg.error(this, "Failed to register UI provider (non-fatal): " + e.getMessage());
				}
			} catch (Exception e) {
				Msg.error(this, "Failed to register UI provider (non-fatal): " + e.getMessage());
			}
		}

		// Register this tool with the singleton manager
		// The first tool to register becomes the server owner and gets its provider used
		// Server starts HERE - immediately when the tool opens, before any program is loaded
		isServerOwner = manager.registerTool(tool, provider);

		if (isServerOwner) {
			Msg.info(this, "This plugin instance is the MCP server owner");
		} else {
			Msg.info(this, "This plugin instance registered with existing MCP server");
		}

		if (provider != null) {
			provider.logSession("Plugin initialized" + (isServerOwner ? " (server owner)" : ""));
		}
	}

	/**
	 * Process plugin events for program lifecycle and location tracking.
	 * This replaces ProgramPlugin's automatic event handling.
	 */
	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			Program program = ((ProgramActivatedPluginEvent) event).getActiveProgram();
			programActivated(program);
		} else if (event instanceof ProgramOpenedPluginEvent) {
			Program program = ((ProgramOpenedPluginEvent) event).getProgram();
			if (provider != null && program != null) {
				provider.logSession("Program opened: " + program.getName());
			}
		} else if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			programDeactivated(program);
		} else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocation loc = ((ProgramLocationPluginEvent) event).getLocation();
			locationChanged(loc);
		}
	}

	private void programActivated(Program program) {
		this.currentProgram = program;

		// Notify manager that this tool is now active (focus tracking)
		if (manager != null) {
			manager.setActiveTool(tool);
			manager.setActivePlugin(this);
		}

		GhidrAssistMCPBackend backend = getBackend();
		if (backend != null) {
			backend.onProgramActivated(program);
		}
		if (provider != null && program != null) {
			provider.logSession("Program activated: " + program.getName());
		}
	}

	private void locationChanged(ProgramLocation loc) {
		this.currentLocation1 = loc;

		// Set this as the active plugin for UI context access
		if (manager != null) {
			manager.setActivePlugin(this);
		}

		if (provider != null && loc != null) {
			provider.logMessage("Location changed to: " + loc.getAddress());
		}
	}

	private void programDeactivated(Program program) {
		if (program != null && program.equals(this.currentProgram)) {
			this.currentProgram = null;
		}
		GhidrAssistMCPBackend backend = getBackend();
		if (backend != null) {
			backend.onProgramDeactivated(program);
		}
		if (provider != null) {
			provider.logSession("Program closed: " + (program != null ? program.getName() : "null"));
		}
	}

	/**
	 * Apply new configuration from the UI.
	 * Delegates to the singleton manager which handles server restart if needed.
	 */
	public void applyConfiguration(String host, int port, boolean enabled, boolean asyncEnabled,
			boolean allowDestructiveTools, AuthConfig.AuthMode authMode, String authUsername,
			String authPassword, String oauthIssuer, String oauthJwksUrl, String oauthAudience,
			String oauthRequiredScope, String oauthPublicBaseUrl, boolean oauthTrustForwardedHeaders,
			String oauthCallbackId, Map<String, Boolean> toolStates) {
		if (manager != null) {
			manager.applyConfiguration(host, port, enabled, asyncEnabled, allowDestructiveTools,
				authMode, authUsername, authPassword, oauthIssuer, oauthJwksUrl, oauthAudience,
				oauthRequiredScope, oauthPublicBaseUrl, oauthTrustForwardedHeaders, oauthCallbackId,
				toolStates);
		}
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			provider.logSession("Plugin disposing");

			try {
				tool.removeComponentProvider(provider);
			} catch (Exception e) {
				Msg.error(this, "Error removing UI provider", e);
			}
			provider = null;
		}

		// Unregister this tool from the singleton manager
		// The manager will stop the server when all tools are unregistered
		if (manager != null) {
			manager.unregisterTool(tool);
		}

		super.dispose();
	}

	/**
	 * Get the MCP backend for tool management.
	 * Returns the shared backend from the singleton manager.
	 */
	public GhidrAssistMCPBackend getBackend() {
		return manager != null ? manager.getBackend() : null;
	}

	/**
	 * Get the singleton manager.
	 */
	public GhidrAssistMCPManager getManager() {
		return manager;
	}

	/**
	 * Get the current server configuration.
	 * Returns configuration from the singleton manager.
	 */
	public String getCurrentHost() {
		return manager != null ? manager.getCurrentHost() : "localhost";
	}

	public int getCurrentPort() {
		return manager != null ? manager.getCurrentPort() : 8080;
	}

	public boolean isServerEnabled() {
		return manager != null ? manager.isServerEnabled() : false;
	}

	/**
	 * Get the current program using ProgramManager service for accurate tracking.
	 * This method properly handles multi-program scenarios.
	 */
	public Program getCurrentProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			Program current = pm.getCurrentProgram();
			if (current != null) {
				return current;
			}
		}
		// Fall back to tracked program
		return currentProgram;
	}

	/**
	 * Get all open programs in the current tool.
	 * This allows tools to list and select from multiple open programs.
	 */
	public List<Program> getAllOpenPrograms() {
		List<Program> programs = new ArrayList<>();
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			Program[] openPrograms = pm.getAllOpenPrograms();
			if (openPrograms != null) {
				for (Program p : openPrograms) {
					programs.add(p);
				}
			}
		}
		return programs;
	}

	/**
	 * Find an open program by name.
	 * Supports partial matching if exact match not found.
	 *
	 * @param programName The name of the program to find
	 * @return The matching program, or null if not found
	 */
	public Program getProgramByName(String programName) {
		if (programName == null || programName.trim().isEmpty()) {
			return getCurrentProgram();
		}

		List<Program> programs = getAllOpenPrograms();

		// First try exact match
		for (Program p : programs) {
			if (p.getName().equals(programName)) {
				return p;
			}
		}

		// Try case-insensitive match
		for (Program p : programs) {
			if (p.getName().equalsIgnoreCase(programName)) {
				return p;
			}
		}

		// Try partial match (contains)
		for (Program p : programs) {
			if (p.getName().toLowerCase().contains(programName.toLowerCase())) {
				return p;
			}
		}

		return null;
	}

	/**
	 * Get the current UI address from the location tracker.
	 */
	public Address getCurrentAddress() {
		if (currentLocation1 != null) {
			return currentLocation1.getAddress();
		}
		return null;
	}

	/**
	 * Get the current function containing the UI cursor.
	 */
	public Function getCurrentFunction() {
		Program program = getCurrentProgram();
		Address address = getCurrentAddress();

		if (program != null && address != null) {
			FunctionManager functionManager = program.getFunctionManager();
			return functionManager.getFunctionContaining(address);
		}
		return null;
	}
}
