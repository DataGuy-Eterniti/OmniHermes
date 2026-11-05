/**
 * Presence Gate — Desktop UI Plugin Extension
 *
 * Adds a real-time biometric security widget and presence indicator
 * to the Hermes Desktop status bar and command palette.
 * Strictly uses official Hermes Plugin SDK APIs.
 */

export default function activate(context) {
  // 1. Create Status Bar Widget
  const statusBarItem = context.ui.createStatusBarItem({
    id: 'presence-gate-indicator',
    alignment: 'right',
    priority: 100,
  });

  statusBarItem.text = '🛡️ Presence: Active';
  statusBarItem.tooltip = 'Presence Gate: Biometric Monitoring Active';
  statusBarItem.command = 'presence.showStatus';
  statusBarItem.show();

  // 2. Register Desktop Commands
  context.commands.registerCommand('presence.showStatus', async () => {
    try {
      const status = await context.agent.callTool('presence_status', {});
      const owner = status.owner_info?.owner_name || 'Not Enrolled';
      const presenceText = status.presence?.status === 'AWAY' ? '🔴 Away (Locked)' : '🟢 Present';
      const chainValid = status.audit_chain?.valid ? 'Verified (Tamper-Free)' : 'Invalid';

      context.ui.showInformationMessage(
        `Presence Gate Status\n` +
        `• Owner: ${owner}\n` +
        `• Status: ${status.status.toUpperCase()}\n` +
        `• Presence: ${presenceText}\n` +
        `• Audit Chain: ${chainValid}`
      );
    } catch (err) {
      context.ui.showErrorMessage(`Failed to query Presence Gate: ${err.message}`);
    }
  });

  context.commands.registerCommand('presence.viewAuditLogs', async () => {
    try {
      const logs = await context.agent.callTool('presence_audit_logs', { limit: 15, verify_chain: true });
      context.ui.showOutputChannel('Presence Gate Audit Log', JSON.stringify(logs, null, 2));
    } catch (err) {
      context.ui.showErrorMessage(`Failed to fetch audit log: ${err.message}`);
    }
  });

  // 3. Periodic presence ping
  const interval = setInterval(async () => {
    try {
      const status = await context.agent.callTool('presence_status', {});
      if (status.presence?.status === 'AWAY') {
        statusBarItem.text = '🔒 Presence: Away (Locked)';
        statusBarItem.color = '#F43F5E';
      } else {
        statusBarItem.text = '🛡️ Presence: Protected';
        statusBarItem.color = '#10B981';
      }
    } catch (_) {
      // Ignore background query errors
    }
  }, 10000);

  context.subscriptions.push({
    dispose: () => clearInterval(interval),
  });
}
