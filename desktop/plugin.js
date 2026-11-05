/**
 * Omnihermes — Desktop UI Plugin Extension
 *
 * Adds a real-time biometric security widget and presence indicator
 * to the Hermes Desktop status bar and command palette.
 */

export default function activate(context) {
  // 1. Create Status Bar Widget
  const statusBarItem = context.ui.createStatusBarItem({
    id: 'omnihermes-presence-indicator',
    alignment: 'right',
    priority: 100,
  });

  statusBarItem.text = '🛡️ Omnihermes: Active';
  statusBarItem.tooltip = 'Omnihermes Biometric Presence Gate: Monitoring';
  statusBarItem.command = 'omnihermes.showStatus';
  statusBarItem.show();

  // 2. Register Desktop Commands
  context.commands.registerCommand('omnihermes.showStatus', async () => {
    try {
      const status = await context.agent.callTool('omnihermes_status', {});
      const presenceText = status.presence?.status === 'AWAY' ? '🔴 Away (Locked)' : '🟢 Present';
      context.ui.showInformationMessage(
        `Omnihermes Security Gate\n` +
        `• Owner: ${status.owner_name || 'Not Enrolled'}\n` +
        `• Status: ${status.status.toUpperCase()}\n` +
        `• Presence: ${presenceText}\n` +
        `• Audit Chain: ${status.audit_chain?.valid ? 'Verified (Tamper-Free)' : 'Invalid'}`
      );
    } catch (err) {
      context.ui.showErrorMessage(`Failed to query Omnihermes: ${err.message}`);
    }
  });

  context.commands.registerCommand('omnihermes.viewAuditLogs', async () => {
    try {
      const logs = await context.agent.callTool('omnihermes_audit_logs', { limit: 15, verify_chain: true });
      context.ui.showOutputChannel('Omnihermes Audit Log', JSON.stringify(logs, null, 2));
    } catch (err) {
      context.ui.showErrorMessage(`Failed to fetch audit log: ${err.message}`);
    }
  });

  // 3. Periodic presence ping
  const interval = setInterval(async () => {
    try {
      const status = await context.agent.callTool('omnihermes_status', {});
      if (status.presence?.status === 'AWAY') {
        statusBarItem.text = '🔒 Omnihermes: Away (Locked)';
        statusBarItem.color = '#F43F5E';
      } else {
        statusBarItem.text = '🛡️ Omnihermes: Protected';
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
