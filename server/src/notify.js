// Outbound alert notifications: Microsoft Teams, Slack or a generic signed JSON webhook.
import crypto from 'node:crypto';

const SEV_COLOR = { critical: 'C62828', warning: 'B45309', info: '1D4ED8' };

function body(kind, alerts, portal) {
  const lines = alerts.map((a) => `• [${a.severity.toUpperCase()}] ${a.message}`).join('\n');
  const title = `${alerts.length} new alert${alerts.length > 1 ? 's' : ''} in Asset Portal`;
  if (kind === 'teams') {
    return {
      type: 'message',
      attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: {
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4',
        body: [{ type: 'TextBlock', text: title, weight: 'Bolder', size: 'Medium' },
          ...alerts.slice(0, 20).map((a) => ({ type: 'TextBlock', wrap: true, text: `**${a.severity.toUpperCase()}** — ${a.message}`,
            color: a.severity === 'critical' ? 'Attention' : a.severity === 'warning' ? 'Warning' : 'Default' }))],
        actions: portal ? [{ type: 'Action.OpenUrl', title: 'Open alerts', url: `${portal}/#/alerts` }] : [],
      } }],
    };
  }
  if (kind === 'slack') {
    return { text: title, blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `*${title}*\n${lines}` } },
      ...(portal ? [{ type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Open alerts' }, url: `${portal}/#/alerts` }] }] : [])] };
  }
  return { event: 'alerts.created', sent_at: new Date().toISOString(), portal,
    alerts: alerts.map((a) => ({ id: a.id, kind: a.kind, severity: a.severity, message: a.message, asset_id: a.asset_id, color: SEV_COLOR[a.severity] })) };
}

export async function sendWebhook(db, vault, alerts) {
  const url = vault.decrypt(db.setting('webhook_url_enc', '')) || '';
  if (!url || !alerts.length) return { sent: false };
  const min = db.setting('webhook_min_severity', 'warning');
  const rank = { info: 0, warning: 1, critical: 2 };
  const list = alerts.filter((a) => rank[a.severity] >= rank[min]);
  if (!list.length) return { sent: false };
  const kind = db.setting('webhook_kind', 'generic');
  const payload = JSON.stringify(body(kind, list, db.setting('public_url', '')));
  const headers = { 'Content-Type': 'application/json', 'User-Agent': 'AssetPortal-Webhook/1' };
  const secret = vault.decrypt(db.setting('webhook_secret_enc', '')) || '';
  if (kind === 'generic' && secret) {
    const ts = Math.floor(Date.now() / 1000);
    headers['X-AssetPortal-Timestamp'] = String(ts);
    headers['X-AssetPortal-Signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(`${ts}.${payload}`).digest('hex');
  }
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 10000);
  try {
    const r = await fetch(url, { method: 'POST', headers, body: payload, signal: ctl.signal, redirect: 'error' });
    db.setSetting('webhook_last', JSON.stringify({ at: new Date().toISOString(), status: r.status, count: list.length }));
    return { sent: r.ok, status: r.status };
  } catch (e) {
    db.setSetting('webhook_last', JSON.stringify({ at: new Date().toISOString(), error: e.message, count: list.length }));
    return { sent: false, error: e.message };
  } finally { clearTimeout(t); }
}
