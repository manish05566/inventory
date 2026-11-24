// Granular permissions. Every API request is mapped to one permission string; users get permissions
// from their role (defaults below) or, when assigned, from a permission group that replaces the defaults.

export const PERM_CATALOG = [
  { module: 'dashboard', label: 'Dashboard & search', perms: ['view'] },
  { module: 'assets', label: 'Assets', perms: ['view', 'edit', 'delete', 'checkout', 'audit'] },
  { module: 'stock', label: 'Accessories & consumables', perms: ['view', 'edit', 'checkout'] },
  { module: 'software', label: 'Software catalog', perms: ['view', 'edit'] },
  { module: 'licenses', label: 'Licenses', perms: ['view', 'edit'] },
  { module: 'contracts', label: 'Contracts', perms: ['view', 'edit'] },
  { module: 'catalog', label: 'Catalog (models, categories, manufacturers, suppliers, companies)', perms: ['view', 'edit'] },
  { module: 'people', label: 'People', perms: ['view', 'edit'] },
  { module: 'locations', label: 'Locations & departments', perms: ['view', 'edit'] },
  { module: 'alerts', label: 'Alerts', perms: ['view', 'edit'] },
  { module: 'discovery', label: 'Network discovery', perms: ['view', 'edit'] },
  { module: 'agents', label: 'Agents & deployment', perms: ['view', 'edit'] },
  { module: 'reports', label: 'Reports', perms: ['view'] },
  { module: 'import', label: 'Bulk import', perms: ['run'] },
  { module: 'monitoring', label: 'Activity & screenshots', perms: ['view'] },
  { module: 'admin', label: 'Administration (users, settings, security)', perms: ['all'] },
];
export const ALL_PERMS = PERM_CATALOG.flatMap((m) => m.perms.map((p) => `${m.module}.${p}`));

export function roleDefaults(role) {
  if (role === 'admin') return ALL_PERMS;
  if (role === 'tech') return ALL_PERMS.filter((p) => p !== 'admin.all');
  if (role === 'viewer') return ALL_PERMS.filter((p) => p.endsWith('.view') && p !== 'monitoring.view');
  return []; // 'user' = self-service only
}

export function effectivePerms(db, user) {
  if (!user) return [];
  if (user.role === 'admin') return ALL_PERMS; // admins can never be locked out by a group
  if (user.group_id) {
    const g = db.get('SELECT perms FROM perm_groups WHERE id=?', user.group_id);
    if (g) { try { return JSON.parse(g.perms).filter((p) => ALL_PERMS.includes(p) && p !== 'admin.all'); } catch { return []; } }
  }
  return roleDefaults(user.role);
}

const MODULE_OF = {
  assets: 'assets', checkouts: 'assets', relations: 'assets', stock: 'stock', software: 'software', licenses: 'licenses',
  contracts: 'contracts', people: 'people', locations: 'locations', departments: 'locations', map: 'locations', alerts: 'alerts',
  discovery: 'discovery', agents: 'agents', 'agent-info': 'agents', reports: 'reports', dashboard: 'dashboard', search: 'dashboard',
  meta: 'dashboard', monitoring: 'monitoring', screenshots: 'monitoring', import: 'import',
  companies: 'catalog', manufacturers: 'catalog', suppliers: 'catalog', categories: 'catalog', models: 'catalog',
  settings: 'admin', users: 'admin', groups: 'admin', audit: 'admin', security: 'admin', tokens: 'admin', admin: 'admin', 'custom-fields': 'admin',
};

/** Permission required for a route, or null when any signed-in user may call it (self-service). */
export function requiredPerm(method, pathname, metaRole) {
  if (metaRole === 'user') return null;
  const seg = pathname.split('/');            // ['', 'api', '<module>', ...]
  const top = seg[2] || '';
  if (top === 'me' || top === 'logout' || top === 'self') return null;
  if (top === 'custom-fields' && method === 'GET') return 'assets.view'; // field definitions are not sensitive
  const mod = MODULE_OF[top] || 'admin';
  let perm;
  if (mod === 'admin') perm = 'admin.all';
  else if (mod === 'monitoring') perm = 'monitoring.view';
  else if (mod === 'import') perm = 'import.run';
  else if (mod === 'assets' && /\/(activity|screenshot)$/.test(pathname)) perm = 'monitoring.view';
  else if (mod === 'assets' && (/[/-](checkout|checkin)$/.test(pathname) || top === 'checkouts') && method !== 'GET') perm = 'assets.checkout';
  else if (mod === 'assets' && /[/-]audit$/.test(pathname) && method !== 'GET') perm = 'assets.audit';
  else if (mod === 'stock' && /\/(checkout|checkin|consume)$/.test(pathname)) perm = 'stock.checkout';
  else if (mod === 'assets' && method === 'DELETE' && seg.length === 4) perm = 'assets.delete';
  else if (mod === 'reports' || mod === 'dashboard') perm = `${mod}.view`;
  else perm = method === 'GET' ? `${mod}.view` : `${mod}.edit`;
  // Safety net: routes declared admin-only always need admin; tech-only GETs need edit rights.
  if (metaRole === 'admin') return 'admin.all';
  const pm = perm.split('.')[0];
  if (metaRole === 'tech' && perm.endsWith('.view') && !['monitoring', 'reports', 'dashboard'].includes(pm)) return perm.replace(/\.view$/, '.edit');
  return perm;
}
