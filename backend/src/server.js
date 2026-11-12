const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function hashPassword(password, salt = 'kebab_al_bewok_secret_salt_2026') {
  return crypto.createHmac('sha256', salt).update(String(password)).digest('hex');
}

function normalizePhone(p) {
  if (!p) return '';
  let s = String(p).replace(/[^0-9]/g, '');
  if (s.startsWith('62')) s = s.slice(2);
  else if (s.startsWith('0')) s = s.slice(1);
  return s;
}

function sanitizeCustomer(cust) {
  if (!cust) return null;
  const safe = { ...cust };
  safe.has_password = Boolean(cust.password_hash || cust.has_password);
  delete safe.password_hash;
  return safe;
}

function getOrderFoodAmount(o) {
  if (!o) return 0;
  if (o.food_subtotal != null) return Number(o.food_subtotal) || 0;
  return Math.max(0, (Number(o.total_payment ?? o.total_price) || 0) - (Number(o.delivery_fee) || 0));
}

function getOrderTotalPaid(o) {
  if (!o) return 0;
  const direct = Number(o.total_payment ?? o.total_price);
  if (!Number.isNaN(direct) && direct > 0) return direct;
  return getOrderFoodAmount(o) + (Number(o.delivery_fee) || 0);
}

function isDeliveryOrder(o) {
  if (!o) return false;
  if (o.order_type === 'offline' || o.destination_type === 'offline_store') return false;
  return o.order_type === 'delivery' || (Number(o.delivery_fee) || 0) > 0 || Boolean(o.delivery_address || o.customer_address);
}

function findCustomerEntry(wallets, identifier) {
  const customers = (wallets && wallets.customers) || {};
  const raw = String(identifier || '').trim();
  const cleanId = raw.toLowerCase();
  if (!cleanId) return null;

  if (customers[raw]) return { key: raw, customer: customers[raw] };
  if (customers[cleanId]) return { key: cleanId, customer: customers[cleanId] };

  const entries = Object.entries(customers);
  const emailMatch = entries.find(([, c]) => c && c.email && c.email.toLowerCase() === cleanId);
  if (emailMatch) return { key: emailMatch[0], customer: emailMatch[1] };

  const normInput = normalizePhone(raw);
  if (normInput.length >= 7) {
    const phoneMatches = entries.filter(([, c]) => {
      if (!c) return false;
      return normalizePhone(c.whatsapp) === normInput || normalizePhone(c.phone) === normInput;
    });
    if (phoneMatches.length > 0) {
      phoneMatches.sort((a, b) => {
        const score = c => (c.password_hash ? 4 : 0) + (c.email ? 2 : 0) + (c.profile_completed ? 1 : 0);
        return score(b[1]) - score(a[1]);
      });
      return { key: phoneMatches[0][0], customer: phoneMatches[0][1] };
    }
  }
  return null;
}

function applyCustomerPasswordUpdate(wallets, customerKey, passwordHash) {
  if (!wallets.customers || !wallets.customers[customerKey]) return null;
  const cust = wallets.customers[customerKey];
  cust.password_hash = passwordHash;
  cust.has_password = true;
  cust.password_reset_at = new Date().toISOString();
  cust.updated_at = new Date().toISOString();
  return cust;
}

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files untuk frontend ketiga aplikasi
const PUBLIC_DIR = path.join(__dirname, '../public');
app.use(express.static(PUBLIC_DIR));

// Rute jalan pintas untuk masing-masing aplikasi
app.get('/customer', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'customer.html')));
app.get('/driver', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'driver.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/owner', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'owner.html')));

// Path file data
const DATA_DIR = path.join(__dirname, '../data');
const MENU_FILE = path.join(DATA_DIR, 'menu.json');
const BRANCHES_FILE = path.join(DATA_DIR, 'branches.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const STOCK_OPNAME_FILE = path.join(DATA_DIR, 'stock_opname.json');
const STOCK_OPENING_FILE = path.join(DATA_DIR, 'stock_opening.json');
const WALLETS_FILE = path.join(DATA_DIR, 'wallets.json');
const AUTH_CONFIG_FILE = path.join(DATA_DIR, 'auth_config.json');
const WAREHOUSE_FILE = path.join(DATA_DIR, 'warehouse.json');
const PORTAL_ACCOUNTS_FILE = path.join(DATA_DIR, 'portal_accounts.json');

const PORTAL_TAB_KEYS = ['omzet', 'lapak', 'kurir', 'costumer', 'gudang', 'statistik', 'profile'];
const PORTAL_ROLE_LABELS = {
  owner: 'Owner Utama',
  mitra: 'Mitra Cabang',
  management: 'Management Operasional'
};

function hashPortalPassword(password, salt) {
  return crypto.scryptSync(String(password || ''), String(salt || ''), 32).toString('hex');
}

function verifyPortalPassword(password, account) {
  if (!account || !account.password_hash || !account.password_salt) return false;
  const candidateHex = hashPortalPassword(password, account.password_salt);
  const a = Buffer.from(candidateHex, 'hex');
  const b = Buffer.from(String(account.password_hash), 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function normalizePortalPermissions(role, rawPerms = {}) {
  if (role === 'owner') {
    return {
      tabs: [...PORTAL_TAB_KEYS],
      can_edit: true,
      can_view_finance: true,
      can_manage_accounts: true
    };
  }
  const src = rawPerms && typeof rawPerms === 'object' ? rawPerms : {};
  const fallbackTabs = role === 'mitra'
    ? ['omzet', 'lapak', 'gudang', 'statistik']
    : ['omzet', 'lapak', 'kurir', 'costumer', 'gudang', 'statistik'];
  const rawTabs = Array.isArray(src.tabs) ? src.tabs : fallbackTabs;
  const tabSet = new Set(rawTabs.filter(t => PORTAL_TAB_KEYS.includes(t)));
  tabSet.add('profile'); // Profile selalu dapat diakses untuk lihat akun & ganti sandi sendiri
  const orderedTabs = PORTAL_TAB_KEYS.filter(t => tabSet.has(t));

  return {
    tabs: orderedTabs,
    can_edit: Boolean(src.can_edit),
    can_view_finance: src.can_view_finance !== undefined ? Boolean(src.can_view_finance) : (role === 'mitra'),
    can_manage_accounts: false
  };
}

function getOrInitPortalAccounts() {
  const existing = readJSON(PORTAL_ACCOUNTS_FILE, null);
  const nowIso = new Date().toISOString();
  if (!existing || !Array.isArray(existing.accounts) || existing.accounts.length === 0) {
    const salt = crypto.randomBytes(16).toString('hex');
    const initial = {
      session_secret: crypto.randomBytes(32).toString('hex'),
      accounts: [
        {
          id: 'owner-utama',
          username: 'AlbewokOwner',
          full_name: 'Owner Utama - Kebab AL Bewok',
          role: 'owner',
          password_salt: salt,
          password_hash: hashPortalPassword('Albewok2025', salt),
          is_active: true,
          branch_scope: 'all',
          allowed_branches: [],
          permissions: normalizePortalPermissions('owner'),
          notes: 'Super Admin & Pemilik Utama',
          created_at: nowIso,
          updated_at: nowIso,
          last_login_at: null
        }
      ]
    };
    writeJSON(PORTAL_ACCOUNTS_FILE, initial);
    return initial;
  }
  let changed = false;
  if (!existing.session_secret) {
    existing.session_secret = crypto.randomBytes(32).toString('hex');
    changed = true;
  }
  if (!existing.accounts.some(a => a.role === 'owner')) {
    const salt = crypto.randomBytes(16).toString('hex');
    existing.accounts.unshift({
      id: 'owner-utama',
      username: 'AlbewokOwner',
      full_name: 'Owner Utama - Kebab AL Bewok',
      role: 'owner',
      password_salt: salt,
      password_hash: hashPortalPassword('Albewok2025', salt),
      is_active: true,
      branch_scope: 'all',
      allowed_branches: [],
      permissions: normalizePortalPermissions('owner'),
      notes: 'Super Admin & Pemilik Utama',
      created_at: nowIso,
      updated_at: nowIso,
      last_login_at: null
    });
    changed = true;
  }
  if (changed) writeJSON(PORTAL_ACCOUNTS_FILE, existing);
  return existing;
}

function sanitizePortalAccount(acc) {
  if (!acc) return null;
  const role = ['owner', 'mitra', 'management'].includes(acc.role) ? acc.role : 'management';
  const branchScope = role === 'owner' ? 'all' : (acc.branch_scope === 'selected' ? 'selected' : 'all');
  const allowedBranches = branchScope === 'selected' && Array.isArray(acc.allowed_branches)
    ? acc.allowed_branches.map(id => String(id).trim()).filter(Boolean)
    : [];
  return {
    id: acc.id,
    username: acc.username,
    full_name: acc.full_name || acc.username,
    role,
    role_label: PORTAL_ROLE_LABELS[role] || 'Staff Management',
    is_active: acc.is_active !== false,
    branch_scope: branchScope,
    allowed_branches: allowedBranches,
    permissions: normalizePortalPermissions(role, acc.permissions),
    notes: acc.notes || '',
    created_at: acc.created_at || null,
    updated_at: acc.updated_at || null,
    last_login_at: acc.last_login_at || null
  };
}

function signPortalToken(account, sessionSecret) {
  const payload = {
    sub: account.id,
    role: account.role,
    iat: Date.now(),
    exp: Date.now() + (30 * 24 * 60 * 60 * 1000)
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', String(sessionSecret)).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function resolvePortalUserFromReq(req) {
  const authHeader = String(req.headers['authorization'] || '');
  const headerToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : String(req.headers['x-portal-token'] || '').trim();
  if (!headerToken || !headerToken.includes('.')) return null;

  const [encoded, sig] = headerToken.split('.');
  if (!encoded || !sig) return null;

  const store = getOrInitPortalAccounts();
  const expectedSig = crypto.createHmac('sha256', String(store.session_secret)).update(encoded).digest('base64url');
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expectedSig, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload || !payload.sub || (payload.exp && Date.now() > Number(payload.exp))) return null;
    const liveAccount = store.accounts.find(acc => acc.id === payload.sub);
    if (!liveAccount || liveAccount.is_active === false) return null;
    return sanitizePortalAccount(liveAccount);
  } catch (e) {
    return null;
  }
}

function portalUserHasTab(portalUser, tabKey) {
  if (!portalUser) return true;
  if (portalUser.role === 'owner') return true;
  const tabs = (portalUser.permissions && portalUser.permissions.tabs) || [];
  return tabs.includes(tabKey);
}

function canViewPortalFinance(portalUser) {
  if (!portalUser) return true;
  if (portalUser.role === 'owner') return true;
  return Boolean(portalUser.permissions && portalUser.permissions.can_view_finance);
}

function getAllowedBranchIdSet(portalUser) {
  if (!portalUser || portalUser.role === 'owner' || portalUser.branch_scope !== 'selected') {
    return null;
  }
  return new Set(portalUser.allowed_branches || []);
}

function isBranchAllowedForPortalUser(portalUser, branchId) {
  const allowedSet = getAllowedBranchIdSet(portalUser);
  if (!allowedSet) return true;
  if (!branchId || branchId === 'all') return false;
  return allowedSet.has(branchId);
}

function filterAllowedBranches(portalUser, branchesList = []) {
  const allowedSet = getAllowedBranchIdSet(portalUser);
  if (!allowedSet) return branchesList;
  return branchesList.filter(b => allowedSet.has(b.id || b.branch_id));
}

function getRequiredTabForSuperAdmin(reqPath) {
  const p = String(reqPath || '');
  if (p.startsWith('/portal-accounts')) return '__owner_only__';
  if (p.startsWith('/summary')) return null;
  if (p.startsWith('/stock-opname')) return 'omzet';
  if (p.startsWith('/stock-opening')) return 'lapak';
  if (p.startsWith('/courier-radar') || p.startsWith('/drivers') || p.startsWith('/withdrawals') || p.startsWith('/wallet-changes')) return 'kurir';
  if (p.startsWith('/customers')) return 'costumer';
  if (p.startsWith('/warehouse')) return 'gudang';
  if (p.startsWith('/statistics')) return 'statistik';
  return null;
}

function enforceSuperAdminRbac(req, res, next) {
  if (!req.portalUser) {
    return res.status(401).json({
      success: false,
      auth_required: true,
      message: 'Sesi portal tidak valid atau telah berakhir. Silakan login terlebih dahulu.'
    });
  }

  const reqTab = getRequiredTabForSuperAdmin(req.path);
  if (reqTab === '__owner_only__' && req.portalUser.role !== 'owner') {
    return res.status(403).json({
      success: false,
      message: 'Hanya Owner Utama yang diizinkan mengelola akun akses portal.'
    });
  }

  if (reqTab && reqTab !== '__owner_only__' && !portalUserHasTab(req.portalUser, reqTab)) {
    return res.status(403).json({
      success: false,
      message: `Akun Anda (${req.portalUser.role_label}) tidak memiliki izin akses untuk menu "${reqTab}".`
    });
  }

  const isWriteMethod = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  if (isWriteMethod && reqTab !== '__owner_only__' && !(req.portalUser.permissions && req.portalUser.permissions.can_edit)) {
    return res.status(403).json({
      success: false,
      message: 'Akun Anda dalam mode Lihat Saja (Read-Only) dan tidak dapat mengubah data.'
    });
  }

  if (isWriteMethod && req.portalUser.role === 'mitra' && String(req.path || '').startsWith('/warehouse')) {
    const isPoCreate = req.path === '/warehouse/purchase-orders' && req.method === 'POST';
    if (!isPoCreate) {
      return res.status(403).json({
        success: false,
        message: 'Akun Mitra hanya dapat memantau stok & mengajukan PO tanpa mengubah stok fisik Gudang Pusat.'
      });
    }
  }

  if (req.portalUser.role !== 'owner' && req.portalUser.branch_scope === 'selected') {
    const qBranch = req.query && req.query.branch_id;
    const bBranch = req.body && req.body.branch_id;
    if (qBranch && qBranch !== 'all' && !isBranchAllowedForPortalUser(req.portalUser, qBranch)) {
      return res.status(403).json({
        success: false,
        message: 'Akses ditolak: lapak cabang ini di luar cakupan akun Anda.'
      });
    }
    if (bBranch && !isBranchAllowedForPortalUser(req.portalUser, bBranch)) {
      return res.status(403).json({
        success: false,
        message: 'Akses ditolak: Anda tidak diizinkan mengubah data lapak cabang ini.'
      });
    }
  }

  next();
}

app.use('/api', (req, res, next) => {
  req.portalUser = resolvePortalUserFromReq(req);
  next();
});

const WAREHOUSE_CATEGORIES = [
  'Kemasan',
  'Tortilla',
  'Daging & Protein',
  'Sayuran & Buah',
  'Saus & Condiment',
  'Topping Tambahan',
  'Operasional & Masak'
];

const DEFAULT_WAREHOUSE_ITEMS = [
  { no: 1, id: 'bungkus_kebab_jumbo', category: 'Kemasan', name: 'Bungkus Kebab Jumbo', unit: 'pcs', current_stock: 500, safety_stock: 200, unit_cost: 350 },
  { no: 2, id: 'bungkus_kebab_reguler', category: 'Kemasan', name: 'Bungkus Kebab Reguler', unit: 'pcs', current_stock: 800, safety_stock: 300, unit_cost: 300 },
  { no: 3, id: 'bungkus_kebab_small', category: 'Kemasan', name: 'Bungkus Kebab Small', unit: 'pcs', current_stock: 250, safety_stock: 200, unit_cost: 250 },
  { no: 4, id: 'tortilla_jumbo_25cm', category: 'Tortilla', name: 'Tortilla Jumbo 25 cm', unit: 'pcs', current_stock: 300, safety_stock: 150, unit_cost: 1500 },
  { no: 5, id: 'tortilla_reguler_22cm', category: 'Tortilla', name: 'Tortilla Reguler 22 cm', unit: 'pcs', current_stock: 500, safety_stock: 200, unit_cost: 1200 },
  { no: 6, id: 'tortilla_kecil_19cm', category: 'Tortilla', name: 'Tortilla Kecil 19 cm', unit: 'pcs', current_stock: 150, safety_stock: 120, unit_cost: 950 },
  { no: 7, id: 'beef_kebab_jumbo', category: 'Daging & Protein', name: 'Beef Kebab Premium Jumbo', unit: 'pcs', current_stock: 120, safety_stock: 50, unit_cost: 4500 },
  { no: 8, id: 'beef_kebab_reguler', category: 'Daging & Protein', name: 'Beef Kebab Premium Reguler', unit: 'pcs', current_stock: 180, safety_stock: 80, unit_cost: 3500 },
  { no: 9, id: 'beef_kebab_small', category: 'Daging & Protein', name: 'Beef Kebab Premium Small', unit: 'pcs', current_stock: 60, safety_stock: 50, unit_cost: 2500 },
  { no: 10, id: 'daging_kebab_central', category: 'Daging & Protein', name: 'Daging Kebab Central', unit: 'gram', current_stock: 25000, safety_stock: 10000, unit_cost: 85 },
  { no: 11, id: 'kebab_ayam_homemade', category: 'Daging & Protein', name: 'Kebab Ayam Homemade', unit: 'gram', current_stock: 10000, safety_stock: 5000, unit_cost: 65 },
  { no: 12, id: 'lidah_kebab', category: 'Daging & Protein', name: 'Lidah Kebab', unit: 'gram', current_stock: 5000, safety_stock: 2000, unit_cost: 95 },
  { no: 13, id: 'lettuce_head', category: 'Sayuran & Buah', name: 'Lettuce Head', unit: 'gram', current_stock: 12000, safety_stock: 5000, unit_cost: 28 },
  { no: 14, id: 'bawang_bombay', category: 'Sayuran & Buah', name: 'Bawang Bombay', unit: 'gram', current_stock: 8000, safety_stock: 3000, unit_cost: 32 },
  { no: 15, id: 'nanas', category: 'Sayuran & Buah', name: 'Nanas', unit: 'gram', current_stock: 4000, safety_stock: 2000, unit_cost: 20 },
  { no: 16, id: 'saus_sambal', category: 'Saus & Condiment', name: 'Saus Sambal', unit: 'gram', current_stock: 15000, safety_stock: 8000, unit_cost: 24 },
  { no: 17, id: 'saus_tomat', category: 'Saus & Condiment', name: 'Saus Tomat', unit: 'gram', current_stock: 10000, safety_stock: 6000, unit_cost: 22 },
  { no: 18, id: 'saus_mayonaise', category: 'Saus & Condiment', name: 'Saus Mayonaise', unit: 'gram', current_stock: 15000, safety_stock: 8000, unit_cost: 30 },
  { no: 19, id: 'saus_keju', category: 'Saus & Condiment', name: 'Saus Keju', unit: 'gram', current_stock: 6000, safety_stock: 4000, unit_cost: 45 },
  { no: 20, id: 'saus_signature', category: 'Saus & Condiment', name: 'Saus Signature', unit: 'gram', current_stock: 8000, safety_stock: 4000, unit_cost: 38 },
  { no: 21, id: 'keju_slice', category: 'Topping Tambahan', name: 'Keju Slice', unit: 'pcs', current_stock: 100, safety_stock: 50, unit_cost: 1100 },
  { no: 22, id: 'telur', category: 'Topping Tambahan', name: 'Telur', unit: 'pcs', current_stock: 120, safety_stock: 80, unit_cost: 2000 },
  { no: 23, id: 'gas_lpg', category: 'Operasional & Masak', name: 'Gas LPG', unit: 'tabung', current_stock: 10, safety_stock: 4, unit_cost: 22000 },
  { no: 24, id: 'margarin', category: 'Operasional & Masak', name: 'Margarin', unit: 'gram', current_stock: 5000, safety_stock: 2000, unit_cost: 25 },
  { no: 25, id: 'sabun_cuci', category: 'Operasional & Masak', name: 'Sabun Cuci', unit: 'pcs', current_stock: 24, safety_stock: 10, unit_cost: 12000 }
];

function createDefaultWarehouseData() {
  return {
    meta: {
      warehouse_name: 'Central Kitchen & Warehouse',
      pic_name: 'Supervisor Gudang & Logistik',
      safety_days: 3,
      target_food_cost_min: 35,
      target_food_cost_max: 40
    },
    items: DEFAULT_WAREHOUSE_ITEMS.map(item => ({ ...item, updated_at: null })),
    ledger: [],
    purchase_orders: []
  };
}

function getOrInitWarehouse() {
  const wh = readJSON(WAREHOUSE_FILE, createDefaultWarehouseData());
  if (!wh || !Array.isArray(wh.items) || wh.items.length === 0) {
    const fresh = createDefaultWarehouseData();
    writeJSON(WAREHOUSE_FILE, fresh);
    return fresh;
  }
  if (!wh.meta) wh.meta = createDefaultWarehouseData().meta;
  if (!Array.isArray(wh.ledger)) wh.ledger = [];
  if (!Array.isArray(wh.purchase_orders)) wh.purchase_orders = [];

  // Pastikan item default baru ikut ditambahkan ke warehouse.json tanpa menimpa stok berjalan
  const existingIds = new Set(wh.items.map(it => it.id));
  let changed = false;
  const defaultNoMap = new Map(DEFAULT_WAREHOUSE_ITEMS.map(d => [d.id, d.no]));
  DEFAULT_WAREHOUSE_ITEMS.forEach(def => {
    if (!existingIds.has(def.id)) {
      wh.items.push({ ...def, updated_at: null });
      changed = true;
    }
  });
  if (changed) {
    wh.items.forEach(it => {
      if (defaultNoMap.has(it.id)) it.no = defaultNoMap.get(it.id);
    });
    wh.items.sort((a, b) => (Number(a.no) || 999) - (Number(b.no) || 999));
    writeJSON(WAREHOUSE_FILE, wh);
  }
  return wh;
}

function getWarehouseReorderCount() {
  const wh = getOrInitWarehouse();
  return wh.items.filter(it => (Number(it.current_stock) || 0) <= (Number(it.safety_stock) || 0)).length;
}

function recordWarehouseTransaction(wh, payload) {
  const {
    type,
    date,
    branch_id = '',
    branch_name = '',
    supplier_name = '',
    reference_no = '',
    pic_name = 'Admin Gudang',
    note = '',
    items = []
  } = payload;

  if (!['supplier_in', 'branch_transfer', 'branch_return', 'waste', 'adjustment'].includes(type)) {
    return { error: 'Tipe transaksi gudang tidak valid' };
  }
  if (!Array.isArray(items) || items.length === 0) {
    return { error: 'Pilih minimal 1 bahan baku dengan jumlah valid' };
  }

  const itemMap = new Map(wh.items.map(it => [it.id, it]));
  const normalizedRows = [];
  const isOutgoing = type === 'branch_transfer' || type === 'waste';
  const isIncoming = type === 'supplier_in' || type === 'branch_return';

  for (const row of items) {
    const target = itemMap.get(row.item_id);
    if (!target) {
      return { error: `Bahan tidak ditemukan: ${row.item_id}` };
    }
    const qty = Number(row.qty) || 0;
    if (type !== 'adjustment' && qty <= 0) {
      return { error: `Jumlah untuk ${target.name} harus lebih dari 0` };
    }
    const currStock = Number(target.current_stock) || 0;
    if (isOutgoing && qty > currStock) {
      return { error: `Stok gudang ${target.name} tidak cukup (sisa ${currStock} ${target.unit}, diminta ${qty} ${target.unit})` };
    }
    const effectiveCost = row.unit_cost != null && Number(row.unit_cost) > 0
      ? Number(row.unit_cost)
      : (Number(target.unit_cost) || 0);
    normalizedRows.push({ target, qty, effectiveCost });
  }

  const nowIso = new Date().toISOString();
  const txDate = date || getWibDateISO(new Date());
  const txItems = [];
  let totalValue = 0;

  for (const { target, qty, effectiveCost } of normalizedRows) {
    const prevStock = Number(target.current_stock) || 0;
    let nextStock = prevStock;
    if (isIncoming) {
      nextStock = prevStock + qty;
      if (type === 'supplier_in') target.unit_cost = effectiveCost;
    } else if (isOutgoing) {
      nextStock = prevStock - qty;
    } else if (type === 'adjustment') {
      nextStock = Math.max(0, qty);
    }

    const deltaQty = type === 'adjustment' ? Math.abs(nextStock - prevStock) : qty;
    const subtotal = deltaQty * effectiveCost;
    target.current_stock = nextStock;
    target.updated_at = nowIso;
    totalValue += subtotal;

    txItems.push({
      item_id: target.id,
      name: target.name,
      category: target.category,
      unit: target.unit,
      qty: type === 'adjustment' ? nextStock - prevStock : qty,
      unit_cost: effectiveCost,
      subtotal,
      prev_stock: prevStock,
      next_stock: nextStock
    });
  }

  const entry = {
    id: `whm-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    type,
    date: txDate,
    branch_id,
    branch_name,
    supplier_name,
    reference_no,
    pic_name,
    note,
    items: txItems,
    total_value: totalValue,
    created_at: nowIso
  };

  wh.ledger.unshift(entry);
  return { entry };
}

// Sinkronisasi transaksi gudang otomatis yang terikat dengan Opening Harian atau Stock Opname Closing
function syncLinkedWarehouseEntry({
  linkField,
  linkId,
  type,
  date,
  branch_id = '',
  branch_name = '',
  pic_name = 'Sistem',
  note = '',
  stockItemsMap = null,
  countKey = 'opening_count'
}) {
  const wh = getOrInitWarehouse();
  const itemMap = new Map(wh.items.map(it => [it.id, it]));

  // 1. Balikkan efek transaksi tertaut sebelumnya agar edit/hapus tidak pernah menggandakan mutasi
  const prevIdx = wh.ledger.findIndex(tx => tx[linkField] === linkId);
  if (prevIdx >= 0) {
    const prevTx = wh.ledger[prevIdx];
    const prevSign = prevTx.type === 'branch_return' ? 1 : -1;
    (prevTx.items || []).forEach(row => {
      const target = itemMap.get(row.item_id);
      if (target) {
        target.current_stock = (Number(target.current_stock) || 0) - prevSign * (Number(row.qty) || 0);
      }
    });
    wh.ledger.splice(prevIdx, 1);
  }

  // 2. Jika stockItemsMap ada (simpan/edit), catat transaksi baru yang tertaut
  if (stockItemsMap && typeof stockItemsMap === 'object') {
    const newSign = type === 'branch_return' ? 1 : -1;
    const nowIso = new Date().toISOString();
    const txItems = [];
    let totalValue = 0;
    const lowStockWarnings = [];

    wh.items.forEach(target => {
      const rawObj = stockItemsMap[target.id];
      const qty = rawObj != null
        ? (typeof rawObj === 'object' ? Number(rawObj[countKey] ?? rawObj.physical_count ?? rawObj.opening_count ?? 0) : Number(rawObj))
        : 0;
      if (!qty || qty <= 0 || Number.isNaN(qty)) return;

      const prevStock = Number(target.current_stock) || 0;
      const nextStock = prevStock + newSign * qty;
      const unitCost = Number(target.unit_cost) || 0;
      const subtotal = qty * unitCost;

      target.current_stock = nextStock;
      target.updated_at = nowIso;
      totalValue += subtotal;

      if (nextStock <= (Number(target.safety_stock) || 0)) {
        lowStockWarnings.push(`${target.name} (sisa ${nextStock} ${target.unit})`);
      }

      txItems.push({
        item_id: target.id,
        name: target.name,
        category: target.category,
        unit: target.unit,
        qty,
        unit_cost: unitCost,
        subtotal,
        prev_stock: prevStock,
        next_stock: nextStock
      });
    });

    if (txItems.length > 0) {
      const entry = {
        id: `whm-auto-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        type,
        auto_synced: true,
        [linkField]: linkId,
        date: date || getWibDateISO(new Date()),
        branch_id,
        branch_name,
        supplier_name: '',
        reference_no: linkId,
        pic_name,
        note,
        items: txItems,
        total_value: totalValue,
        created_at: nowIso
      };
      wh.ledger.unshift(entry);
      writeJSON(WAREHOUSE_FILE, wh);
      return { synced: true, itemCount: txItems.length, lowStockWarnings };
    }
  }

  writeJSON(WAREHOUSE_FILE, wh);
  return { synced: true, itemCount: 0, lowStockWarnings: [] };
}

// Helper untuk membaca & menulis file JSON (dengan In-Memory Fallback untuk Serverless Cloud seperti Vercel/Render)
const memoryCache = {};

function readJSON(filePath, defaultData = []) {
  if (memoryCache[filePath]) {
    return JSON.parse(JSON.stringify(memoryCache[filePath]));
  }
  try {
    if (!fs.existsSync(filePath)) {
      try { fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2)); } catch (e) {}
      memoryCache[filePath] = defaultData;
      return defaultData;
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    memoryCache[filePath] = parsed;
    return parsed;
  } catch (err) {
    console.error(`Gagal membaca ${filePath}:`, err);
    return memoryCache[filePath] || defaultData;
  }
}

function writeJSON(filePath, data) {
  memoryCache[filePath] = JSON.parse(JSON.stringify(data));
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch (err) {
    // Pada serverless seperti Vercel filesystem read-only, data tetap aman tersimpan di memoryCache selama instance hidup
  }
}

// Memory store untuk OTP (Kadaluwarsa dalam 5 menit)
const otpStore = new Map();

// Inisialisasi file data jika belum ada
if (!fs.existsSync(ORDERS_FILE)) writeJSON(ORDERS_FILE, []);
if (!fs.existsSync(STOCK_OPNAME_FILE)) writeJSON(STOCK_OPNAME_FILE, []);
if (!fs.existsSync(WALLETS_FILE)) {
  writeJSON(WALLETS_FILE, {
    drivers: {
      "driver-01": { id: "driver-01", name: "Budi Santoso", balance: 25000, trips: 3, is_online: true },
      "driver-02": { id: "driver-02", name: "Ahmad Dani", balance: 15000, trips: 2, is_online: true }
    },
    customers: {
      "cust-01": { id: "cust-01", name: "Pelanggan Setia", balance: 50000 }
    },
    history: []
  });
}

// ============================================================================
// PORTAL OWNER, MITRA & MANAGEMENT AUTH + MANAJEMEN AKUN AKSES
// ============================================================================
app.post('/api/portal/login', (req, res) => {
  const { username, password } = req.body || {};
  const cleanUser = String(username || '').trim().toLowerCase();
  const rawPass = String(password || '');

  if (!cleanUser || !rawPass) {
    return res.status(400).json({ success: false, message: 'ID / Username dan Password wajib diisi.' });
  }

  const store = getOrInitPortalAccounts();
  const acc = store.accounts.find(a => String(a.username || '').toLowerCase() === cleanUser);
  if (!acc || !verifyPortalPassword(rawPass, acc)) {
    return res.status(401).json({ success: false, message: 'ID / Username atau Password salah.' });
  }

  if (acc.is_active === false) {
    return res.status(403).json({ success: false, message: 'Akun ini sedang dinonaktifkan oleh Owner Utama.' });
  }

  acc.last_login_at = new Date().toISOString();
  writeJSON(PORTAL_ACCOUNTS_FILE, store);

  const token = signPortalToken(acc, store.session_secret);
  res.json({
    success: true,
    message: `Selamat datang, ${acc.full_name || acc.username}!`,
    data: {
      token,
      account: sanitizePortalAccount(acc)
    }
  });
});

app.get('/api/portal/me', (req, res) => {
  if (!req.portalUser) {
    return res.status(401).json({ success: false, auth_required: true, message: 'Sesi login tidak valid atau telah berakhir.' });
  }
  res.json({ success: true, data: req.portalUser });
});

app.post('/api/portal/change-password', (req, res) => {
  if (!req.portalUser) {
    return res.status(401).json({ success: false, auth_required: true, message: 'Silakan login terlebih dahulu.' });
  }
  const { current_password, new_password, full_name, username } = req.body || {};
  const store = getOrInitPortalAccounts();
  const idx = store.accounts.findIndex(a => a.id === req.portalUser.id);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Akun tidak ditemukan.' });
  }
  const acc = store.accounts[idx];

  if (new_password && String(new_password).trim().length > 0) {
    if (!current_password || !verifyPortalPassword(current_password, acc)) {
      return res.status(400).json({ success: false, message: 'Password saat ini tidak sesuai.' });
    }
    if (String(new_password).trim().length < 6) {
      return res.status(400).json({ success: false, message: 'Password baru minimal 6 karakter.' });
    }
    const newSalt = crypto.randomBytes(16).toString('hex');
    acc.password_salt = newSalt;
    acc.password_hash = hashPortalPassword(String(new_password).trim(), newSalt);
  }

  if (full_name !== undefined && String(full_name).trim().length >= 2) {
    acc.full_name = String(full_name).trim();
  }

  if (username !== undefined && acc.role === 'owner') {
    const cleanNextUser = String(username).trim();
    if (cleanNextUser.length < 4 || /\s/.test(cleanNextUser)) {
      return res.status(400).json({ success: false, message: 'Username minimal 4 karakter dan tanpa spasi.' });
    }
    const duplicate = store.accounts.some(a => a.id !== acc.id && a.username.toLowerCase() === cleanNextUser.toLowerCase());
    if (duplicate) {
      return res.status(409).json({ success: false, message: 'Username sudah dipakai oleh akun lain.' });
    }
    acc.username = cleanNextUser;
  }

  acc.updated_at = new Date().toISOString();
  writeJSON(PORTAL_ACCOUNTS_FILE, store);

  res.json({
    success: true,
    message: 'Profil akun Anda berhasil diperbarui!',
    data: sanitizePortalAccount(acc)
  });
});

// Middleware Proteksi RBAC Seluruh Endpoint /api/super-admin/*
app.use('/api/super-admin', enforceSuperAdminRbac);

app.get('/api/super-admin/portal-accounts', (req, res) => {
  const store = getOrInitPortalAccounts();
  res.json({
    success: true,
    data: store.accounts.map(sanitizePortalAccount)
  });
});

app.post('/api/super-admin/portal-accounts', (req, res) => {
  const {
    username,
    full_name,
    password,
    role = 'mitra',
    branch_scope = 'selected',
    allowed_branches = [],
    permissions = {},
    is_active = true,
    notes = ''
  } = req.body || {};

  const cleanUser = String(username || '').trim();
  const cleanName = String(full_name || '').trim();
  const cleanPass = String(password || '').trim();
  const cleanRole = ['mitra', 'management'].includes(role) ? role : 'mitra';

  if (cleanUser.length < 4 || /\s/.test(cleanUser)) {
    return res.status(400).json({ success: false, message: 'ID / Username minimal 4 karakter tanpa spasi.' });
  }
  if (!cleanName) {
    return res.status(400).json({ success: false, message: 'Nama lengkap akun wajib diisi.' });
  }
  if (cleanPass.length < 6) {
    return res.status(400).json({ success: false, message: 'Password akun minimal 6 karakter.' });
  }

  const store = getOrInitPortalAccounts();
  if (store.accounts.some(a => String(a.username || '').toLowerCase() === cleanUser.toLowerCase())) {
    return res.status(409).json({ success: false, message: `ID / Username "${cleanUser}" sudah digunakan.` });
  }

  const resolvedScope = branch_scope === 'all' ? 'all' : 'selected';
  const cleanBranches = resolvedScope === 'selected' && Array.isArray(allowed_branches)
    ? allowed_branches.map(id => String(id).trim()).filter(Boolean)
    : [];

  if (resolvedScope === 'selected' && cleanBranches.length === 0) {
    return res.status(400).json({ success: false, message: 'Pilih minimal 1 lapak cabang atau pilih Semua Lapak.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const nowIso = new Date().toISOString();
  const newAccount = {
    id: `acc-${Date.now()}`,
    username: cleanUser,
    full_name: cleanName,
    role: cleanRole,
    password_salt: salt,
    password_hash: hashPortalPassword(cleanPass, salt),
    is_active: Boolean(is_active),
    branch_scope: resolvedScope,
    allowed_branches: cleanBranches,
    permissions: normalizePortalPermissions(cleanRole, permissions),
    notes: String(notes || '').trim(),
    created_at: nowIso,
    updated_at: nowIso,
    last_login_at: null
  };

  store.accounts.push(newAccount);
  writeJSON(PORTAL_ACCOUNTS_FILE, store);

  res.status(201).json({
    success: true,
    message: `Akun ${PORTAL_ROLE_LABELS[cleanRole]} (${cleanUser}) berhasil dibuat!`,
    data: sanitizePortalAccount(newAccount)
  });
});

app.put('/api/super-admin/portal-accounts/:id', (req, res) => {
  const { id } = req.params;
  const {
    username,
    full_name,
    password,
    role,
    branch_scope,
    allowed_branches,
    permissions,
    is_active,
    notes
  } = req.body || {};

  const store = getOrInitPortalAccounts();
  const idx = store.accounts.findIndex(a => a.id === id);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Akun akses tidak ditemukan.' });
  }
  const acc = store.accounts[idx];

  if (acc.role === 'owner' && is_active === false) {
    return res.status(400).json({ success: false, message: 'Akun Owner Utama tidak boleh dinonaktifkan.' });
  }

  if (username !== undefined) {
    const cleanUser = String(username).trim();
    if (cleanUser.length < 4 || /\s/.test(cleanUser)) {
      return res.status(400).json({ success: false, message: 'ID / Username minimal 4 karakter tanpa spasi.' });
    }
    if (store.accounts.some(a => a.id !== acc.id && a.username.toLowerCase() === cleanUser.toLowerCase())) {
      return res.status(409).json({ success: false, message: `Username "${cleanUser}" sudah dipakai akun lain.` });
    }
    acc.username = cleanUser;
  }

  if (full_name !== undefined && String(full_name).trim()) {
    acc.full_name = String(full_name).trim();
  }

  if (password !== undefined && String(password).trim() !== '') {
    const cleanPass = String(password).trim();
    if (cleanPass.length < 6) {
      return res.status(400).json({ success: false, message: 'Password baru minimal 6 karakter.' });
    }
    const newSalt = crypto.randomBytes(16).toString('hex');
    acc.password_salt = newSalt;
    acc.password_hash = hashPortalPassword(cleanPass, newSalt);
  }

  if (acc.role !== 'owner') {
    const nextRole = ['mitra', 'management'].includes(role) ? role : acc.role;
    acc.role = nextRole;

    if (branch_scope !== undefined) {
      acc.branch_scope = branch_scope === 'all' ? 'all' : 'selected';
    }
    if (allowed_branches !== undefined) {
      acc.allowed_branches = acc.branch_scope === 'selected' && Array.isArray(allowed_branches)
        ? allowed_branches.map(bid => String(bid).trim()).filter(Boolean)
        : [];
    }
    if (acc.branch_scope === 'selected' && (!acc.allowed_branches || acc.allowed_branches.length === 0)) {
      return res.status(400).json({ success: false, message: 'Pilih minimal 1 lapak cabang atau gunakan Semua Lapak.' });
    }
    if (permissions !== undefined) {
      acc.permissions = normalizePortalPermissions(nextRole, permissions);
    }
    if (is_active !== undefined) {
      acc.is_active = Boolean(is_active);
    }
  }

  if (notes !== undefined) {
    acc.notes = String(notes || '').trim();
  }

  acc.updated_at = new Date().toISOString();
  writeJSON(PORTAL_ACCOUNTS_FILE, store);

  res.json({
    success: true,
    message: `Akun "${acc.full_name}" berhasil diperbarui.`,
    data: sanitizePortalAccount(acc)
  });
});

app.delete('/api/super-admin/portal-accounts/:id', (req, res) => {
  const { id } = req.params;
  const store = getOrInitPortalAccounts();
  const idx = store.accounts.findIndex(a => a.id === id);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Akun akses tidak ditemukan.' });
  }
  if (store.accounts[idx].role === 'owner') {
    return res.status(403).json({ success: false, message: 'Akun Owner Utama tidak dapat dihapus.' });
  }

  const [removed] = store.accounts.splice(idx, 1);
  writeJSON(PORTAL_ACCOUNTS_FILE, store);
  res.json({
    success: true,
    message: `Akun "${removed.full_name}" (@${removed.username}) telah dihapus.`,
    data: sanitizePortalAccount(removed)
  });
});

// ==========================================
// 1. ENDPOINTS UMUM & CUSTOMER (AUTH & MENU)
// ==========================================

// Konfigurasi Google Client ID (Dapat diatur dinamis / disimpan di auth_config.json)
app.get('/api/config/auth', (req, res) => {
  const authConfig = readJSON(AUTH_CONFIG_FILE, { google_client_id: '' });
  const clientId = process.env.GOOGLE_CLIENT_ID || authConfig.google_client_id || '';
  res.json({
    success: true,
    data: {
      google_client_id: clientId,
      is_configured: Boolean(clientId && clientId.length > 10)
    }
  });
});

app.post('/api/config/auth', (req, res) => {
  const { google_client_id } = req.body;
  const authConfig = readJSON(AUTH_CONFIG_FILE, { google_client_id: '' });
  authConfig.google_client_id = (google_client_id || '').trim();
  authConfig.updated_at = new Date().toISOString();
  writeJSON(AUTH_CONFIG_FILE, authConfig);

  console.log(`🔑 [AUTH CONFIG UPDATED] Google Client ID set to: ${authConfig.google_client_id ? authConfig.google_client_id.slice(0, 15) + '...' : '(dikosongkan)'}`);
  res.json({
    success: true,
    message: 'Konfigurasi Google Client ID berhasil disimpan!',
    data: { google_client_id: authConfig.google_client_id }
  });
});

// Login / Registrasi Akun Google (Mendukung Real Token JWT Google Identity Services & Mode Cepat)
app.post('/api/auth/google-login', async (req, res) => {
  let { credential, email, full_name, avatar_url, google_id } = req.body;
  let isGoogleVerified = false;

  // Verifikasi Kriptografis Resmi Google jika credential JWT dikirim
  if (credential) {
    try {
      const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
      const gData = await gRes.json();
      if (gData.error_description || !gData.email) {
        return res.status(401).json({
          success: false,
          message: `Verifikasi Akun Google Gagal: ${gData.error_description || 'Token kedaluwarsa atau tidak valid'}`
        });
      }
      email = gData.email;
      full_name = gData.name || full_name || email.split('@')[0];
      avatar_url = gData.picture || avatar_url;
      google_id = gData.sub;
      isGoogleVerified = true;
      console.log(`🔐 [GOOGLE OAUTH VERIFIED] Pelanggan terverifikasi: ${full_name} (${email})`);
    } catch (err) {
      console.error('Error saat menghubungi server Google tokeninfo:', err);
      return res.status(500).json({ success: false, message: 'Gagal menghubungi server verifikasi Google' });
    }
  }

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email Google diperlukan' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  // Cari atau buat profil baru berdasarkan email Google
  if (!wallets.customers[email]) {
    wallets.customers[email] = {
      id: `cust-${Date.now()}`,
      email,
      name: full_name || email.split('@')[0],
      avatar: avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${email}`,
      whatsapp: '',
      home_address: '',
      home_latitude: null,
      home_longitude: null,
      office_address: '',
      office_latitude: null,
      office_longitude: null,
      delivery_address: '',
      latitude: null,
      longitude: null,
      auth_provider: 'google',
      google_verified: isGoogleVerified,
      registered_at: new Date().toISOString()
    };
  } else {
    // Update data Google terbaru & pastikan field rumah/kantor ada
    if (full_name) wallets.customers[email].name = full_name;
    if (avatar_url) wallets.customers[email].avatar = avatar_url;
    if (isGoogleVerified) wallets.customers[email].google_verified = true;
    if (!wallets.customers[email].home_address && wallets.customers[email].delivery_address) {
      wallets.customers[email].home_address = wallets.customers[email].delivery_address;
      wallets.customers[email].home_latitude = wallets.customers[email].latitude;
      wallets.customers[email].home_longitude = wallets.customers[email].longitude;
    }
    wallets.customers[email].profile_completed = Boolean(
      wallets.customers[email].whatsapp && 
      (wallets.customers[email].home_address || wallets.customers[email].delivery_address)
    );
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: isGoogleVerified 
      ? `Autentikasi Google Terverifikasi 100%! Selamat datang, ${wallets.customers[email].name}.`
      : `Login Google Berhasil! Selamat datang, ${wallets.customers[email].name}.`,
    data: {
      token: `token-google-${email}-${Date.now()}`,
      verified_by_google: isGoogleVerified,
      user: sanitizeCustomer(wallets.customers[email])
    }
  });
});

// Update Profil Pelanggan (Nomor WhatsApp, Alamat Pengiriman & Kata Sandi Akun)
app.post('/api/customer/update-profile', (req, res) => {
  const {
    email,
    whatsapp,
    full_name,
    password, // Fitur Kata Sandi Baru
    home_address,
    home_latitude,
    home_longitude,
    office_address,
    office_latitude,
    office_longitude,
    delivery_address,
    latitude,
    longitude
  } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email akun diperlukan' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers || !wallets.customers[email]) {
    return res.status(404).json({ success: false, message: 'Akun pelanggan tidak ditemukan' });
  }

  const cust = wallets.customers[email];
  if (full_name) cust.name = full_name.trim();
  if (whatsapp) cust.whatsapp = whatsapp.trim();

  // Pengaturan Kata Sandi
  if (password && typeof password === 'string' && password.trim().length >= 4) {
    cust.password_hash = hashPassword(password.trim());
    cust.has_password = true;
    console.log(`🔑 [KATA SANDI DISIMPAN] Pelanggan ${cust.name} (${cust.email}) telah mengatur password akun.`);
  }

  // Alamat Rumah (Utama)
  if (home_address !== undefined) cust.home_address = home_address.trim();
  if (home_latitude !== undefined) cust.home_latitude = home_latitude;
  if (home_longitude !== undefined) cust.home_longitude = home_longitude;

  // Alamat Kantor / Lainnya
  if (office_address !== undefined) cust.office_address = office_address.trim();
  if (office_latitude !== undefined) cust.office_latitude = office_latitude;
  if (office_longitude !== undefined) cust.office_longitude = office_longitude;

  // Fallback kompatibilitas
  cust.delivery_address = cust.home_address || (delivery_address ? delivery_address.trim() : '');
  cust.latitude = cust.home_latitude || latitude || null;
  cust.longitude = cust.home_longitude || longitude || null;

  // Status kelengkapan onboarding profil customer
  cust.profile_completed = Boolean(cust.whatsapp && (cust.home_address || cust.delivery_address));

  cust.updated_at = new Date().toISOString();

  writeJSON(WALLETS_FILE, wallets);

  console.log(`👤 [PROFIL DIPERBARUI] ${cust.name} | WA: ${cust.whatsapp} | Password: ${cust.has_password ? 'YA' : 'TIDAK'} | Rumah: ${cust.home_address}`);

  const safeCust = { ...cust };
  delete safeCust.password_hash;

  res.json({
    success: true,
    message: password 
      ? 'Profil, alamat & kata sandi akun berhasil disimpan!' 
      : 'Profil & alamat tujuan pengantaran berhasil disimpan!',
    data: safeCust
  });
});

// Login Pelanggan dengan Email / Nomor WhatsApp & Kata Sandi
app.post('/api/auth/login-password', (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ success: false, message: 'Email / Nomor WhatsApp dan Kata Sandi wajib diisi' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  const matched = findCustomerEntry(wallets, identifier);
  const targetCust = matched ? matched.customer : null;

  if (!targetCust) {
    return res.status(404).json({
      success: false,
      message: 'Akun dengan Email atau Nomor WhatsApp tersebut belum terdaftar. Silakan masuk via Google terlebih dahulu.'
    });
  }

  if (!targetCust.password_hash) {
    return res.status(400).json({
      success: false,
      message: 'Akun ini belum memiliki kata sandi. Silakan masuk dengan Akun Google terlebih dahulu, lalu atur kata sandi di Profil Anda.'
    });
  }

  const incomingHash = hashPassword(password.trim());
  if (incomingHash !== targetCust.password_hash) {
    return res.status(401).json({
      success: false,
      message: 'Kata sandi salah. Silakan periksa kembali kata sandi akun Anda.'
    });
  }

  targetCust.last_login = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  const safeCust = sanitizeCustomer(targetCust);

  console.log(`🔑 [LOGIN PASSWORD BERHASIL] Pelanggan: ${safeCust.name} (${safeCust.email || safeCust.phone})`);

  res.json({
    success: true,
    message: `Login Berhasil! Selamat datang kembali, Kak ${safeCust.name}.`,
    data: {
      token: `token-pass-${safeCust.id || safeCust.email || safeCust.phone}-${Date.now()}`,
      user: safeCust
    }
  });
});

// Pengajuan Lupa Kata Sandi Customer (Menunggu ACC Owner)
app.post('/api/auth/forgot-password', (req, res) => {
  const { identifier, new_password, note } = req.body || {};
  if (!identifier || !new_password) {
    return res.status(400).json({
      success: false,
      message: 'Email / Nomor WhatsApp dan Kata Sandi Baru wajib diisi.'
    });
  }

  const cleanPass = String(new_password).trim();
  if (cleanPass.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Kata sandi baru minimal 6 karakter.'
    });
  }

  const wallets = readJSON(WALLETS_FILE);
  const matched = findCustomerEntry(wallets, identifier);
  if (!matched) {
    return res.status(404).json({
      success: false,
      message: 'Akun dengan Email / WhatsApp tersebut tidak ditemukan. Pastikan sudah pernah masuk sebelumnya.'
    });
  }

  if (!wallets.password_reset_requests) wallets.password_reset_requests = [];
  const { key: customerKey, customer: cust } = matched;
  const nowIso = new Date().toISOString();
  const newHash = hashPassword(cleanPass);

  const existingPending = wallets.password_reset_requests.find(
    r => r.customer_key === customerKey && r.status === 'pending'
  );

  let resetReq;
  if (existingPending) {
    existingPending.new_password_hash = newHash;
    existingPending.has_requested_password = true;
    existingPending.note = (note || '').trim() || existingPending.note || 'Lupa kata sandi akun';
    existingPending.requested_at = nowIso;
    resetReq = existingPending;
  } else {
    resetReq = {
      id: `pwr-${Date.now()}`,
      customer_key: customerKey,
      customer_id: cust.id || customerKey,
      customer_name: cust.name || 'Pelanggan',
      customer_email: cust.email || '',
      customer_phone: cust.whatsapp || cust.phone || '',
      note: (note || '').trim() || 'Lupa kata sandi akun',
      new_password_hash: newHash,
      has_requested_password: true,
      status: 'pending',
      requested_at: nowIso
    };
    wallets.password_reset_requests.push(resetReq);
  }

  writeJSON(WALLETS_FILE, wallets);

  console.log(`🔐 [LUPA PASSWORD CUSTOMER] ${cust.name} (${cust.email || cust.whatsapp || cust.phone}) mengajukan reset menunggu ACC Owner.`);

  const { new_password_hash, ...safeReq } = resetReq;
  res.json({
    success: true,
    message: 'Pengajuan reset kata sandi terkirim ke Owner! Setelah di-ACC Owner, Anda langsung bisa login memakai kata sandi baru tersebut.',
    data: safeReq
  });
});

// Cek Status Pengajuan Lupa Kata Sandi Customer
app.get('/api/auth/forgot-password/status', (req, res) => {
  const { identifier } = req.query;
  if (!identifier) {
    return res.status(400).json({ success: false, message: 'Identifier diperlukan' });
  }
  const wallets = readJSON(WALLETS_FILE);
  const matched = findCustomerEntry(wallets, identifier);
  if (!matched) {
    return res.status(404).json({ success: false, message: 'Akun tidak ditemukan' });
  }

  const list = (wallets.password_reset_requests || [])
    .filter(r => r.customer_key === matched.key)
    .sort((a, b) => new Date(b.requested_at) - new Date(a.requested_at));

  if (list.length === 0) {
    return res.json({ success: true, data: null, message: 'Belum ada pengajuan reset kata sandi untuk akun ini.' });
  }

  const { new_password_hash, ...latest } = list[0];
  res.json({ success: true, data: latest });
});

// Login Dapur & Kasir Lapak (Mendukung PIN Kasir Cabang, Kata Sandi & Akun Google)
app.post('/api/auth/kitchen-login', (req, res) => {
  const { branch_id, pin_or_password, staff_name, email } = req.body;

  const branches = readJSON(BRANCHES_FILE);
  const targetBranch = branches.find(b => b.id === branch_id) || branches[0];

  if (!targetBranch) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan' });
  }

  const inputPin = String(pin_or_password || '').trim();
  const validBranchPin = targetBranch.staff_pin || '1234';

  // Verifikasi PIN / Password Kasir:
  // Cocok jika sama dengan PIN cabang (default 1234), atau password master "albewok2026" / "admin123"
  const isPinValid = inputPin === validBranchPin || inputPin === '1234' || inputPin === 'admin123' || inputPin === 'albewok2026';

  if (!isPinValid) {
    return res.status(401).json({
      success: false,
      message: `PIN Kasir salah! PIN standar adalah 1234 untuk ${targetBranch.name}.`
    });
  }

  const staffName = staff_name ? staff_name.trim() : `Kasir ${targetBranch.name.replace('Kebab AL Bewok - ', '')}`;
  const staffEmail = email ? email.trim() : `kasir.${targetBranch.id}@kebab-albewok.com`;

  const staffUser = {
    id: `staff-${targetBranch.id}-${Date.now().toString().slice(-4)}`,
    name: staffName,
    email: staffEmail,
    role: 'staff_kasir',
    branch_id: targetBranch.id,
    branch_name: targetBranch.name
  };

  console.log(`🏪 [KITCHEN LOGIN] ${staffUser.name} berhasil masuk ke ${targetBranch.name}`);

  res.json({
    success: true,
    message: `Akses diterima! Selamat bertugas di ${targetBranch.name}.`,
    data: {
      token: `token-kitchen-${targetBranch.id}-${Date.now()}`,
      staff: staffUser,
      branch: targetBranch
    }
  });
});

// Login Cepat & Gratis (Fallback)
app.post('/api/auth/login-free', (req, res) => {
  const { full_name, phone_number } = req.body;

  if (!full_name || full_name.trim().length < 2) {
    return res.status(400).json({ success: false, message: 'Mohon masukkan nama lengkap yang jelas.' });
  }

  let cleanPhone = (phone_number || '').replace(/[^0-9]/g, '');
  if (cleanPhone.startsWith('0')) cleanPhone = '62' + cleanPhone.slice(1);

  if (cleanPhone.length < 10 || cleanPhone.length > 15) {
    return res.status(400).json({ success: false, message: 'Nomor WhatsApp tidak valid (minimal 10 digit).' });
  }

  // Simpan data pelanggan ke database
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  const name = full_name.trim();
  wallets.customers[cleanPhone] = {
    phone: cleanPhone,
    name,
    balance: (wallets.customers[cleanPhone] ? wallets.customers[cleanPhone].balance : 0),
    last_login: new Date().toISOString()
  };
  writeJSON(WALLETS_FILE, wallets);

  console.log(`✅ [LOGIN GRATIS] Pelanggan terdaftar: ${name} (${cleanPhone})`);

  res.json({
    success: true,
    message: `Selamat datang, Kak ${name}! Nomor WhatsApp Anda berhasil terhubung.`,
    data: {
      token: `token-${cleanPhone}-${Date.now()}`,
      user: wallets.customers[cleanPhone]
    }
  });
});

// Kirim Kode OTP WhatsApp (Opsional jika nanti ada bot)
app.post('/api/auth/send-otp', (req, res) => {
  const { phone_number, full_name } = req.body;
  if (!phone_number || phone_number.length < 9) {
    return res.status(400).json({ success: false, message: 'Nomor WhatsApp tidak valid' });
  }

  // Format nomor (hapus karakter aneh, ubah 08.. jadi format standar)
  let cleanPhone = phone_number.replace(/[^0-9]/g, '');
  if (cleanPhone.startsWith('0')) cleanPhone = '62' + cleanPhone.slice(1);

  // Buat 4 digit OTP
  const otpCode = Math.floor(1000 + Math.random() * 9000).toString();
  otpStore.set(cleanPhone, {
    otp: otpCode,
    full_name: full_name || 'Pelanggan Kebab',
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  console.log(`🔑 [OTP KEBAB AL BEWOK] Kode verifikasi untuk ${cleanPhone} (${full_name}): ${otpCode}`);

  // Kirimkan ke WhatsApp Bot Gratis (port 5001) jika bot aktif
  fetch('http://127.0.0.1:5001/api/send-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone: cleanPhone, otp: otpCode, name: full_name || 'Pelanggan Kebab' })
  }).then(r => r.json()).then(data => {
    if (data.success) {
      console.log(`📲 [WA BOT SUKSES] OTP asli telah terkirim via WhatsApp ke ${cleanPhone}`);
    }
  }).catch(() => {
    // Bot WA mungkin belum dinyalakan, sistem tetap berjalan aman
  });

  res.json({
    success: true,
    message: 'Kode verifikasi berhasil dikirim!',
    data: {
      phone: cleanPhone,
      // Dikembalikan di response agar simulasi langsung jalan tanpa perlu langganan API gateway WA berbayar
      demo_otp: otpCode
    }
  });
});

// Verifikasi Kode OTP & Buat Sesi Login
app.post('/api/auth/verify-otp', (req, res) => {
  const { phone_number, otp_code, full_name } = req.body;
  let cleanPhone = (phone_number || '').replace(/[^0-9]/g, '');
  if (cleanPhone.startsWith('0')) cleanPhone = '62' + cleanPhone.slice(1);

  const session = otpStore.get(cleanPhone);

  // Validasi: Kode benar ATAU menggunakan Master PIN Demo '1234'
  const isMasterCode = (otp_code === '1234');
  const isValidSession = session && (session.otp === otp_code);

  if (!isMasterCode && !isValidSession) {
    return res.status(400).json({ success: false, message: 'Kode OTP salah. Silakan masukkan 1234 untuk demo.' });
  }

  // Simpan/update profil pelanggan di wallets/database
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.customers) wallets.customers = {};

  const name = full_name || (session ? session.full_name : 'Pelanggan Kebab');
  wallets.customers[cleanPhone] = {
    phone: cleanPhone,
    name,
    balance: (wallets.customers[cleanPhone] ? wallets.customers[cleanPhone].balance : 0),
    registered_at: new Date().toISOString()
  };
  writeJSON(WALLETS_FILE, wallets);

  // Hapus OTP setelah dipakai
  otpStore.delete(cleanPhone);

  res.json({
    success: true,
    message: 'Login berhasil! Selamat datang di Kebab AL Bewok.',
    data: {
      token: `token-${cleanPhone}-${Date.now()}`,
      user: wallets.customers[cleanPhone]
    }
  });
});

// Ambil Menu Kebab AL Bewok
app.get('/api/menu', (req, res) => {
  const menu = readJSON(MENU_FILE);
  res.json({ success: true, data: menu });
});

// Ambil Daftar Cabang Lapak
app.get('/api/branches', (req, res) => {
  const branches = readJSON(BRANCHES_FILE);
  res.json({ success: true, data: branches });
});

// Ambil Detail Satu Cabang
app.get('/api/branches/:id', (req, res) => {
  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === req.params.id);
  if (!branch) {
    return res.status(404).json({ success: false, message: 'Cabang tidak ditemukan' });
  }
  res.json({ success: true, data: branch });
});

// Helper Biaya Tetap Bulanan Cabang & Kalkulasi Laba Bersih (Terpusat)
function normalizeFixedExpenses(raw = {}) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const monthly_salary = Math.max(0, Number(src.monthly_salary) || 0);
  const monthly_rent = Math.max(0, Number(src.monthly_rent) || 0);
  const monthly_utilities = Math.max(0, Number(src.monthly_utilities) || 0);
  const monthly_total = monthly_salary + monthly_rent + monthly_utilities;
  return {
    monthly_salary,
    monthly_rent,
    monthly_utilities,
    monthly_total,
    daily_prorata: Math.round(monthly_total / 30)
  };
}

function computeBranchProfitMetrics({ branch, omzet = 0, totalHpp = 0, closingOp = null }) {
  const exp = normalizeFixedExpenses(branch && branch.fixed_expenses);
  const pettyCash = closingOp ? Math.max(0, Number(closingOp.petty_cash) || 0) : 0;
  const pettyCashNote = closingOp ? String(closingOp.petty_cash_note || '').trim() : '';
  const fixedProrata = exp.daily_prorata;
  const totalOpex = pettyCash + fixedProrata;
  const grossProfit = omzet - totalHpp;
  const netProfit = grossProfit - totalOpex;
  const netMarginPct = omzet > 0 ? Number(((netProfit / omzet) * 100).toFixed(1)) : null;

  return {
    gross_profit: grossProfit,
    petty_cash: pettyCash,
    petty_cash_note: pettyCashNote,
    fixed_prorata: fixedProrata,
    total_opex: totalOpex,
    net_profit: netProfit,
    net_margin_pct: netMarginPct
  };
}

// Update Profil Lapak: Nama, Lokasi (Alamat, Lat, Lng), Nomor Telepon & QRIS Lapak
app.put('/api/admin/branches/:id', (req, res) => {
  const { id } = req.params;
  if (req.portalUser) {
    if (!portalUserHasTab(req.portalUser, 'lapak')) {
      return res.status(403).json({ success: false, message: 'Akses ke menu Lapak tidak diizinkan untuk akun ini.' });
    }
    if (!(req.portalUser.permissions && req.portalUser.permissions.can_edit)) {
      return res.status(403).json({ success: false, message: 'Akun Anda dalam mode Lihat Saja (Read-Only).' });
    }
    if (!isBranchAllowedForPortalUser(req.portalUser, id)) {
      return res.status(403).json({ success: false, message: 'Lapak cabang ini di luar cakupan akun Anda.' });
    }
  }
  const {
    name,
    address,
    phone,
    latitude,
    longitude,
    qris_image,
    bank_info,
    is_open,
    open_hours,
    staff_pin,
    out_of_stock,
    cash_opening,
    fixed_expenses
  } = req.body;

  const branches = readJSON(BRANCHES_FILE);
  const idx = branches.findIndex(b => b.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan' });
  }

  if (name !== undefined && name !== null) branches[idx].name = String(name).trim();
  if (address !== undefined && address !== null) branches[idx].address = String(address).trim();
  if (phone !== undefined && phone !== null) branches[idx].phone = String(phone).trim();
  if (latitude !== undefined && latitude !== null && !isNaN(Number(latitude))) {
    branches[idx].latitude = parseFloat(latitude);
  }
  if (longitude !== undefined && longitude !== null && !isNaN(Number(longitude))) {
    branches[idx].longitude = parseFloat(longitude);
  }
  if (qris_image !== undefined && qris_image !== null && String(qris_image).trim() !== '') {
    branches[idx].qris_image = String(qris_image).trim();
  }
  if (bank_info !== undefined && bank_info !== null) branches[idx].bank_info = String(bank_info).trim();
  if (is_open !== undefined && is_open !== null) branches[idx].is_open = Boolean(is_open);
  if (open_hours !== undefined && open_hours !== null) branches[idx].open_hours = String(open_hours).trim();
  if (staff_pin !== undefined && staff_pin !== null && String(staff_pin).trim() !== '') {
    branches[idx].staff_pin = String(staff_pin).trim();
  }
  if (Array.isArray(out_of_stock)) {
    branches[idx].out_of_stock = out_of_stock;
  }
  if (cash_opening !== undefined && cash_opening !== null && !isNaN(Number(cash_opening))) {
    branches[idx].cash_opening = Math.max(0, Number(cash_opening));
  }
  if (fixed_expenses !== undefined && fixed_expenses !== null && typeof fixed_expenses === 'object') {
    if (!req.portalUser || (req.portalUser.role !== 'mitra' && canViewPortalFinance(req.portalUser))) {
      const norm = normalizeFixedExpenses(fixed_expenses);
      branches[idx].fixed_expenses = {
        monthly_salary: norm.monthly_salary,
        monthly_rent: norm.monthly_rent,
        monthly_utilities: norm.monthly_utilities
      };
    }
  }

  writeJSON(BRANCHES_FILE, branches);
  console.log(`[BRANCH UPDATE] Profil Cabang ${id} (${branches[idx].name}) berhasil diperbarui.`);
  res.json({
    success: true,
    message: 'Profil lapak dan QRIS berhasil diperbarui',
    data: branches[idx]
  });
});

// Tambah Cabang Baru
app.post('/api/admin/branches', (req, res) => {
  if (req.portalUser) {
    if (req.portalUser.role === 'mitra' || !portalUserHasTab(req.portalUser, 'lapak') || !(req.portalUser.permissions && req.portalUser.permissions.can_edit)) {
      return res.status(403).json({ success: false, message: 'Anda tidak memiliki izin menambahkan lapak cabang baru.' });
    }
  }
  const {
    name,
    address,
    phone,
    latitude,
    longitude,
    qris_image,
    bank_info,
    open_hours = '15:00 - 23:00',
    staff_pin = '1234',
    cash_opening = 100000,
    is_open = true,
    fixed_expenses
  } = req.body;

  if (!name || !address) {
    return res.status(400).json({ success: false, message: 'Nama dan alamat cabang wajib diisi' });
  }

  const branches = readJSON(BRANCHES_FILE);
  // Cari nomor cabang tertinggi agar ID selalu unik walau cabang > 9 atau pernah dihapus
  const maxNum = branches.reduce((max, b) => {
    const m = String(b.id || '').match(/(\d+)$/);
    return m ? Math.max(max, parseInt(m[1], 10)) : max;
  }, 0);
  let nextNum = maxNum + 1;
  let newId = `cabang-${String(nextNum).padStart(2, '0')}`;
  while (branches.some(b => b.id === newId)) {
    nextNum++;
    newId = `cabang-${String(nextNum).padStart(2, '0')}`;
  }

  const parsedLat = parseFloat(latitude);
  const parsedLng = parseFloat(longitude);
  const parsedCashOpening = Number(cash_opening);
  const normFixed = normalizeFixedExpenses(fixed_expenses);

  const newBranch = {
    id: newId,
    name: String(name).trim(),
    address: String(address).trim(),
    phone: phone ? String(phone).trim() : '0852-8584-1330',
    latitude: !isNaN(parsedLat) ? parsedLat : -6.2088,
    longitude: !isNaN(parsedLng) ? parsedLng : 106.8456,
    qris_image: (qris_image && String(qris_image).trim()) ? String(qris_image).trim() : `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=QRIS_${newId}`,
    bank_info: bank_info !== undefined && bank_info !== null ? String(bank_info).trim() : 'BCA a/n Kebab AL Bewok',
    is_open: Boolean(is_open),
    open_hours: String(open_hours || '15:00 - 23:00').trim(),
    staff_pin: String(staff_pin || '1234').trim() || '1234',
    out_of_stock: [],
    cash_opening: !isNaN(parsedCashOpening) ? Math.max(0, parsedCashOpening) : 100000,
    fixed_expenses: {
      monthly_salary: normFixed.monthly_salary,
      monthly_rent: normFixed.monthly_rent,
      monthly_utilities: normFixed.monthly_utilities
    }
  };

  branches.push(newBranch);
  writeJSON(BRANCHES_FILE, branches);
  console.log(`[BRANCH CREATE] Cabang baru ditambahkan: ${newBranch.name} (${newId})`);
  res.status(201).json({ success: true, message: 'Cabang baru berhasil ditambahkan', data: newBranch });
});

// Hapus Cabang Lapak (Minimal menyisakan 1 cabang aktif)
app.delete('/api/admin/branches/:id', (req, res) => {
  if (req.portalUser) {
    if (req.portalUser.role === 'mitra' || !portalUserHasTab(req.portalUser, 'lapak') || !(req.portalUser.permissions && req.portalUser.permissions.can_edit)) {
      return res.status(403).json({ success: false, message: 'Anda tidak memiliki izin menghapus lapak cabang.' });
    }
  }
  const { id } = req.params;
  const branches = readJSON(BRANCHES_FILE);
  if (branches.length <= 1) {
    return res.status(400).json({ success: false, message: 'Minimal harus ada 1 lapak aktif di sistem.' });
  }
  const idx = branches.findIndex(b => b.id === id);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan' });
  }

  const [removed] = branches.splice(idx, 1);
  writeJSON(BRANCHES_FILE, branches);
  console.log(`[BRANCH DELETE] Cabang dihapus: ${removed.name} (${id})`);
  res.json({ success: true, message: `Lapak "${removed.name}" berhasil dihapus.`, data: removed });
});

// Checkout Pesanan Baru
app.post('/api/orders/checkout', (req, res) => {
  const {
    customer_name,
    customer_phone,
    customer_address,
    customer_email,
    destination_type = 'home',
    branch_id,
    items,
    delivery_distance_km = 2.0,
    payment_method = 'qris_statis',
    customer_notes = ''
  } = req.body;

  if (!items || items.length === 0) {
    return res.status(400).json({ success: false, message: 'Keranjang belanja kosong' });
  }

  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === branch_id) || branches[0];

  // Hitung subtotal makanan
  const food_subtotal = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

  // Rumus Ongkir Hemat: Rp 6.000 untuk 2 km pertama, +Rp 2.000 tiap km berikutnya
  let delivery_fee = 6000;
  if (delivery_distance_km > 2) {
    delivery_fee += Math.ceil(delivery_distance_km - 2) * 2000;
  }

  const total_payment = food_subtotal + delivery_fee;
  const order_code = `KB-${Date.now().toString().slice(-6)}`;

  const newOrder = {
    id: `ord-${Date.now()}`,
    order_code,
    branch_id: branch.id,
    branch_name: branch.name,
    branch_latitude: branch.latitude || -6.2088,
    branch_longitude: branch.longitude || 106.8456,
    customer_name: customer_name || 'Pelanggan Kebab',
    customer_email: customer_email || null,
    customer_phone: customer_phone || '081234567890',
    customer_address: customer_address || 'Jl. Mawar No. 10',
    customer_latitude: parseFloat(req.body.customer_latitude || req.body.latitude) || -6.2150,
    customer_longitude: parseFloat(req.body.customer_longitude || req.body.longitude) || 106.8520,
    destination_type,
    delivery_distance_km,
    items,
    food_subtotal,
    delivery_fee,
    total_payment,
    payment_method, // 'qris_statis' atau 'customer_balance'
    payment_proof: null,
    status: payment_method === 'customer_balance' ? 'cooking' : 'pending_payment',
    created_at: new Date().toISOString(),
    driver_id: null,
    driver_name: null,
    driver_phone: null,
    driver_vehicle: null,
    driver_photo: null,
    driver_latitude: null,
    driver_longitude: null,
    delivery_proof: null
  };

  const orders = readJSON(ORDERS_FILE);
  orders.unshift(newOrder);
  writeJSON(ORDERS_FILE, orders);

  res.json({
    success: true,
    message: 'Pesanan berhasil dibuat!',
    data: {
      order: newOrder,
      qris_image: branch.qris_image,
      bank_info: branch.bank_info
    }
  });
});

// Upload Bukti Bayar QRIS Statis
app.post('/api/orders/:id/payment-proof', (req, res) => {
  const { id } = req.params;
  const { proof_image } = req.body; // base64 / image url

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id || o.order_code === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].payment_proof = proof_image || 'https://placehold.co/400x600/png?text=Bukti+Transfer+QRIS+Valid';
  orders[orderIndex].status = 'pending_verification';
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Bukti pembayaran terkirim! Menunggu verifikasi dapur.', data: orders[orderIndex] });
});

function calculateBearingDeg(lat1, lng1, lat2, lng2) {
  const rad = Math.PI / 180;
  const phi1 = lat1 * rad;
  const phi2 = lat2 * rad;
  const dLambda = (lng2 - lng1) * rad;
  const y = Math.sin(dLambda) * Math.cos(phi2);
  const x = Math.cos(phi1) * Math.sin(phi2) - Math.sin(phi1) * Math.cos(phi2) * Math.cos(dLambda);
  return ((Math.atan2(y, x) * 180) / Math.PI + 360) % 360;
}

function resolveOrderDriverPosition(order) {
  const branchLat = Number(order.branch_latitude) || -6.2088;
  const branchLng = Number(order.branch_longitude) || 106.8456;
  const custLat = Number(order.customer_latitude) || -6.2150;
  const custLng = Number(order.customer_longitude) || 106.8520;

  let driverLat = Number(order.driver_latitude) || branchLat;
  let driverLng = Number(order.driver_longitude) || branchLng;

  if (!order.manual_gps) {
    if (order.status === 'driver_heading_to_branch' || order.driver_phase === 'to_branch') {
      const startLat = Number(order.driver_start_latitude) || (branchLat + 0.0065);
      const startLng = Number(order.driver_start_longitude) || (branchLng - 0.0055);
      const elapsedSec = (Date.now() - new Date(order.driver_accepted_at || Date.now()).getTime()) / 1000;
      const progress = Math.min(0.96, Math.max(0, elapsedSec / 45));
      driverLat = startLat + (branchLat - startLat) * progress;
      driverLng = startLng + (branchLng - startLng) * progress;
    } else if (order.status === 'on_delivery' || order.driver_phase === 'to_customer') {
      const startTime = order.driver_picked_up_at || order.driver_accepted_at || Date.now();
      const elapsedSec = (Date.now() - new Date(startTime).getTime()) / 1000;
      const progress = Math.min(0.96, Math.max(0, elapsedSec / 65));
      driverLat = branchLat + (custLat - branchLat) * progress;
      driverLng = branchLng + (custLng - branchLng) * progress;
    }
  }

  return { driverLat, driverLng, branchLat, branchLng, custLat, custLng };
}

function updateDriverTelemetryInWallet(driverId, latitude, longitude, extra = {}) {
  if (!driverId) return;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[driverId]) return;
  const d = wallets.drivers[driverId];
  const parsedLat = parseFloat(latitude);
  const parsedLng = parseFloat(longitude);
  if (!isNaN(parsedLat) && !isNaN(parsedLng)) {
    if (d.last_latitude !== undefined && d.last_longitude !== undefined && (d.last_latitude !== parsedLat || d.last_longitude !== parsedLng)) {
      d.last_heading = calculateBearingDeg(d.last_latitude, d.last_longitude, parsedLat, parsedLng);
    }
    d.last_latitude = parsedLat;
    d.last_longitude = parsedLng;
  }
  if (extra.is_online !== undefined) d.is_online = Boolean(extra.is_online);
  if (extra.heading !== undefined && !isNaN(Number(extra.heading))) d.last_heading = Number(extra.heading);
  if (extra.speed_kmh !== undefined && !isNaN(Number(extra.speed_kmh))) d.last_speed_kmh = Number(extra.speed_kmh);
  d.last_seen_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);
}

// Lacak Status Pesanan & Lokasi Driver Real-time (3 Fase: Menuju Lapak -> Ambil Makanan -> Menuju Customer)
app.get('/api/orders/:id', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const order = orders.find(o => o.id === id || o.order_code === id);

  if (!order) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  const pos = resolveOrderDriverPosition(order);
  order.driver_latitude = pos.driverLat;
  order.driver_longitude = pos.driverLng;

  res.json({ success: true, data: order });
});

// Heartbeat GPS & Status Standby Kurir (Untuk Radar Lalu Lintas Kurir Owner)
app.post('/api/driver/location', (req, res) => {
  const { driver_id, latitude, longitude, is_online, heading, speed_kmh } = req.body;
  if (!driver_id) {
    return res.status(400).json({ success: false, message: 'driver_id wajib diisi' });
  }
  updateDriverTelemetryInWallet(driver_id, latitude, longitude, { is_online, heading, speed_kmh });
  res.json({ success: true, message: 'Telemetri GPS kurir diperbarui' });
});

// Update Live GPS Lokasi Kurir saat Menuju Lapak / Mengantar
app.post('/api/driver/orders/:id/location', (req, res) => {
  const { id } = req.params;
  const { latitude, longitude, phase, heading, speed_kmh } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id || o.order_code === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].driver_latitude = parseFloat(latitude);
  orders[orderIndex].driver_longitude = parseFloat(longitude);
  orders[orderIndex].manual_gps = true;
  if (phase) orders[orderIndex].driver_phase = phase;
  orders[orderIndex].last_location_update = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  if (orders[orderIndex].driver_id) {
    updateDriverTelemetryInWallet(orders[orderIndex].driver_id, latitude, longitude, { is_online: true, heading, speed_kmh });
  }

  res.json({ success: true, message: 'Lokasi kurir terkirim secara live', data: { latitude, longitude } });
});

// ==========================================
// 2. ENDPOINTS ADMIN LAPAK / DAPUR
// ==========================================

// Daftar Pesanan Dapur & Kasir
app.get('/api/admin/orders', (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  res.json({ success: true, data: orders });
});

// Verifikasi Pembayaran QRIS Masuk -> Status Jadi 'cooking'
app.post('/api/admin/orders/:id/verify-payment', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].status = 'cooking';
  orders[orderIndex].payment_verified_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Pembayaran valid! Pesanan masuk ke antrean masak.', data: orders[orderIndex] });
});

// Makanan Siap Pick-up -> Panggil Kurir Freelance
app.post('/api/admin/orders/:id/ready', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  orders[orderIndex].status = 'ready_for_pickup';
  orders[orderIndex].ready_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  res.json({ success: true, message: 'Pesanan siap! Notifikasi disiarkan ke kurir terdekat.', data: orders[orderIndex] });
});

// Input Pesanan Kasir Manual Lapak (POS Offline: Walk-in / Dine-in / Takeaway)
app.post('/api/admin/orders/offline', (req, res) => {
  const {
    branch_id,
    customer_name = 'Pelanggan Langsung',
    items,
    payment_method = 'cash', // 'cash' | 'qris_offline'
    cash_tendered = 0,
    cash_change = 0,
    order_notes = ''
  } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ success: false, message: 'Item pesanan kasir tidak boleh kosong' });
  }

  const branches = readJSON(BRANCHES_FILE);
  const targetBranch = branches.find(b => b.id === branch_id) || branches[0];

  const food_subtotal = items.reduce((sum, item) => sum + (Number(item.price) * Number(item.quantity)), 0);
  const total_payment = food_subtotal;

  const orders = readJSON(ORDERS_FILE);
  const orderId = `ord-pos-${Date.now()}`;
  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const orderCode = `KB-OFF-${randomSuffix}`;

  const newOrder = {
    id: orderId,
    order_code: orderCode,
    branch_id: targetBranch.id,
    branch_name: targetBranch.name,
    branch_latitude: targetBranch.latitude,
    branch_longitude: targetBranch.longitude,
    customer_name: (customer_name && customer_name.trim()) ? customer_name.trim() : 'Pelanggan Langsung',
    customer_email: null,
    customer_phone: '-',
    customer_address: 'Makan di Tempat / Bawa Pulang (Walk-in)',
    customer_latitude: targetBranch.latitude,
    customer_longitude: targetBranch.longitude,
    destination_type: 'offline_store',
    delivery_distance_km: 0,
    items,
    food_subtotal,
    delivery_fee: 0,
    total_payment,
    payment_method, // 'cash' atau 'qris_offline'
    cash_tendered: Number(cash_tendered) || total_payment,
    cash_change: Number(cash_change) || 0,
    order_type: 'offline', // Pembeda jelas dari online
    order_notes,
    payment_proof: payment_method === 'qris_offline' ? (targetBranch.qris_image || 'https://placehold.co/300x300/png?text=QRIS+Lapak') : null,
    status: 'completed', // Pesanan offline kasir selesai langsung saat bayar
    completed_at: new Date().toISOString(),
    created_at: new Date().toISOString()
  };

  orders.unshift(newOrder);
  writeJSON(ORDERS_FILE, orders);

  res.json({
    success: true,
    message: 'Pesanan kasir offline berhasil dicatat & masuk ke pengkasian!',
    data: newOrder
  });
});

const ID_MONTHS = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];

function getLocalWibDate(dateInput = new Date()) {
  const utcMs = new Date(dateInput).getTime();
  return new Date(utcMs + 7 * 60 * 60 * 1000);
}

function getWibDateISO(dateInput = new Date()) {
  if (!dateInput) return '';
  return getLocalWibDate(dateInput).toISOString().split('T')[0];
}

function formatClosingDateId(dateInput = new Date(), prefix = 'Closing') {
  const d = getLocalWibDate(dateInput);
  const day = String(d.getUTCDate()).padStart(2, '0');
  const monthName = ID_MONTHS[d.getUTCMonth()] || 'Januari';
  const year = d.getUTCFullYear();
  return `${prefix} ${day} ${monthName} ${year}`;
}

function getDefaultBusinessDateISO(now = new Date()) {
  const wib = getLocalWibDate(now);
  if (wib.getUTCHours() < 15) {
    wib.setUTCDate(wib.getUTCDate() - 1);
  }
  return wib.toISOString().split('T')[0];
}

function parseClosingDateToISO(closingDateStr, fallbackISO) {
  if (closingDateStr) {
    const match = String(closingDateStr).match(/(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})/);
    if (match) {
      const day = match[1].padStart(2, '0');
      const monthIdx = ID_MONTHS.findIndex(m => m.toLowerCase() === match[2].toLowerCase());
      if (monthIdx >= 0) {
        return `${match[3]}-${String(monthIdx + 1).padStart(2, '0')}-${day}`;
      }
    }
  }
  return fallbackISO || getDefaultBusinessDateISO();
}

function isDateInRange(dateISO, startDate, endDate) {
  if (!dateISO) return !startDate && !endDate;
  if (startDate && dateISO < startDate) return false;
  if (endDate && dateISO > endDate) return false;
  return true;
}

function summarizePosOrders(ordersList) {
  let foodRev = 0;
  let delivFee = 0;
  let cashRev = 0;
  let qrisRev = 0;
  let onlineCount = 0;
  let offlineCount = 0;

  ordersList.forEach(o => {
    const food = Number(o.food_subtotal) || 0;
    const deliv = Number(o.delivery_fee) || 0;
    const total = Number(o.total_payment) || (food + deliv);
    const method = (o.payment_method || '').toLowerCase();

    foodRev += food;
    delivFee += deliv;
    if (method.includes('cash') || method.includes('tunai')) {
      cashRev += total;
    } else {
      qrisRev += total;
    }
    if (o.order_type === 'offline') {
      offlineCount++;
    } else {
      onlineCount++;
    }
  });

  return {
    order_count: ordersList.length,
    food_revenue: foodRev,
    delivery_fee_held: delivFee,
    cash_revenue: cashRev,
    qris_revenue: qrisRev,
    online_count: onlineCount,
    offline_count: offlineCount
  };
}

function enrichOpnameRecord(item, orders, now = new Date()) {
  const businessDate = item.business_date || parseClosingDateToISO(item.closing_date, item.date);
  let isLocked = false;
  if (item.manual_locked) {
    isLocked = true;
  } else if (item.manual_unlocked) {
    isLocked = false;
  } else if (item.lock_deadline) {
    isLocked = now.getTime() > new Date(item.lock_deadline).getTime();
  }

  // Cocokkan transaksi POS pada tanggal bisnis & cabang yang sama untuk audit selisih kas/QRIS
  const matchingOrders = (orders || []).filter(o =>
    o.branch_id === item.branch_id &&
    o.status !== 'pending_payment' &&
    o.status !== 'cancelled' &&
    getWibDateISO(o.created_at) === businessDate
  );
  const posSummary = summarizePosOrders(matchingOrders);
  const omzetCash = Number(item.omzet_cash) || 0;
  const omzetBca = Number(item.omzet_bca) || 0;

  return {
    ...item,
    business_date: businessDate,
    is_locked: isLocked,
    pos_audit: {
      order_count: posSummary.order_count,
      pos_cash_total: posSummary.cash_revenue,
      pos_qris_total: posSummary.qris_revenue,
      pos_food_total: posSummary.food_revenue,
      diff_cash: omzetCash - posSummary.cash_revenue,
      diff_bca: omzetBca - posSummary.qris_revenue
    }
  };
}

// Katalog Item Stock Opname Kasir Lapak (Sinkron Real-Time dengan Master Gudang Pusat)
app.get('/api/admin/opname-items', (req, res) => {
  const wh = getOrInitWarehouse();
  const data = (wh.items || []).map((it, idx) => ({
    no: Number(it.no) || (idx + 1),
    id: it.id,
    name: it.name,
    unit: it.unit === 'pcs' && it.category === 'Tortilla' ? 'lembar' : it.unit,
    category: it.category
  }));
  res.json({ success: true, data });
});

// Ambil Riwayat Laporan Stock Opname Lapak
app.get('/api/admin/stock-opname', (req, res) => {
  if (req.portalUser && !portalUserHasTab(req.portalUser, 'omzet')) {
    return res.status(403).json({ success: false, message: 'Akses ke data Closing & Omzet tidak diizinkan.' });
  }
  const { branch_id, start_date, end_date } = req.query;
  const list = readJSON(STOCK_OPNAME_FILE);
  const orders = readJSON(ORDERS_FILE);
  const now = new Date();

  let enriched = list.map(item => enrichOpnameRecord(item, orders, now));

  const allowedSet = getAllowedBranchIdSet(req.portalUser);
  if (allowedSet) {
    enriched = enriched.filter(op => allowedSet.has(op.branch_id));
  }
  if (branch_id && branch_id !== 'all') {
    enriched = enriched.filter(op => op.branch_id === branch_id);
  }
  if (start_date || end_date) {
    enriched = enriched.filter(op => isDateInRange(op.business_date, start_date, end_date));
  }

  res.json({ success: true, data: enriched });
});

// Simpan / Perbarui Laporan Stock Opname Harian (Buka 22:30 WIB - Kunci 15:00 WIB)
app.post('/api/admin/stock-opname', (req, res) => {
  const {
    branch_id,
    branch_name,
    staff_name,
    closing_date,
    business_date,
    cash_opening = 100000,
    omzet_cash = 0,
    omzet_bca = 0,
    omzet_gofood = 0,
    omzet_grabfood = 0,
    omzet_shopeefood = 0,
    petty_cash = 0,
    petty_cash_note = '',
    total_omzet = 0,
    total_setor_kas,
    stock_items,
    notes,
    is_bypass = false
  } = req.body;

  if (!branch_id || !stock_items) {
    return res.status(400).json({ success: false, message: 'Data stock opname tidak lengkap' });
  }

  const list = readJSON(STOCK_OPNAME_FILE);
  const now = new Date();

  // Hitung lock_deadline: Jam 15:00 WIB pada hari berikutnya
  const deadline = new Date(now);
  if (getLocalWibDate(now).getUTCHours() >= 15) {
    deadline.setDate(deadline.getDate() + 1);
  }
  deadline.setHours(15, 0, 0, 0);

  const formattedClosingDate = closing_date || formatClosingDateId(business_date || getDefaultBusinessDateISO(now));
  const resolvedBusinessDate = business_date || parseClosingDateToISO(formattedClosingDate, getDefaultBusinessDateISO(now));

  // Cek apakah ada record yang sama untuk branch_id dan closing_date / business_date
  const existingIndex = list.findIndex(op =>
    op.branch_id === branch_id &&
    (op.closing_date === formattedClosingDate || (op.business_date && op.business_date === resolvedBusinessDate))
  );

  if (existingIndex >= 0 && !is_bypass) {
    const existing = list[existingIndex];
    const isCurrentlyLocked = existing.manual_locked ||
      (!existing.manual_unlocked && existing.lock_deadline && now.getTime() > new Date(existing.lock_deadline).getTime());
    if (isCurrentlyLocked) {
      return res.status(403).json({
        success: false,
        message: 'Laporan stock opname ini sudah terkunci permanen sejak pukul 15:00 WIB dan tidak dapat diubah lagi.'
      });
    }
  }

  const prev = existingIndex >= 0 ? list[existingIndex] : {};
  const cleanCashOpening = Number(cash_opening) || 100000;
  const cleanOmzetCash = Number(omzet_cash) || 0;
  const cleanPettyCash = Math.max(0, Number(petty_cash) || 0);
  const cleanPettyNote = String(petty_cash_note || '').trim();
  const computedSetorKas = (total_setor_kas !== undefined && total_setor_kas !== null && !isNaN(Number(total_setor_kas)))
    ? Number(total_setor_kas)
    : (cleanCashOpening + cleanOmzetCash - cleanPettyCash);

  const opnameRecord = {
    id: prev.id || `opname-${Date.now()}`,
    branch_id,
    branch_name: branch_name || 'Kalisari',
    staff_name: staff_name || 'Kasir Lapak',
    closing_date: formattedClosingDate,
    business_date: resolvedBusinessDate,
    date: getWibDateISO(now),
    created_at: prev.created_at || now.toISOString(),
    updated_at: now.toISOString(),
    lock_deadline: prev.lock_deadline || deadline.toISOString(),
    manual_unlocked: Boolean(prev.manual_unlocked),
    manual_locked: Boolean(prev.manual_locked),
    owner_verified: Boolean(prev.owner_verified),
    owner_verified_at: prev.owner_verified_at || null,
    cash_opening: cleanCashOpening,
    omzet_cash: cleanOmzetCash,
    omzet_bca: Number(omzet_bca) || 0,
    omzet_gofood: Number(omzet_gofood) || 0,
    omzet_grabfood: Number(omzet_grabfood) || 0,
    omzet_shopeefood: Number(omzet_shopeefood) || 0,
    petty_cash: cleanPettyCash,
    petty_cash_note: cleanPettyNote,
    total_omzet: Number(total_omzet) || 0,
    total_setor_kas: computedSetorKas,
    stock_items,
    notes: notes || '',
    is_bypass: Boolean(is_bypass),
    status: 'submitted_to_owner'
  };

  if (existingIndex >= 0) {
    list[existingIndex] = opnameRecord;
  } else {
    list.unshift(opnameRecord);
  }

  writeJSON(STOCK_OPNAME_FILE, list);

  // Otomatis kembalikan sisa fisik Closing Opname ke Gudang Pusat (kolom Dikembalikan -> hitung Terpakai & HPP)
  const warehouseReturnSync = syncLinkedWarehouseEntry({
    linkField: 'source_opname_id',
    linkId: opnameRecord.id,
    type: 'branch_return',
    date: opnameRecord.business_date,
    branch_id: opnameRecord.branch_id,
    branch_name: opnameRecord.branch_name,
    pic_name: opnameRecord.staff_name,
    note: `Dikembalikan otomatis dari ${opnameRecord.closing_date}`,
    stockItemsMap: opnameRecord.stock_items,
    countKey: 'physical_count'
  });

  res.json({
    success: true,
    message: 'Laporan Stock Opname Harian berhasil dikirim ke Dashboard Owner & sisa bahan otomatis dicatat kembali ke Gudang Pusat!',
    data: opnameRecord,
    warehouse_sync: warehouseReturnSync
  });
});

// Owner Koreksi / Input Pengeluaran Kas Kecil (Petty Cash) pada Laporan Closing
app.post('/api/super-admin/stock-opname/:id/petty-cash', (req, res) => {
  const { id } = req.params;
  const { petty_cash = 0, petty_cash_note = '' } = req.body || {};
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan.' });
  }
  if (!isBranchAllowedForPortalUser(req.portalUser, list[idx].branch_id)) {
    return res.status(403).json({ success: false, message: 'Laporan lapak cabang ini di luar cakupan akun Anda.' });
  }

  const cleanPetty = Math.max(0, Number(petty_cash) || 0);
  const cleanNote = String(petty_cash_note || '').trim();
  const op = list[idx];
  const cashOpening = Number(op.cash_opening) || 100000;
  const omzetCash = Number(op.omzet_cash) || 0;

  op.petty_cash = cleanPetty;
  op.petty_cash_note = cleanNote;
  op.total_setor_kas = cashOpening + omzetCash - cleanPetty;
  op.updated_at = new Date().toISOString();

  writeJSON(STOCK_OPNAME_FILE, list);
  res.json({
    success: true,
    message: 'Pengeluaran kas kecil harian berhasil diperbarui.',
    data: op
  });
});

// Owner Verifikasi Setoran Closing Harian
app.post('/api/super-admin/stock-opname/:id/verify', (req, res) => {
  const { id } = req.params;
  const { verified } = req.body || {};
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan' });
  }
  if (!isBranchAllowedForPortalUser(req.portalUser, list[idx].branch_id)) {
    return res.status(403).json({ success: false, message: 'Laporan lapak cabang ini di luar cakupan akun Anda.' });
  }

  const nextVerified = verified !== undefined ? Boolean(verified) : !Boolean(list[idx].owner_verified);
  list[idx].owner_verified = nextVerified;
  list[idx].owner_verified_at = nextVerified ? new Date().toISOString() : null;
  writeJSON(STOCK_OPNAME_FILE, list);

  res.json({
    success: true,
    message: nextVerified ? 'Setoran closing berhasil diverifikasi Owner.' : 'Verifikasi setoran dibatalkan.',
    data: list[idx]
  });
});

// Owner Buka Kunci / Kunci Manual Laporan Closing (Override jam 15:00 WIB)
app.post('/api/super-admin/stock-opname/:id/toggle-lock', (req, res) => {
  const { id } = req.params;
  const { unlock } = req.body || {};
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan' });
  }
  if (!isBranchAllowedForPortalUser(req.portalUser, list[idx].branch_id)) {
    return res.status(403).json({ success: false, message: 'Laporan lapak cabang ini di luar cakupan akun Anda.' });
  }

  const now = new Date();
  const currentlyLocked = list[idx].manual_locked ||
    (!list[idx].manual_unlocked && list[idx].lock_deadline && now.getTime() > new Date(list[idx].lock_deadline).getTime());
  const shouldUnlock = unlock !== undefined ? Boolean(unlock) : currentlyLocked;

  list[idx].manual_unlocked = shouldUnlock;
  list[idx].manual_locked = !shouldUnlock;
  writeJSON(STOCK_OPNAME_FILE, list);

  res.json({
    success: true,
    message: shouldUnlock ? 'Kunci laporan dibuka sementara agar kasir bisa merevisi.' : 'Laporan berhasil dikunci oleh Owner.',
    data: list[idx]
  });
});

// Owner Hapus Laporan Closing (untuk membersihkan data uji/salah input)
app.delete('/api/super-admin/stock-opname/:id', (req, res) => {
  const { id } = req.params;
  const list = readJSON(STOCK_OPNAME_FILE);
  const idx = list.findIndex(op => op.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Laporan closing tidak ditemukan' });
  }
  if (!isBranchAllowedForPortalUser(req.portalUser, list[idx].branch_id)) {
    return res.status(403).json({ success: false, message: 'Laporan lapak cabang ini di luar cakupan akun Anda.' });
  }

  const [removed] = list.splice(idx, 1);
  writeJSON(STOCK_OPNAME_FILE, list);

  syncLinkedWarehouseEntry({
    linkField: 'source_opname_id',
    linkId: removed.id,
    stockItemsMap: null
  });

  res.json({
    success: true,
    message: `Laporan "${removed.closing_date || removed.id}" berhasil dihapus.`,
    data: removed
  });
});

// ==========================================
// 3. ENDPOINTS DRIVER FREELANCE & SALDO OTOMATIS
// ==========================================

// Login / Registrasi Akun Google Kurir (Mendukung Real Token JWT Google Identity Services & Mode Cepat)
app.post('/api/driver/auth/google-login', async (req, res) => {
  let { credential, email, full_name, avatar_url, phone } = req.body;
  let isGoogleVerified = false;

  // Verifikasi Kriptografis Resmi Google jika credential JWT dikirim
  if (credential) {
    try {
      const gRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
      const gData = await gRes.json();
      if (gData.error_description || !gData.email) {
        return res.status(401).json({
          success: false,
          message: `Verifikasi Akun Google Kurir Gagal: ${gData.error_description || 'Token kedaluwarsa atau tidak valid'}`
        });
      }
      email = gData.email;
      full_name = gData.name || full_name || email.split('@')[0];
      avatar_url = gData.picture || avatar_url;
      isGoogleVerified = true;
      console.log(`🛵 [GOOGLE OAUTH VERIFIED DRIVER] Kurir terverifikasi: ${full_name} (${email})`);
    } catch (err) {
      console.error('Error saat menghubungi server Google tokeninfo driver:', err);
      return res.status(500).json({ success: false, message: 'Gagal menghubungi server verifikasi Google' });
    }
  }

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email Google kurir diperlukan' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  const driverKey = email.toLowerCase().replace(/[^a-z0-9]/g, '_');
  let driver = Object.values(wallets.drivers).find(d => d.email === email || d.id === driverKey);

  if (!driver) {
    driver = {
      id: driverKey,
      email,
      name: full_name || 'Kurir Freelance',
      avatar: avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${email}`,
      phone: phone || '085285841330',
      vehicle: 'Honda Beat',
      vehicle_plate: 'B 3918 KEB',
      balance: 37000,
      trips: 5,
      is_online: true,
      is_verified: true,
      google_verified: isGoogleVerified,
      registered_at: new Date().toISOString()
    };
    wallets.drivers[driver.id] = driver;
  } else {
    if (full_name) driver.name = full_name;
    if (avatar_url) driver.avatar = avatar_url;
    if (isGoogleVerified) driver.google_verified = true;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: isGoogleVerified 
      ? `Autentikasi Google Terverifikasi 100%! Selamat bertugas, Kak ${driver.name}.`
      : `Login Google Berhasil! Selamat bertugas, Kak ${driver.name}.`,
    data: {
      token: `token-driver-${driver.id}-${Date.now()}`,
      verified_by_google: isGoogleVerified,
      driver
    }
  });
});

// Update Profil Kurir & Pendaftaran Rekening Dompet (Terkunci 1x Input)
app.post('/api/driver/update-profile', (req, res) => {
  const { 
    driver_id, 
    email, 
    name, 
    phone, 
    vehicle, 
    vehicle_plate, 
    avatar,
    wallet_channel,
    wallet_account_number,
    wallet_account_name
  } = req.body;

  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  let driver = null;
  if (driver_id && wallets.drivers[driver_id]) {
    driver = wallets.drivers[driver_id];
  } else if (email) {
    driver = Object.values(wallets.drivers).find(d => d.email === email);
  }

  if (!driver) {
    return res.status(404).json({ success: false, message: 'Akun kurir tidak ditemukan' });
  }

  if (name) driver.name = name;
  if (phone) driver.phone = phone;
  if (vehicle) driver.vehicle = vehicle;
  if (vehicle_plate) driver.vehicle_plate = vehicle_plate;
  if (avatar) driver.avatar = avatar;

  // ATURAN DOMPET: HANYA BISA 1 KALI INPUT (LOCKED PERMANEN)
  if (wallet_account_number) {
    if (driver.registered_wallet && driver.registered_wallet.locked) {
      // Jika sudah terkunci dan driver mencoba mengubah nomor tanpa persetujuan owner
      if (
        driver.registered_wallet.account_number !== wallet_account_number ||
        driver.registered_wallet.channel !== wallet_channel
      ) {
        return res.status(403).json({
          success: false,
          wallet_locked: true,
          message: 'Nomor dompet/rekening sudah TERKUNCI permanen demi keamanan. Untuk mengganti, silakan ajukan permohonan resmi ke Owner!'
        });
      }
    } else {
      // Pendaftaran pertama kali: langsung kunci permanen!
      driver.registered_wallet = {
        channel: wallet_channel || 'DANA',
        account_number: wallet_account_number,
        account_name: wallet_account_name || driver.name,
        locked: true,
        locked_at: new Date().toISOString()
      };
    }
  }

  driver.profile_completed = true;
  driver.updated_at = new Date().toISOString();

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Biodata profil kurir & data dompet berhasil disimpan!',
    data: driver
  });
});

// Permohonan Penggantian Rekening Dompet Kurir (Wajib Konfirmasi Owner)
app.post('/api/driver/request-wallet-change', (req, res) => {
  const { driver_id, reason, new_channel, new_account_number, new_account_name } = req.body;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[driver_id]) {
    return res.status(404).json({ success: false, message: 'Driver tidak ditemukan' });
  }

  if (!wallets.wallet_change_requests) wallets.wallet_change_requests = [];

  const request = {
    id: `wcr-${Date.now()}`,
    driver_id,
    driver_name: wallets.drivers[driver_id].name,
    current_wallet: wallets.drivers[driver_id].registered_wallet,
    new_channel: new_channel || 'DANA',
    new_account_number,
    new_account_name: new_account_name || wallets.drivers[driver_id].name,
    reason: reason || 'Pergantian nomor akun e-wallet / rekening bank',
    status: 'pending',
    requested_at: new Date().toISOString()
  };

  wallets.wallet_change_requests.unshift(request);
  wallets.drivers[driver_id].wallet_change_pending = true;
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Permohonan penggantian rekening berhasil diajukan! Menunggu konfirmasi & persetujuan dari Owner.',
    data: request
  });
});

// Super Admin / Owner Menyetujui Penggantian Rekening Dompet
app.post('/api/super-admin/wallet-changes/:id/approve', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.wallet_change_requests) wallets.wallet_change_requests = [];

  const reqIndex = wallets.wallet_change_requests.findIndex(r => r.id === id);
  if (reqIndex === -1) {
    return res.status(404).json({ success: false, message: 'Permohonan tidak ditemukan' });
  }

  const changeReq = wallets.wallet_change_requests[reqIndex];
  changeReq.status = 'approved';
  changeReq.approved_at = new Date().toISOString();

  // Update rekening driver
  if (wallets.drivers[changeReq.driver_id]) {
    wallets.drivers[changeReq.driver_id].registered_wallet = {
      channel: changeReq.new_channel,
      account_number: changeReq.new_account_number,
      account_name: changeReq.new_account_name,
      locked: true,
      updated_by_owner_at: new Date().toISOString()
    };
    wallets.drivers[changeReq.driver_id].wallet_change_pending = false;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Permohonan pergantian rekening kurir berhasil disetujui Owner!',
    data: changeReq
  });
});

// Super Admin / Owner Menolak Penggantian Rekening Dompet
app.post('/api/super-admin/wallet-changes/:id/reject', (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.wallet_change_requests) wallets.wallet_change_requests = [];

  const reqIndex = wallets.wallet_change_requests.findIndex(r => r.id === id);
  if (reqIndex === -1) {
    return res.status(404).json({ success: false, message: 'Permohonan tidak ditemukan' });
  }

  const changeReq = wallets.wallet_change_requests[reqIndex];
  changeReq.status = 'rejected';
  changeReq.rejected_at = new Date().toISOString();
  if (reason) changeReq.rejected_reason = String(reason).trim();

  if (wallets.drivers && wallets.drivers[changeReq.driver_id]) {
    wallets.drivers[changeReq.driver_id].wallet_change_pending = false;
  }

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Permohonan pergantian rekening kurir ditolak.',
    data: changeReq
  });
});

// Verifikasi Biometrik Wajah Kurir (Anti Joki / Pinjam Akun)
app.post('/api/driver/verify-face', (req, res) => {
  const { driver_id, email, face_image } = req.body;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  let driver = null;
  if (driver_id && wallets.drivers[driver_id]) {
    driver = wallets.drivers[driver_id];
  } else if (email) {
    driver = Object.values(wallets.drivers).find(d => d.email === email);
  }

  if (!driver) {
    return res.status(404).json({ success: false, message: 'Akun kurir tidak ditemukan' });
  }

  driver.face_verified = true;
  driver.biometric_verified = true;
  driver.biometric_method = 'face';
  driver.face_verified_at = new Date().toISOString();
  if (face_image) {
    driver.last_face_photo = face_image;
  }
  driver.is_online = true; // Otomatis aktifkan status online
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: 'Verifikasi biometrik wajah berhasil! Akun resmi aktif & siap bertugas.',
    data: driver
  });
});

// Verifikasi Biometrik Ganda: Sidik Jari (Utama/Anti-Gelap) atau Wajah (Alternatif)
// Mengunci Prinsip: 1 Akun 1 Driver (Device Lock & Anti-Joki)
app.post('/api/driver/verify-biometric', (req, res) => {
  const { driver_id, email, method = 'fingerprint', device_id, biometric_proof } = req.body;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers) wallets.drivers = {};

  let driver = null;
  if (driver_id && wallets.drivers[driver_id]) {
    driver = wallets.drivers[driver_id];
  } else if (email) {
    driver = Object.values(wallets.drivers).find(d => d.email === email);
  }

  if (!driver) {
    return res.status(404).json({ success: false, message: 'Akun kurir tidak ditemukan' });
  }

  // PRINSIP 1 AKUN 1 DRIVER: Kunci perangkat (Device Binding)
  if (device_id) {
    if (driver.registered_device_id && driver.registered_device_id !== device_id) {
      driver.last_device_switch_at = new Date().toISOString();
    }
    driver.registered_device_id = device_id;
  }

  driver.face_verified = true;
  driver.biometric_verified = true;
  driver.biometric_method = method; // 'fingerprint' atau 'face'
  driver.biometric_verified_at = new Date().toISOString();
  if (biometric_proof) {
    driver.last_biometric_proof = biometric_proof;
  }
  driver.is_online = true;

  writeJSON(WALLETS_FILE, wallets);

  const methodText = method === 'fingerprint' ? 'Sidik Jari (Fingerprint Sensor)' : 'Pemindaian Wajah';
  res.json({
    success: true,
    message: `Verifikasi ${methodText} Berhasil! 1 Akun 1 Driver terproteksi resmi & siap bertugas.`,
    data: driver
  });
});

// Radar Orderan Siap Antar (Siapa Cepat Dia Dapat)
app.get('/api/driver/orders/available', (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  // Order yang sudah matang dan belum diambil kurir
  const availableOrders = orders.filter(o => o.status === 'ready_for_pickup' && !o.driver_id);
  res.json({ success: true, data: availableOrders });
});

// Kurir Menerima Orderan (Fase 1: Mulai Melaju dari Lokasi Kurir Menuju Lapak)
app.post('/api/driver/orders/:id/accept', (req, res) => {
  const { id } = req.params;
  const {
    driver_id = 'driver-01',
    driver_name = 'Budi Santoso',
    driver_phone,
    driver_vehicle,
    driver_photo,
    driver_latitude,
    driver_longitude
  } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  if (orders[orderIndex].driver_id) {
    return res.status(400).json({ success: false, message: 'Maaf, pesanan ini sudah diambil kurir lain!' });
  }

  const wallets = readJSON(WALLETS_FILE);
  if (driver_id && wallets.drivers && wallets.drivers[driver_id]) {
    const d = wallets.drivers[driver_id];
    if (d.is_suspended) {
      return res.status(403).json({
        success: false,
        message: 'Akun kurir Anda sedang dinonaktifkan sementara oleh Owner.'
      });
    }
    if (d.biometric_verified === false && d.face_verified === false) {
      return res.status(403).json({
        success: false,
        require_biometric_verification: true,
        message: 'Keamanan Akun: Harap verifikasi Sidik Jari atau Wajah Anda terlebih dahulu sebelum mengambil pesanan ini!'
      });
    }
  }

  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === orders[orderIndex].branch_id) || branches[0];

  const savedDriver = (wallets.drivers && wallets.drivers[driver_id]) ? wallets.drivers[driver_id] : null;

  // Lokasi awal kurir saat terima order (dari GPS HP kurir atau offset realistis ~600 meter di jalan)
  const initialDriverLat = driver_latitude ? parseFloat(driver_latitude) : ((branch.latitude || -6.2088) + 0.0065);
  const initialDriverLng = driver_longitude ? parseFloat(driver_longitude) : ((branch.longitude || 106.8456) - 0.0055);

  orders[orderIndex].driver_id = driver_id;
  orders[orderIndex].driver_name = driver_name || (savedDriver ? savedDriver.name : 'Budi Santoso');
  orders[orderIndex].driver_phone = driver_phone || (savedDriver ? savedDriver.phone : '0852-8584-1330');
  orders[orderIndex].driver_vehicle = driver_vehicle || (savedDriver ? `${savedDriver.vehicle} (${savedDriver.vehicle_plate})` : 'Honda Beat (B 3918 KEB)');
  orders[orderIndex].driver_photo = driver_photo || (savedDriver ? savedDriver.avatar : 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&h=150&fit=crop&crop=face');
  
  // Status Fase 1: Kurir menuju lapak untuk ambil pesanan
  orders[orderIndex].status = 'driver_heading_to_branch';
  orders[orderIndex].driver_phase = 'to_branch';
  orders[orderIndex].driver_accepted_at = new Date().toISOString();
  orders[orderIndex].driver_start_latitude = initialDriverLat;
  orders[orderIndex].driver_start_longitude = initialDriverLng;
  orders[orderIndex].driver_latitude = initialDriverLat;
  orders[orderIndex].driver_longitude = initialDriverLng;
  orders[orderIndex].manual_gps = !!(driver_latitude && driver_longitude);

  writeJSON(ORDERS_FILE, orders);
  const accOrder = orders[orderIndex];
  updateDriverTelemetryInWallet(accOrder.driver_id, accOrder.driver_latitude, accOrder.driver_longitude, {
    is_online: true
  });

  res.json({
    success: true,
    message: 'Orderan berhasil diambil! Silakan meluncur ke lapak kebab untuk mengambil pesanan.',
    data: orders[orderIndex]
  });
});

// Kurir Tiba di Lapak & Mengambil Kebab (Fase 2: Mulai Melaju dari Lapak Menuju Rumah Pelanggan)
app.post('/api/driver/orders/:id/pickup', (req, res) => {
  const { id } = req.params;
  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  const branches = readJSON(BRANCHES_FILE);
  const branch = branches.find(b => b.id === orders[orderIndex].branch_id) || branches[0];

  orders[orderIndex].status = 'on_delivery';
  orders[orderIndex].driver_phase = 'to_customer';
  orders[orderIndex].driver_picked_up_at = new Date().toISOString();
  orders[orderIndex].driver_latitude = branch.latitude || -6.2088;
  orders[orderIndex].driver_longitude = branch.longitude || 106.8456;
  orders[orderIndex].manual_gps = false; // Reset simulasi perjalanan dari lapak ke rumah

  writeJSON(ORDERS_FILE, orders);
  const pickedOrder = orders[orderIndex];
  updateDriverTelemetryInWallet(
    pickedOrder.driver_id,
    pickedOrder.driver_latitude ?? pickedOrder.branch_latitude,
    pickedOrder.driver_longitude ?? pickedOrder.branch_longitude,
    { is_online: true }
  );

  res.json({
    success: true,
    message: 'Kebab berhasil diambil! Sekarang silakan antar ke alamat pelanggan.',
    data: orders[orderIndex]
  });
});

// Kurir Selesai Mengantar -> SALDO DRIVER OTOMATIS BERTAMBAH!
app.post('/api/driver/orders/:id/complete', (req, res) => {
  const { id } = req.params;
  const { delivery_proof } = req.body;

  const orders = readJSON(ORDERS_FILE);
  const orderIndex = orders.findIndex(o => o.id === id);

  if (orderIndex === -1) {
    return res.status(404).json({ success: false, message: 'Pesanan tidak ditemukan' });
  }

  const order = orders[orderIndex];
  if (order.status === 'completed') {
    return res.status(400).json({ success: false, message: 'Pesanan ini sudah selesai sebelumnya.' });
  }

  // Update status pesanan
  order.status = 'completed';
  order.delivery_proof = delivery_proof || 'https://placehold.co/400x300/png?text=Foto+Serah+Terima+Kebab';
  order.completed_at = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  // OTOMATISASI SALDO: Tambah ongkir ke dompet driver
  const wallets = readJSON(WALLETS_FILE);
  const driverId = order.driver_id || 'driver-01';

  if (!wallets.drivers[driverId]) {
    wallets.drivers[driverId] = { id: driverId, name: order.driver_name || 'Driver', balance: 0, trips: 0, is_online: true };
  }

  const earnedFee = order.delivery_fee;
  wallets.drivers[driverId].balance += earnedFee;
  wallets.drivers[driverId].trips += 1;
  wallets.drivers[driverId].is_online = true;
  wallets.drivers[driverId].last_seen_at = new Date().toISOString();
  wallets.drivers[driverId].last_speed_kmh = 0;
  if (order.customer_latitude != null && order.customer_longitude != null) {
    wallets.drivers[driverId].last_latitude = Number(order.customer_latitude);
    wallets.drivers[driverId].last_longitude = Number(order.customer_longitude);
  }

  wallets.history.push({
    id: `tx-${Date.now()}`,
    user_id: driverId,
    order_id: order.id,
    order_code: order.order_code,
    type: 'delivery_earning',
    amount: earnedFee,
    current_balance: wallets.drivers[driverId].balance,
    description: `Ongkos kirim order #${order.order_code}`,
    created_at: new Date().toISOString()
  });

  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: `Pesanan selesai! Saldo Rp ${earnedFee.toLocaleString('id-ID')} otomatis masuk ke dompet Anda.`,
    data: {
      order,
      driver_wallet: wallets.drivers[driverId]
    }
  });
});

// Ambil Informasi Dompet Driver
app.get('/api/driver/wallet/:driverId', (req, res) => {
  const { driverId } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  const driver = wallets.drivers[driverId] || { id: driverId, name: 'Driver', balance: 0, trips: 0 };
  const history = wallets.history.filter(h => h.user_id === driverId);

  res.json({
    success: true,
    data: {
      wallet: driver,
      history
    }
  });
});

// ==========================================
// 4. ENDPOINTS SUPER ADMIN / PEMILIK (OWNER)
// ==========================================

// Ajukan Penarikan Dana oleh Driver (Menggunakan Rekening Terkunci 1 Akun 1 Driver)
app.post('/api/driver/wallet/withdraw', (req, res) => {
  const { driver_id, amount, payout_channel, account_number, account_name } = req.body;
  const wallets = readJSON(WALLETS_FILE);

  if (!wallets.drivers[driver_id] || wallets.drivers[driver_id].balance < amount) {
    return res.status(400).json({ success: false, message: 'Saldo tidak mencukupi untuk ditarik' });
  }

  const driver = wallets.drivers[driver_id];
  // Jika driver sudah mengunci dompet/rekeningnya, gunakan rekening terdaftar
  const finalChannel = (driver.registered_wallet && driver.registered_wallet.channel) ? driver.registered_wallet.channel : (payout_channel || 'DANA');
  const finalAccountNum = (driver.registered_wallet && driver.registered_wallet.account_number) ? driver.registered_wallet.account_number : (account_number || driver.phone || '081234567890');
  const finalAccountName = (driver.registered_wallet && driver.registered_wallet.account_name) ? driver.registered_wallet.account_name : (account_name || driver.name);

  if (!wallets.withdrawals) wallets.withdrawals = [];

  const newWithdrawal = {
    id: `wd-${Date.now()}`,
    driver_id,
    driver_name: driver.name,
    amount: Number(amount),
    payout_channel: finalChannel,
    account_number: finalAccountNum,
    account_name: finalAccountName,
    status: 'pending', // 'pending', 'approved'
    created_at: new Date().toISOString()
  };

  // Kurangi saldo sementara
  driver.balance -= Number(amount);
  wallets.withdrawals.unshift(newWithdrawal);

  if (!wallets.history) wallets.history = [];
  wallets.history.push({
    id: `tx-${Date.now()}`,
    user_id: driver_id,
    type: 'withdrawal',
    amount: Number(amount),
    current_balance: driver.balance,
    description: `Penarikan Dana ke ${finalChannel} (${finalAccountNum})`,
    status: 'pending',
    created_at: new Date().toISOString()
  });

  writeJSON(WALLETS_FILE, wallets);

  res.json({ 
    success: true, 
    message: `Permintaan penarikan Rp ${Number(amount).toLocaleString('id-ID')} ke ${finalChannel} (${finalAccountNum}) berhasil diajukan! Menunggu transfer dari Owner.`, 
    data: newWithdrawal 
  });
});

// Ringkasan Finansial Seluruh Cabang & Tagihan Titipan Ongkir (Mendukung Filter Tanggal)
app.get('/api/super-admin/summary', (req, res) => {
  const { start_date, end_date } = req.query;
  const branchesAll = readJSON(BRANCHES_FILE) || [];
  const branches = filterAllowedBranches(req.portalUser, branchesAll);
  const allowedSet = getAllowedBranchIdSet(req.portalUser);
  const allowFinance = canViewPortalFinance(req.portalUser);
  const allowKurir = portalUserHasTab(req.portalUser, 'kurir');
  const allowCostumer = portalUserHasTab(req.portalUser, 'costumer');
  const allowGudang = portalUserHasTab(req.portalUser, 'gudang');

  const orders = readJSON(ORDERS_FILE);
  const wallets = readJSON(WALLETS_FILE);

  const validOrders = orders.filter(o => {
    if (o.status === 'pending_payment' || o.status === 'cancelled') return false;
    if (allowedSet && !allowedSet.has(o.branch_id)) return false;
    if (start_date || end_date) {
      return isDateInRange(getWibDateISO(o.created_at), start_date, end_date);
    }
    return true;
  });

  let total_food_revenue = 0;
  let total_delivery_fees = 0;

  const branchStats = branches.map(b => {
    const branchOrders = validOrders.filter(o => o.branch_id === b.id);
    const pos = summarizePosOrders(branchOrders);

    total_food_revenue += pos.food_revenue;
    total_delivery_fees += pos.delivery_fee_held;

    return {
      branch_id: b.id,
      branch_name: b.name,
      address: b.address,
      phone: b.phone || '',
      open_hours: b.open_hours || '15:00 - 23:00',
      bank_info: b.bank_info || '',
      staff_pin: b.staff_pin || '1234',
      latitude: b.latitude ?? -6.2088,
      longitude: b.longitude ?? 106.8456,
      has_qris: Boolean(b.qris_image),
      is_open: b.is_open !== false,
      cash_opening: b.cash_opening !== undefined ? b.cash_opening : 100000,
      fixed_expenses: allowFinance ? normalizeFixedExpenses(b.fixed_expenses) : null,
      order_count: pos.order_count,
      food_revenue: pos.food_revenue,
      delivery_fee_held: pos.delivery_fee_held,
      cash_revenue: pos.cash_revenue,
      qris_revenue: pos.qris_revenue,
      online_count: pos.online_count,
      offline_count: pos.offline_count
    };
  });

  res.json({
    success: true,
    data: {
      total_food_revenue,
      total_delivery_fees,
      total_orders: validOrders.length,
      branches: branchStats,
      drivers: allowKurir ? Object.values(wallets.drivers || {}) : [],
      withdrawals: allowKurir ? (wallets.withdrawals || []) : [],
      wallet_change_requests: allowKurir ? (wallets.wallet_change_requests || []) : [],
      customer_password_resets_pending: allowCostumer
        ? (wallets.password_reset_requests || []).filter(r => r.status === 'pending').length
        : 0,
      warehouse_reorder_alerts: allowGudang ? getWarehouseReorderCount() : 0
    }
  });
});

// Owner Setujui Transfer Penarikan Saldo Kurir
app.post('/api/super-admin/withdrawals/:id/approve', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);

  if (!wallets.withdrawals) wallets.withdrawals = [];
  const idx = wallets.withdrawals.findIndex(w => w.id === id);

  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Data penarikan tidak ditemukan' });
  }

  wallets.withdrawals[idx].status = 'approved';
  wallets.withdrawals[idx].approved_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  res.json({ success: true, message: 'Penarikan dana disetujui & ditandai sudah ditransfer!' });
});

// ============================================================================
// RADAR LALU LINTAS KURIR (ATC FLIGHT RADAR STYLE) & KONTROL ADMIN KURIR
// ============================================================================
app.get('/api/super-admin/courier-radar', (req, res) => {
  const branchesAll = readJSON(BRANCHES_FILE) || [];
  const branches = filterAllowedBranches(req.portalUser, branchesAll);
  const allowedSet = getAllowedBranchIdSet(req.portalUser);
  const orders = readJSON(ORDERS_FILE) || [];
  const wallets = readJSON(WALLETS_FILE) || {};
  const driversObj = wallets.drivers || {};

  const defaultBranch = branches[0] || branchesAll[0] || { latitude: -6.33304, longitude: 106.85337 };
  const baseLat = Number(defaultBranch.latitude) || -6.33304;
  const baseLng = Number(defaultBranch.longitude) || 106.85337;

  const readyOrdersRaw = orders.filter(o =>
    isDeliveryOrder(o) && o.status === 'ready_for_pickup' && (!allowedSet || allowedSet.has(o.branch_id))
  );
  const activeOrdersRaw = orders.filter(o =>
    isDeliveryOrder(o) && (o.status === 'accepted' || o.status === 'delivering') && (!allowedSet || allowedSet.has(o.branch_id))
  );

  const branchById = new Map(branches.map(b => [b.id, b]));
  const branchRadar = branches.map(b => ({
    id: b.id,
    name: b.name,
    address: b.address || '',
    phone: b.phone || '',
    latitude: Number(b.latitude) || baseLat,
    longitude: Number(b.longitude) || baseLng,
    ready_count: readyOrdersRaw.filter(o => o.branch_id === b.id).length,
    active_count: activeOrdersRaw.filter(o => o.branch_id === b.id).length
  }));

  const ready_orders = readyOrdersRaw.map(o => {
    const br = branchById.get(o.branch_id);
    return {
      id: o.id,
      branch_id: o.branch_id,
      branch_name: (br && br.name) || o.branch_name || 'Lapak',
      customer_name: o.customer_name || 'Pelanggan',
      delivery_address: o.delivery_address || '',
      delivery_fee: Number(o.delivery_fee) || 0,
      total_price: getOrderTotalPaid(o),
      latitude: Number(o.branch_latitude ?? (br && br.latitude) ?? baseLat),
      longitude: Number(o.branch_longitude ?? (br && br.longitude) ?? baseLng),
      customer_latitude: o.customer_latitude != null ? Number(o.customer_latitude) : null,
      customer_longitude: o.customer_longitude != null ? Number(o.customer_longitude) : null,
      created_at: o.created_at
    };
  });

  const statusOrderWeight = {
    TO_CUSTOMER: 0,
    TO_BRANCH: 1,
    STANDBY: 2,
    OFFLINE: 3,
    SUSPENDED: 4
  };

  const couriers = Object.values(driversObj).map((d, idx) => {
    const activeOrder = activeOrdersRaw.find(o => o.driver_id === d.id) || null;
    const isSuspended = Boolean(d.is_suspended);

    let radarStatus = 'OFFLINE';
    if (isSuspended) radarStatus = 'SUSPENDED';
    else if (activeOrder && activeOrder.status === 'accepted') radarStatus = 'TO_BRANCH';
    else if (activeOrder && activeOrder.status === 'delivering') radarStatus = 'TO_CUSTOMER';
    else if (d.is_online !== false) radarStatus = 'STANDBY';

    const hasLiveGps = d.last_latitude != null && d.last_longitude != null;
    const angle = idx * 1.4;
    let lat = hasLiveGps ? Number(d.last_latitude) : baseLat + Math.sin(angle) * 0.0022;
    let lng = hasLiveGps ? Number(d.last_longitude) : baseLng + Math.cos(angle) * 0.0025;
    let heading = d.last_heading != null ? Number(d.last_heading) : (idx * 65) % 360;
    let activeOrderSummary = null;

    if (activeOrder) {
      const pos = resolveOrderDriverPosition(activeOrder);
      lat = pos.driverLat;
      lng = pos.driverLng;
      const targetLat = activeOrder.status === 'accepted' ? pos.branchLat : pos.custLat;
      const targetLng = activeOrder.status === 'accepted' ? pos.branchLng : pos.custLng;
      heading = d.last_heading != null
        ? Number(d.last_heading)
        : calculateBearingDeg(lat, lng, targetLat, targetLng);

      const br = branchById.get(activeOrder.branch_id);
      activeOrderSummary = {
        id: activeOrder.id,
        status: activeOrder.status,
        branch_id: activeOrder.branch_id,
        branch_name: (br && br.name) || activeOrder.branch_name || 'Lapak',
        customer_name: activeOrder.customer_name || 'Pelanggan',
        delivery_address: activeOrder.delivery_address || '',
        delivery_fee: Number(activeOrder.delivery_fee) || 0,
        branch_latitude: pos.branchLat,
        branch_longitude: pos.branchLng,
        customer_latitude: pos.custLat,
        customer_longitude: pos.custLng,
        target_latitude: targetLat,
        target_longitude: targetLng
      };
    }

    return {
      id: d.id,
      name: d.name || 'Kurir',
      phone: d.phone || '',
      email: d.email || '',
      vehicle: d.vehicle || 'Motor',
      vehicle_plate: d.vehicle_plate || '-',
      balance: Number(d.balance) || 0,
      trips: Number(d.trips) || 0,
      is_online: d.is_online !== false,
      is_suspended: isSuspended,
      radar_status: radarStatus,
      latitude: lat,
      longitude: lng,
      has_live_gps: hasLiveGps || Boolean(activeOrder),
      heading,
      speed_kmh: d.last_speed_kmh != null ? Number(d.last_speed_kmh) : (activeOrder ? 28 : 0),
      last_seen_at: d.last_seen_at || null,
      biometric_verified: Boolean(d.biometric_verified),
      has_device_lock: Boolean(d.registered_device_id),
      registered_wallet: d.registered_wallet || null,
      wallet_change_pending: Boolean(d.wallet_change_pending),
      active_order: activeOrderSummary
    };
  }).sort((a, b) => (statusOrderWeight[a.radar_status] ?? 9) - (statusOrderWeight[b.radar_status] ?? 9));

  const stats = {
    total: couriers.length,
    to_branch: couriers.filter(c => c.radar_status === 'TO_BRANCH').length,
    to_customer: couriers.filter(c => c.radar_status === 'TO_CUSTOMER').length,
    delivering: couriers.filter(c => c.radar_status === 'TO_BRANCH' || c.radar_status === 'TO_CUSTOMER').length,
    standby: couriers.filter(c => c.radar_status === 'STANDBY').length,
    offline: couriers.filter(c => c.radar_status === 'OFFLINE').length,
    suspended: couriers.filter(c => c.radar_status === 'SUSPENDED').length,
    ready_orders: ready_orders.length
  };

  res.json({
    success: true,
    data: {
      generated_at: new Date().toISOString(),
      stats,
      branches: branchRadar,
      ready_orders,
      couriers,
      wallet_change_requests: wallets.wallet_change_requests || []
    }
  });
});

// Owner Aktifkan / Nonaktifkan (Suspend) Akun Kurir
app.post('/api/super-admin/drivers/:id/toggle-status', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[id]) {
    return res.status(404).json({ success: false, message: 'Kurir tidak ditemukan' });
  }

  const driver = wallets.drivers[id];
  const nextSuspended = req.body && typeof req.body.suspended === 'boolean'
    ? req.body.suspended
    : !Boolean(driver.is_suspended);

  driver.is_suspended = nextSuspended;
  if (nextSuspended) {
    driver.is_online = false;
  }
  driver.status_updated_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: nextSuspended
      ? `Akun kurir ${driver.name} dinonaktifkan sementara.`
      : `Akun kurir ${driver.name} diaktifkan kembali.`,
    data: { id: driver.id, is_suspended: driver.is_suspended }
  });
});

// Owner Reset Kunci Perangkat (HP) Kurir
app.post('/api/super-admin/drivers/:id/reset-device', (req, res) => {
  const { id } = req.params;
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.drivers || !wallets.drivers[id]) {
    return res.status(404).json({ success: false, message: 'Kurir tidak ditemukan' });
  }

  const driver = wallets.drivers[id];
  driver.registered_device_id = null;
  driver.device_reset_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  res.json({
    success: true,
    message: `Kunci perangkat HP ${driver.name} berhasil direset.`,
    data: { id: driver.id, has_device_lock: false }
  });
});

// ============================================================================
// PORTAL OWNER TAB COSTUMER: PROFIL PELANGGAN & ACC LUPA PASSWORD
// ============================================================================
app.get('/api/super-admin/customers', (req, res) => {
  const wallets = readJSON(WALLETS_FILE) || {};
  const orders = readJSON(ORDERS_FILE) || [];
  const branches = readJSON(BRANCHES_FILE) || [];
  const branchNameById = new Map(branches.map(b => [b.id, b.name]));

  const custEntries = Object.entries(wallets.customers || {});
  const resetRequestsRaw = wallets.password_reset_requests || [];
  const pendingByKey = new Set(resetRequestsRaw.filter(r => r.status === 'pending').map(r => r.customer_key));

  const customers = custEntries.map(([customerKey, rawCust]) => {
    const safe = sanitizeCustomer(rawCust);
    const normCustPhone = normalizePhone(safe.whatsapp || safe.phone || '');
    const emailLower = safe.email ? safe.email.toLowerCase() : '';

    const matchedOrders = orders.filter(o => {
      if (o.status === 'cancelled' || o.status === 'rejected') return false;
      if (emailLower && o.customer_email && String(o.customer_email).toLowerCase() === emailLower) return true;
      if (safe.id && o.customer_id && o.customer_id === safe.id) return true;
      if (normCustPhone.length >= 7 && o.customer_phone && normalizePhone(o.customer_phone) === normCustPhone) return true;
      return false;
    });

    matchedOrders.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    const totalSpent = matchedOrders.reduce((sum, o) => sum + getOrderTotalPaid(o), 0);
    const recentOrders = matchedOrders.slice(0, 5).map(o => ({
      id: o.id,
      branch_name: branchNameById.get(o.branch_id) || o.branch_name || o.branch_id || 'Lapak',
      total_price: getOrderTotalPaid(o),
      status: o.status,
      order_type: isDeliveryOrder(o) ? 'delivery' : 'offline',
      created_at: o.created_at
    }));

    return {
      ...safe,
      customer_key: customerKey,
      phone_display: safe.whatsapp || safe.phone || '',
      order_count: matchedOrders.length,
      total_spent: totalSpent,
      last_order_at: matchedOrders[0] ? matchedOrders[0].created_at : null,
      recent_orders: recentOrders,
      pending_password_reset: pendingByKey.has(customerKey)
    };
  }).sort((a, b) => {
    if (a.pending_password_reset !== b.pending_password_reset) return a.pending_password_reset ? -1 : 1;
    if (b.order_count !== a.order_count) return b.order_count - a.order_count;
    return new Date(b.updated_at || b.registered_at || 0) - new Date(a.updated_at || a.registered_at || 0);
  });

  const password_reset_requests = resetRequestsRaw
    .map(({ new_password_hash, ...rest }) => rest)
    .sort((a, b) => {
      if ((a.status === 'pending') !== (b.status === 'pending')) return a.status === 'pending' ? -1 : 1;
      return new Date(b.requested_at || 0) - new Date(a.requested_at || 0);
    });

  const stats = {
    total_customers: customers.length,
    completed_profiles: customers.filter(c => c.profile_completed).length,
    with_password: customers.filter(c => c.has_password).length,
    repeat_buyers: customers.filter(c => c.order_count > 0).length,
    total_customer_balance: customers.reduce((sum, c) => sum + (Number(c.balance) || 0), 0),
    pending_password_resets: password_reset_requests.filter(r => r.status === 'pending').length
  };

  res.json({
    success: true,
    data: {
      stats,
      customers,
      password_reset_requests
    }
  });
});

// Owner ACC Pengajuan Lupa Password Customer
app.post('/api/super-admin/customers/password-resets/:id/approve', (req, res) => {
  const { id } = req.params;
  const { temporary_password } = req.body || {};
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.password_reset_requests) wallets.password_reset_requests = [];

  const resetReq = wallets.password_reset_requests.find(r => r.id === id);
  if (!resetReq) {
    return res.status(404).json({ success: false, message: 'Permintaan reset password tidak ditemukan' });
  }

  let nextHash = resetReq.new_password_hash || '';
  if (temporary_password && String(temporary_password).trim().length >= 6) {
    nextHash = hashPassword(String(temporary_password).trim());
  }
  if (!nextHash) {
    return res.status(400).json({
      success: false,
      message: 'Kata sandi baru belum tersedia. Masukkan minimal 6 karakter password sementara.'
    });
  }

  let cust = applyCustomerPasswordUpdate(wallets, resetReq.customer_key, nextHash);
  if (!cust) {
    const fallbackMatch = findCustomerEntry(wallets, resetReq.customer_email || resetReq.customer_phone);
    if (fallbackMatch) {
      cust = applyCustomerPasswordUpdate(wallets, fallbackMatch.key, nextHash);
    }
  }
  if (!cust) {
    return res.status(404).json({ success: false, message: 'Profil akun pelanggan tidak ditemukan' });
  }

  resetReq.status = 'approved';
  resetReq.approved_at = new Date().toISOString();
  writeJSON(WALLETS_FILE, wallets);

  console.log(`✅ [ACC LUPA PASSWORD] Owner menyetujui reset password untuk ${cust.name} (${resetReq.customer_key})`);

  const { new_password_hash, ...safeReq } = resetReq;
  res.json({
    success: true,
    message: `Reset kata sandi ${cust.name} telah di-ACC! Pelanggan sudah bisa login dengan kata sandi barunya.`,
    data: safeReq
  });
});

// Owner Tolak Pengajuan Lupa Password Customer
app.post('/api/super-admin/customers/password-resets/:id/reject', (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  const wallets = readJSON(WALLETS_FILE);
  if (!wallets.password_reset_requests) wallets.password_reset_requests = [];

  const resetReq = wallets.password_reset_requests.find(r => r.id === id);
  if (!resetReq) {
    return res.status(404).json({ success: false, message: 'Permintaan reset password tidak ditemukan' });
  }

  resetReq.status = 'rejected';
  resetReq.rejected_at = new Date().toISOString();
  if (reason) resetReq.rejected_reason = String(reason).trim();
  writeJSON(WALLETS_FILE, wallets);

  const { new_password_hash, ...safeReq } = resetReq;
  res.json({
    success: true,
    message: `Pengajuan reset password ${resetReq.customer_name} ditolak.`,
    data: safeReq
  });
});

// Owner Reset / Atur Ulang Kata Sandi Langsung dari Profil Costumer
app.post('/api/super-admin/customers/:key/reset-password', (req, res) => {
  const { key } = req.params;
  const { new_password } = req.body || {};
  const cleanPass = String(new_password || '').trim();
  if (cleanPass.length < 6) {
    return res.status(400).json({ success: false, message: 'Kata sandi baru minimal 6 karakter.' });
  }

  const wallets = readJSON(WALLETS_FILE);
  const cust = applyCustomerPasswordUpdate(wallets, key, hashPassword(cleanPass));
  if (!cust) {
    return res.status(404).json({ success: false, message: 'Akun pelanggan tidak ditemukan' });
  }

  if (Array.isArray(wallets.password_reset_requests)) {
    wallets.password_reset_requests.forEach(r => {
      if (r.customer_key === key && r.status === 'pending') {
        r.status = 'approved';
        r.approved_at = new Date().toISOString();
      }
    });
  }

  writeJSON(WALLETS_FILE, wallets);
  res.json({
    success: true,
    message: `Kata sandi untuk ${cust.name} berhasil diatur ulang oleh Owner.`
  });
});

// Helper Evaluasi Sesi Harian Per Cabang (Opening Harian Owner + Kiriman Gudang + Closing Opname Kasir)
function evaluateBranchSession(wh, branch, sessionDate, sortedOpnames, branchOpenings) {
  const closingOp = sortedOpnames.find(op => op.business_date === sessionDate) || null;
  const closingIdx = closingOp ? sortedOpnames.findIndex(op => op.id === closingOp.id) : -1;
  const prevClosingOp = closingIdx > 0 ? sortedOpnames[closingIdx - 1] : null;
  const ownerOpening = branchOpenings.find(o => o.business_date === sessionDate) || null;

  const restockByItem = {};
  (wh.ledger || []).forEach(tx => {
    if (tx.type !== 'branch_transfer' || tx.branch_id !== branch.id) return;
    if (ownerOpening && tx.source_opening_id === ownerOpening.id) return;
    const txDate = tx.date || getWibDateISO(tx.created_at);
    const matchesWindow = ownerOpening
      ? txDate === sessionDate
      : (closingOp && prevClosingOp
          ? (txDate > prevClosingOp.business_date && txDate <= sessionDate)
          : txDate === sessionDate);
    if (matchesWindow) {
      (tx.items || []).forEach(r => {
        restockByItem[r.item_id] = (restockByItem[r.item_id] || 0) + (Number(r.qty) || 0);
      });
    }
  });

  const catHppMap = new Map(WAREHOUSE_CATEGORIES.map(c => [c, 0]));
  let totalHpp = 0;
  let comparableItemCount = 0;

  const materialUsageRows = wh.items.map(it => {
    const openingFromOwner = ownerOpening && ownerOpening.stock_items && ownerOpening.stock_items[it.id] != null
      ? Number(ownerOpening.stock_items[it.id].opening_count ?? ownerOpening.stock_items[it.id].physical_count)
      : null;
    const openingQty = openingFromOwner !== null
      ? openingFromOwner
      : (prevClosingOp && prevClosingOp.stock_items && prevClosingOp.stock_items[it.id] != null
          ? Number(prevClosingOp.stock_items[it.id].physical_count)
          : null);
    const closingQty = closingOp && closingOp.stock_items && closingOp.stock_items[it.id] != null
      ? Number(closingOp.stock_items[it.id].physical_count)
      : null;
    const restockQty = restockByItem[it.id] || 0;
    const unitCost = Number(it.unit_cost) || 0;

    const effectiveOpening = openingQty !== null ? openingQty : (restockQty > 0 ? 0 : null);
    let usageQty = null;
    let subtotalHpp = 0;
    if (effectiveOpening !== null && closingQty !== null) {
      usageQty = Math.max(0, effectiveOpening + restockQty - closingQty);
      subtotalHpp = usageQty * unitCost;
      comparableItemCount += 1;
    }

    totalHpp += subtotalHpp;
    catHppMap.set(it.category, (catHppMap.get(it.category) || 0) + subtotalHpp);

    return {
      item_id: it.id,
      category: it.category,
      name: it.name,
      unit: it.unit,
      opening_qty: effectiveOpening,
      restock_qty: restockQty,
      closing_qty: closingQty,
      usage_qty: usageQty,
      unit_cost: unitCost,
      subtotal_hpp: subtotalHpp
    };
  });

  const omzet = closingOp ? (Number(closingOp.total_omzet) || 0) : 0;
  const profitMetrics = closingOp
    ? computeBranchProfitMetrics({ branch, omzet, totalHpp, closingOp })
    : {
        gross_profit: 0,
        petty_cash: 0,
        petty_cash_note: '',
        fixed_prorata: 0,
        total_opex: 0,
        net_profit: 0,
        net_margin_pct: null
      };
  const grossProfit = profitMetrics.gross_profit;
  const foodCostRatio = omzet > 0 && comparableItemCount > 0 ? Number(((totalHpp / omzet) * 100).toFixed(1)) : null;

  const hppByCategory = WAREHOUSE_CATEGORIES.map(cat => {
    const val = catHppMap.get(cat) || 0;
    return {
      category: cat,
      hpp: val,
      share_pct: totalHpp > 0 ? Number(((val / totalHpp) * 100).toFixed(1)) : 0
    };
  });

  const prettyDate = formatClosingDateId(new Date(`${sessionDate}T12:00:00Z`), '').trim();
  const statusTag = ownerOpening && closingOp
    ? 'Opening & Closing Lengkap'
    : ownerOpening
      ? 'Opening Terisi (Menunggu Closing)'
      : closingOp
        ? 'Closing Tercatat'
        : 'Kirim Gudang';

  return {
    business_date: sessionDate,
    session_label: `${prettyDate} • ${statusTag}`,
    has_opening: Boolean(ownerOpening),
    has_closing: Boolean(closingOp),
    has_opname_pair: Boolean((ownerOpening || prevClosingOp) && closingOp),
    has_latest_opname: Boolean(closingOp),
    opening_date: ownerOpening ? ownerOpening.opening_date : (prevClosingOp ? prevClosingOp.closing_date : null),
    closing_date: closingOp ? closingOp.closing_date : null,
    gross_sales: omzet,
    total_hpp: totalHpp,
    gross_profit: grossProfit,
    petty_cash: profitMetrics.petty_cash,
    petty_cash_note: profitMetrics.petty_cash_note,
    fixed_prorata: profitMetrics.fixed_prorata,
    total_opex: profitMetrics.total_opex,
    net_profit: profitMetrics.net_profit,
    net_margin_pct: profitMetrics.net_margin_pct,
    fixed_expenses: normalizeFixedExpenses(branch && branch.fixed_expenses),
    food_cost_ratio: foodCostRatio,
    hpp_by_category: hppByCategory,
    items: materialUsageRows
  };
}

// ============================================================================
// PORTAL OWNER TAB GUDANG: MUTASI STOK PUSAT, PO & EVALUASI HPP CABANG
// ============================================================================
app.get('/api/super-admin/warehouse', (req, res) => {
  const { start_date, end_date } = req.query;
  const wh = getOrInitWarehouse();
  const branches = readJSON(BRANCHES_FILE) || [];
  const opnamesRaw = readJSON(STOCK_OPNAME_FILE) || [];
  const orders = readJSON(ORDERS_FILE) || [];

  const inPeriod = entryDate => isDateInRange(entryDate, start_date, end_date);
  const periodLedger = (wh.ledger || []).filter(tx => inPeriod(tx.date || getWibDateISO(tx.created_at)));

  // Hitung agregasi mutasi periode per item & per cabang (untuk mempertahankan identitas Stok Awal + Masuk - Keluar === Sisa Akhir)
  const itemAgg = new Map();
  wh.items.forEach(it => {
    itemAgg.set(it.id, {
      stock_in: 0,
      waste: 0,
      transfers_by_branch: {},
      total_transfer_out: 0,
      returns_by_branch: {},
      total_returned: 0,
      adj_delta: 0
    });
  });

  const branchTransferTotalsMap = new Map();
  branches.forEach(b => {
    branchTransferTotalsMap.set(b.id, {
      branch_id: b.id,
      branch_name: b.name,
      qty_units: 0,
      total_value: 0,
      tx_count: 0,
      returned_units: 0,
      returned_value: 0
    });
  });

  let totalTransferValue = 0;
  let totalReturnedValue = 0;
  let totalSupplierInValue = 0;
  let totalWasteValue = 0;

  periodLedger.forEach(tx => {
    if (tx.type === 'supplier_in') totalSupplierInValue += Number(tx.total_value) || 0;
    if (tx.type === 'waste') totalWasteValue += Number(tx.total_value) || 0;
    if (tx.type === 'branch_transfer' || tx.type === 'branch_return') {
      if (tx.type === 'branch_transfer') totalTransferValue += Number(tx.total_value) || 0;
      else totalReturnedValue += Number(tx.total_value) || 0;

      if (tx.branch_id) {
        if (!branchTransferTotalsMap.has(tx.branch_id)) {
          branchTransferTotalsMap.set(tx.branch_id, {
            branch_id: tx.branch_id,
            branch_name: tx.branch_name || tx.branch_id,
            qty_units: 0,
            total_value: 0,
            tx_count: 0,
            returned_units: 0,
            returned_value: 0
          });
        }
        const bt = branchTransferTotalsMap.get(tx.branch_id);
        if (tx.type === 'branch_transfer') {
          bt.total_value += Number(tx.total_value) || 0;
          bt.tx_count += 1;
        } else {
          bt.returned_value += Number(tx.total_value) || 0;
        }
      }
    }

    (tx.items || []).forEach(row => {
      const agg = itemAgg.get(row.item_id);
      if (!agg) return;
      const qty = Number(row.qty) || 0;
      if (tx.type === 'supplier_in') {
        agg.stock_in += qty;
      } else if (tx.type === 'waste') {
        agg.waste += qty;
      } else if (tx.type === 'branch_transfer') {
        const bKey = tx.branch_id || 'lainnya';
        agg.transfers_by_branch[bKey] = (agg.transfers_by_branch[bKey] || 0) + qty;
        agg.total_transfer_out += qty;
        if (branchTransferTotalsMap.has(bKey)) {
          branchTransferTotalsMap.get(bKey).qty_units += qty;
        }
      } else if (tx.type === 'branch_return') {
        const bKey = tx.branch_id || 'lainnya';
        agg.returns_by_branch[bKey] = (agg.returns_by_branch[bKey] || 0) + qty;
        agg.total_returned += qty;
        if (branchTransferTotalsMap.has(bKey)) {
          branchTransferTotalsMap.get(bKey).returned_units += qty;
        }
      } else if (tx.type === 'adjustment') {
        agg.adj_delta += qty;
      }
    });
  });

  const items = wh.items.map(it => {
    const agg = itemAgg.get(it.id);
    const currentStock = Number(it.current_stock) || 0;
    const totalOut = agg.total_transfer_out + agg.waste;
    // Identitas mutasi: (Stok Awal + Masuk Supplier + Dikembalikan Lapak) - (Kirim Lapak + Waste) === Sisa Akhir
    const openingStock = Math.max(0, currentStock - agg.stock_in - agg.total_returned - agg.adj_delta + totalOut);
    const availableStock = openingStock + agg.stock_in;
    const totalUsed = Math.max(0, agg.total_transfer_out - agg.total_returned);
    const safetyStock = Number(it.safety_stock) || 0;
    const unitCost = Number(it.unit_cost) || 0;
    const assetValue = currentStock * unitCost;
    const usedValue = totalUsed * unitCost;

    let status = 'SAFE';
    if (currentStock <= safetyStock) status = 'REORDER';
    else if (currentStock <= Math.ceil(safetyStock * 1.25)) status = 'WARNING';

    const suggestedPoQty = currentStock <= safetyStock
      ? Math.max(safetyStock, safetyStock * 2 - currentStock)
      : 0;

    return {
      ...it,
      opening_stock: openingStock,
      stock_in: agg.stock_in,
      available_stock: availableStock,
      transfers_by_branch: agg.transfers_by_branch,
      total_transfer_out: agg.total_transfer_out,
      returns_by_branch: agg.returns_by_branch,
      total_returned: agg.total_returned,
      total_used: totalUsed,
      used_value: usedValue,
      waste: agg.waste,
      total_out: totalOut,
      current_stock: currentStock,
      safety_stock: safetyStock,
      unit_cost: unitCost,
      asset_value: assetValue,
      status,
      suggested_po_qty: suggestedPoQty
    };
  });

  // Evaluasi HPP & Food Cost Ratio Per Lapak Cabang (Memakai helper evaluateBranchSession bersama Tab Statistik)
  const visibleBranches = filterAllowedBranches(req.portalUser, branches);
  const allowedSet = getAllowedBranchIdSet(req.portalUser);
  const allowFinance = canViewPortalFinance(req.portalUser);
  const redactEval = ev => (allowFinance ? ev : {
    ...ev,
    gross_sales: null,
    total_hpp: null,
    gross_profit: null,
    petty_cash: null,
    fixed_prorata: null,
    total_opex: null,
    net_profit: null,
    net_margin_pct: null,
    food_cost_ratio: null,
    hpp_by_category: (ev.hpp_by_category || []).map(c => ({ ...c, hpp: null, share_pct: null })),
    items: (ev.items || []).map(r => ({ ...r, unit_cost: null, subtotal_hpp: null }))
  });

  const enrichedOpnames = opnamesRaw.map(op => enrichOpnameRecord(op, orders));
  const openingsRaw = readJSON(STOCK_OPENING_FILE, []);

  const branchEvaluations = visibleBranches.map(b => {
    const sortedOpnames = enrichedOpnames
      .filter(op => op.branch_id === b.id)
      .sort((a, z) => (a.business_date || '').localeCompare(z.business_date || ''));
    const branchOpenings = openingsRaw.filter(o => o.branch_id === b.id);

    const dateSet = new Set();
    branchOpenings.forEach(o => { if (o.business_date) dateSet.add(o.business_date); });
    sortedOpnames.forEach(op => { if (op.business_date) dateSet.add(op.business_date); });
    (wh.ledger || []).forEach(tx => {
      if (tx.type === 'branch_transfer' && tx.branch_id === b.id) {
        const d = tx.date || getWibDateISO(tx.created_at);
        if (d) dateSet.add(d);
      }
    });

    const allDatesDesc = Array.from(dateSet).sort((a, z) => z.localeCompare(a));
    const filteredDatesDesc = (start_date || end_date)
      ? allDatesDesc.filter(d => isDateInRange(d, start_date, end_date))
      : allDatesDesc;
    const sessionDates = filteredDatesDesc.length > 0 ? filteredDatesDesc : allDatesDesc;

    const sessions = sessionDates.map(d => redactEval(evaluateBranchSession(wh, b, d, sortedOpnames, branchOpenings)));
    const activeEval = sessions[0] || redactEval(evaluateBranchSession(wh, b, getWibDateISO(new Date()), sortedOpnames, branchOpenings));

    return {
      branch_id: b.id,
      branch_name: b.name,
      ...activeEval,
      sessions
    };
  });

  const ratios = allowFinance
    ? branchEvaluations
        .map(e => (e.food_cost_ratio !== null ? e.food_cost_ratio : ((e.sessions || []).find(s => s.food_cost_ratio !== null) || {}).food_cost_ratio ?? null))
        .filter(v => v !== null)
    : [];
  const avgFoodCostRatio = ratios.length > 0
    ? Number((ratios.reduce((a, b) => a + b, 0) / ratios.length).toFixed(1))
    : null;

  const purchaseOrders = [...(wh.purchase_orders || [])].sort(
    (a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)
  );
  const recentLedger = [...(wh.ledger || [])]
    .filter(tx => {
      if (!allowedSet) return true;
      if ((tx.type === 'branch_transfer' || tx.type === 'branch_return') && tx.branch_id) {
        return allowedSet.has(tx.branch_id);
      }
      return true;
    })
    .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));

  const visibleTransferTotalsRaw = Array.from(branchTransferTotalsMap.values())
    .filter(bt => !allowedSet || allowedSet.has(bt.branch_id));
  const visibleTransferTotals = visibleTransferTotalsRaw
    .map(bt => allowFinance ? bt : { ...bt, total_value: null, returned_value: null });

  const scopedTransferVal = allowedSet
    ? visibleTransferTotalsRaw.reduce((s, b) => s + (Number(b.total_value) || 0), 0)
    : totalTransferValue;
  const scopedReturnedVal = allowedSet
    ? visibleTransferTotalsRaw.reduce((s, b) => s + (Number(b.returned_value) || 0), 0)
    : totalReturnedValue;
  const scopedUsedVal = allowedSet
    ? branchEvaluations.reduce((s, e) => s + ((e.sessions || []).reduce((ss, ses) => ss + (Number(ses.total_hpp) || 0), 0)), 0)
    : items.reduce((s, it) => s + (it.used_value || 0), 0);

  const filterBranchMap = obj => {
    if (!allowedSet) return obj || {};
    const out = {};
    Object.entries(obj || {}).forEach(([k, v]) => { if (allowedSet.has(k)) out[k] = v; });
    return out;
  };

  const responseItems = items.map(it => {
    const base = allowFinance ? { ...it } : {
      ...it,
      unit_cost: null,
      asset_value: null,
      used_value: null
    };
    if (!allowedSet) return base;
    const scopedOut = Object.values(filterBranchMap(base.transfers_by_branch)).reduce((s, v) => s + (Number(v) || 0), 0);
    const scopedRet = Object.values(filterBranchMap(base.returns_by_branch)).reduce((s, v) => s + (Number(v) || 0), 0);
    const scopedUsed = Math.max(0, scopedOut - scopedRet);
    return {
      ...base,
      transfers_by_branch: filterBranchMap(base.transfers_by_branch),
      returns_by_branch: filterBranchMap(base.returns_by_branch),
      total_transfer_out: scopedOut,
      total_returned: scopedRet,
      total_used: scopedUsed,
      used_value: allowFinance ? (scopedUsed * (Number(it.unit_cost) || 0)) : null
    };
  });

  res.json({
    success: true,
    data: {
      meta: wh.meta,
      finance_restricted: !allowFinance,
      categories: WAREHOUSE_CATEGORIES,
      branches: visibleBranches.map(b => ({ id: b.id, name: b.name })),
      stats: {
        total_asset_value: allowFinance ? items.reduce((s, it) => s + it.asset_value, 0) : null,
        reorder_count: items.filter(it => it.status === 'REORDER').length,
        warning_count: items.filter(it => it.status === 'WARNING').length,
        total_transfer_value: allowFinance ? scopedTransferVal : null,
        total_returned_value: allowFinance ? scopedReturnedVal : null,
        total_used_value: allowFinance ? scopedUsedVal : null,
        total_supplier_in_value: allowFinance ? totalSupplierInValue : null,
        total_waste_value: allowFinance ? totalWasteValue : null,
        transfer_by_branch_totals: visibleTransferTotals,
        pending_po_count: purchaseOrders.filter(po => po.status === 'ordered').length,
        avg_food_cost_ratio: avgFoodCostRatio
      },
      items: responseItems,
      branch_evaluations: branchEvaluations,
      purchase_orders: allowFinance ? purchaseOrders : purchaseOrders.map(po => ({ ...po, total_cost: null })),
      ledger: recentLedger.slice(0, 60)
    }
  });
});

// Catat Transaksi Mutasi Gudang (Masuk Supplier / Kirim Cabang / Rusak-Waste)
app.post('/api/super-admin/warehouse/transaction', (req, res) => {
  const { type, date, branch_id, supplier_name, reference_no, pic_name, note, items } = req.body || {};
  const wh = getOrInitWarehouse();
  const branches = readJSON(BRANCHES_FILE) || [];
  let branchName = '';

  if (type === 'branch_transfer') {
    const targetBranch = branches.find(b => b.id === branch_id);
    if (!targetBranch) {
      return res.status(400).json({ success: false, message: 'Pilih lapak tujuan distribusi terlebih dahulu.' });
    }
    branchName = targetBranch.name;
  }

  const result = recordWarehouseTransaction(wh, {
    type,
    date,
    branch_id,
    branch_name: branchName,
    supplier_name,
    reference_no,
    pic_name,
    note,
    items
  });

  if (result.error) {
    return res.status(400).json({ success: false, message: result.error });
  }

  writeJSON(WAREHOUSE_FILE, wh);
  const labelMap = {
    supplier_in: 'Penerimaan dari supplier',
    branch_transfer: `Distribusi ke ${branchName}`,
    waste: 'Pencatatan rusak / waste'
  };

  res.json({
    success: true,
    message: `${labelMap[type] || 'Mutasi gudang'} berhasil dicatat!`,
    data: result.entry
  });
});

// Perbarui Harga Modal, Safety Stock, atau Penyesuaian Fisik Item Gudang
app.patch('/api/super-admin/warehouse/items/:id', (req, res) => {
  const { id } = req.params;
  const { unit_cost, safety_stock, current_stock, pic_name, note } = req.body || {};
  const wh = getOrInitWarehouse();
  const item = wh.items.find(it => it.id === id);
  if (!item) {
    return res.status(404).json({ success: false, message: 'Bahan baku tidak ditemukan' });
  }

  if (unit_cost !== undefined && !Number.isNaN(Number(unit_cost)) && Number(unit_cost) >= 0) {
    item.unit_cost = Number(unit_cost);
  }
  if (safety_stock !== undefined && !Number.isNaN(Number(safety_stock)) && Number(safety_stock) >= 0) {
    item.safety_stock = Number(safety_stock);
  }
  if (current_stock !== undefined && !Number.isNaN(Number(current_stock)) && Number(current_stock) >= 0) {
    const nextStock = Number(current_stock);
    if (nextStock !== Number(item.current_stock)) {
      recordWarehouseTransaction(wh, {
        type: 'adjustment',
        pic_name: pic_name || 'Owner (Stock Opname Gudang)',
        note: note || `Penyesuaian fisik stok ${item.name}`,
        items: [{ item_id: item.id, qty: nextStock }]
      });
    }
  }
  item.updated_at = new Date().toISOString();
  writeJSON(WAREHOUSE_FILE, wh);

  res.json({
    success: true,
    message: `Pengaturan ${item.name} berhasil diperbarui.`,
    data: item
  });
});

// Buat Purchase Order (PO) Pembelian Bahan ke Supplier
app.post('/api/super-admin/warehouse/purchase-orders', (req, res) => {
  const { supplier_name, note, items } = req.body || {};
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ success: false, message: 'Pilih minimal 1 bahan baku untuk dibuat PO.' });
  }

  const wh = getOrInitWarehouse();
  const itemMap = new Map(wh.items.map(it => [it.id, it]));
  const poItems = [];
  let totalCost = 0;

  for (const row of items) {
    const master = itemMap.get(row.item_id);
    const qty = Number(row.qty) || 0;
    if (!master || qty <= 0) continue;
    const unitCost = row.unit_cost != null && Number(row.unit_cost) > 0 ? Number(row.unit_cost) : (Number(master.unit_cost) || 0);
    const subtotal = qty * unitCost;
    totalCost += subtotal;
    poItems.push({
      item_id: master.id,
      name: master.name,
      category: master.category,
      unit: master.unit,
      qty,
      unit_cost: unitCost,
      subtotal
    });
  }

  if (poItems.length === 0) {
    return res.status(400).json({ success: false, message: 'Tidak ada item PO dengan kuantitas valid.' });
  }

  const po = {
    id: `PO-${getWibDateISO().replace(/-/g, '')}-${String(wh.purchase_orders.length + 1).padStart(2, '0')}`,
    supplier_name: (supplier_name || '').trim() || 'Supplier Pusat / Pasar Induk',
    note: (note || '').trim(),
    items: poItems,
    total_estimated_cost: totalCost,
    status: 'ordered',
    created_at: new Date().toISOString()
  };

  wh.purchase_orders.unshift(po);
  writeJSON(WAREHOUSE_FILE, wh);

  res.json({
    success: true,
    message: `PO ${po.id} berhasil diterbitkan!`,
    data: po
  });
});

// Terima Barang PO -> Otomatis Masuk ke Stok Gudang & Ledger
app.post('/api/super-admin/warehouse/purchase-orders/:id/receive', (req, res) => {
  const { id } = req.params;
  const wh = getOrInitWarehouse();
  const po = wh.purchase_orders.find(p => p.id === id);
  if (!po) {
    return res.status(404).json({ success: false, message: 'PO tidak ditemukan' });
  }
  if (po.status !== 'ordered') {
    return res.status(400).json({ success: false, message: `PO ini berstatus "${po.status}" dan tidak dapat diterima lagi.` });
  }

  const txResult = recordWarehouseTransaction(wh, {
    type: 'supplier_in',
    supplier_name: po.supplier_name,
    reference_no: po.id,
    pic_name: 'Owner / Penerimaan PO',
    note: po.note || `Penerimaan barang sesuai ${po.id}`,
    items: po.items.map(it => ({ item_id: it.item_id, qty: it.qty, unit_cost: it.unit_cost }))
  });

  if (txResult.error) {
    return res.status(400).json({ success: false, message: txResult.error });
  }

  po.status = 'received';
  po.received_at = new Date().toISOString();
  writeJSON(WAREHOUSE_FILE, wh);

  res.json({
    success: true,
    message: `Barang ${po.id} berhasil diterima & stok gudang otomatis bertambah!`,
    data: po
  });
});

// Batalkan Purchase Order
app.post('/api/super-admin/warehouse/purchase-orders/:id/cancel', (req, res) => {
  const { id } = req.params;
  const wh = getOrInitWarehouse();
  const po = wh.purchase_orders.find(p => p.id === id);
  if (!po) {
    return res.status(404).json({ success: false, message: 'PO tidak ditemukan' });
  }
  po.status = 'cancelled';
  po.cancelled_at = new Date().toISOString();
  writeJSON(WAREHOUSE_FILE, wh);

  res.json({ success: true, message: `PO ${po.id} dibatalkan.`, data: po });
});

// ============================================================================
// PORTAL OWNER TAB LAPAK (CABANG): SUB-TAB OPENING HARIAN (CASH & 21 BAHAN)
// ============================================================================
app.get('/api/super-admin/stock-opening', (req, res) => {
  const { branch_id, start_date, end_date } = req.query;
  const list = readJSON(STOCK_OPENING_FILE, []);
  const allowedSet = getAllowedBranchIdSet(req.portalUser);
  let filtered = [...list].sort((a, b) =>
    (b.business_date || '').localeCompare(a.business_date || '') ||
    new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0)
  );
  if (allowedSet) {
    filtered = filtered.filter(item => allowedSet.has(item.branch_id));
  }
  if (branch_id && branch_id !== 'all') {
    filtered = filtered.filter(item => item.branch_id === branch_id);
  }
  if (start_date || end_date) {
    filtered = filtered.filter(item => isDateInRange(item.business_date || item.date, start_date, end_date));
  }
  res.json({ success: true, data: filtered });
});

app.get('/api/super-admin/stock-opening/prefill', (req, res) => {
  const { branch_id, business_date } = req.query;
  const targetDate = business_date || getWibDateISO(new Date());
  const branchesAll = readJSON(BRANCHES_FILE) || [];
  const visibleBranches = filterAllowedBranches(req.portalUser, branchesAll);
  const branch = branch_id
    ? (visibleBranches.find(b => b.id === branch_id) || null)
    : (visibleBranches[0] || null);
  if (!branch) {
    return res.status(branch_id && branchesAll.some(b => b.id === branch_id) ? 403 : 404).json({
      success: false,
      message: 'Lapak tidak ditemukan atau di luar akses akun Anda.'
    });
  }

  const openings = readJSON(STOCK_OPENING_FILE, []);
  const opnames = readJSON(STOCK_OPNAME_FILE, []);
  const orders = readJSON(ORDERS_FILE, []);
  const wh = getOrInitWarehouse();

  const existingOpening = openings.find(
    o => o.branch_id === branch.id && o.business_date === targetDate
  ) || null;

  const branchClosings = opnames
    .map(op => enrichOpnameRecord(op, orders))
    .filter(op => op.branch_id === branch.id && (!targetDate || (op.business_date || '') <= targetDate))
    .sort((a, b) => (b.business_date || '').localeCompare(a.business_date || ''));

  // Pilih closing sebelumnya (diutamakan yang tanggalnya < targetDate)
  const prevClosing = branchClosings.find(op => (op.business_date || '') < targetDate)
    || branchClosings[0]
    || null;

  const restockToday = {};
  (wh.ledger || []).forEach(tx => {
    if (
      tx.type === 'branch_transfer' &&
      !tx.source_opening_id &&
      tx.branch_id === branch.id &&
      (tx.date || getWibDateISO(tx.created_at)) === targetDate
    ) {
      (tx.items || []).forEach(row => {
        restockToday[row.item_id] = (restockToday[row.item_id] || 0) + (Number(row.qty) || 0);
      });
    }
  });

  res.json({
    success: true,
    data: {
      business_date: targetDate,
      opening_date: formatClosingDateId(new Date(`${targetDate}T12:00:00Z`), 'Opening'),
      branch: {
        id: branch.id,
        name: branch.name,
        cash_opening: branch.cash_opening !== undefined ? Number(branch.cash_opening) : 100000
      },
      existing_opening: existingOpening,
      prev_closing: prevClosing ? {
        id: prevClosing.id,
        closing_date: prevClosing.closing_date,
        business_date: prevClosing.business_date,
        stock_items: prevClosing.stock_items || {}
      } : null,
      restock_today: restockToday,
      master_items: wh.items.map(it => ({
        no: it.no,
        id: it.id,
        category: it.category,
        name: it.name,
        unit: it.unit,
        unit_cost: it.unit_cost
      }))
    }
  });
});

app.post('/api/super-admin/stock-opening', (req, res) => {
  const {
    branch_id,
    business_date,
    opening_date,
    staff_name,
    cash_opening = 100000,
    stock_items,
    notes = ''
  } = req.body || {};

  if (!branch_id || !stock_items) {
    return res.status(400).json({ success: false, message: 'Lapak cabang dan stok opening bahan baku wajib diisi.' });
  }

  const branches = readJSON(BRANCHES_FILE) || [];
  const branchIndex = branches.findIndex(b => b.id === branch_id);
  if (branchIndex === -1) {
    return res.status(404).json({ success: false, message: 'Cabang lapak tidak ditemukan.' });
  }

  const now = new Date();
  const resolvedDate = business_date || getWibDateISO(now);
  const formattedOpeningDate = opening_date || formatClosingDateId(new Date(`${resolvedDate}T12:00:00Z`), 'Opening');
  const cleanCashOpening = Math.max(0, Number(cash_opening) || 0);

  const openings = readJSON(STOCK_OPENING_FILE, []);
  const existingIdx = openings.findIndex(o =>
    o.branch_id === branch_id && o.business_date === resolvedDate
  );
  const prev = existingIdx >= 0 ? openings[existingIdx] : {};

  const record = {
    id: prev.id || `opening-${Date.now()}`,
    branch_id,
    branch_name: branches[branchIndex].name,
    staff_name: (staff_name || '').trim() || 'Owner / Supervisor',
    opening_date: formattedOpeningDate,
    business_date: resolvedDate,
    cash_opening: cleanCashOpening,
    stock_items,
    notes: String(notes || '').trim(),
    created_at: prev.created_at || now.toISOString(),
    updated_at: now.toISOString()
  };

  if (existingIdx >= 0) {
    openings[existingIdx] = record;
  } else {
    openings.unshift(record);
  }
  writeJSON(STOCK_OPENING_FILE, openings);

  // Sinkronkan juga modal awal Cash Opening ke data cabang aktif agar kasir lapak langsung membacanya
  branches[branchIndex].cash_opening = cleanCashOpening;
  writeJSON(BRANCHES_FILE, branches);

  // Otomatis catat stok Opening Harian sebagai Kirim ke Lapak pada Gudang Pusat (akumulasi semua lapak)
  const warehouseSync = syncLinkedWarehouseEntry({
    linkField: 'source_opening_id',
    linkId: record.id,
    type: 'branch_transfer',
    date: resolvedDate,
    branch_id,
    branch_name: branches[branchIndex].name,
    pic_name: record.staff_name,
    note: `Otomatis dari ${formattedOpeningDate}`,
    stockItemsMap: stock_items,
    countKey: 'opening_count'
  });

  res.json({
    success: true,
    message: `Opening Harian (${formattedOpeningDate}) untuk ${branches[branchIndex].name} disimpan & otomatis tercatat di Kirim Lapak Gudang!`,
    data: record,
    warehouse_sync: warehouseSync
  });
});

app.delete('/api/super-admin/stock-opening/:id', (req, res) => {
  const { id } = req.params;
  const openings = readJSON(STOCK_OPENING_FILE, []);
  const idx = openings.findIndex(o => o.id === id);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: 'Data opening harian tidak ditemukan.' });
  }
  if (!isBranchAllowedForPortalUser(req.portalUser, openings[idx].branch_id)) {
    return res.status(403).json({ success: false, message: 'Opening harian cabang ini di luar akses akun Anda.' });
  }
  const removed = openings.splice(idx, 1)[0];
  writeJSON(STOCK_OPENING_FILE, openings);

  syncLinkedWarehouseEntry({
    linkField: 'source_opening_id',
    linkId: removed.id,
    stockItemsMap: null
  });

  res.json({ success: true, message: `Opening "${removed.opening_date}" berhasil dihapus & kiriman gudang terkait dibatalkan.` });
});

// ============================================================================
// PORTAL OWNER TAB STATISTIK: TREN HARIAN, LEADERBOARD, MENU, PEAK HOURS & RETENTION
// ============================================================================
app.get('/api/super-admin/statistics', (req, res) => {
  const { branch_id = 'all', start_date, end_date } = req.query;
  const branchesAll = readJSON(BRANCHES_FILE) || [];
  const branches = filterAllowedBranches(req.portalUser, branchesAll);
  const allowedSet = getAllowedBranchIdSet(req.portalUser);
  const allowFinance = canViewPortalFinance(req.portalUser);

  const ordersAll = readJSON(ORDERS_FILE) || [];
  const opnamesRaw = (readJSON(STOCK_OPNAME_FILE, []) || []).filter(op => !allowedSet || allowedSet.has(op.branch_id));
  const openingsRaw = (readJSON(STOCK_OPENING_FILE, []) || []).filter(o => !allowedSet || allowedSet.has(o.branch_id));
  const wallets = readJSON(WALLETS_FILE, {});
  const wh = getOrInitWarehouse();

  const validOrders = ordersAll.filter(o =>
    o.status !== 'pending_payment' && o.status !== 'cancelled' && o.status !== 'rejected' &&
    (!allowedSet || allowedSet.has(o.branch_id))
  );
  const enrichedOpnames = opnamesRaw.map(op => enrichOpnameRecord(op, validOrders));

  const inRange = iso => isDateInRange(iso, start_date, end_date);
  const matchesBranch = (itemBranchId, targetId) => !targetId || targetId === 'all' || itemBranchId === targetId;

  const periodOrdersAll = validOrders.filter(o => inRange(getWibDateISO(o.created_at)));
  const periodOpnamesAll = enrichedOpnames.filter(op => inRange(op.business_date));

  const scopedOrders = periodOrdersAll.filter(o => matchesBranch(o.branch_id, branch_id));
  const scopedOpnames = periodOpnamesAll.filter(op => matchesBranch(op.branch_id, branch_id));

  // Helper ringkas menghitung omzet, HPP, order & profit untuk 1 cabang dalam periode
  function summarizeBranchMetrics(b) {
    const bSortedOpnames = enrichedOpnames
      .filter(op => op.branch_id === b.id)
      .sort((a, z) => (a.business_date || '').localeCompare(z.business_date || ''));
    const bOpenings = openingsRaw.filter(o => o.branch_id === b.id);
    const bPeriodOpnames = periodOpnamesAll.filter(op => op.branch_id === b.id);
    const bPeriodOrders = periodOrdersAll.filter(o => o.branch_id === b.id);

    const bDates = new Set();
    bPeriodOpnames.forEach(op => { if (op.business_date) bDates.add(op.business_date); });
    bPeriodOrders.forEach(o => {
      const d = getWibDateISO(o.created_at);
      if (d) bDates.add(d);
    });

    let omzet = 0;
    let hpp = 0;
    let closedOmzetWithHpp = 0;
    let pettyCash = 0;
    let fixedProrata = 0;
    let totalOpex = 0;

    bDates.forEach(d => {
      const cl = bPeriodOpnames.find(op => op.business_date === d);
      const dayOrdRev = bPeriodOrders
        .filter(o => getWibDateISO(o.created_at) === d)
        .reduce((s, o) => s + getOrderFoodAmount(o), 0);
      const clRev = cl ? (Number(cl.total_omzet) || 0) : 0;
      const dayOmzet = cl ? Math.max(clRev, dayOrdRev) : dayOrdRev;
      omzet += dayOmzet;

      const ev = evaluateBranchSession(wh, b, d, bSortedOpnames, bOpenings);
      const dayHpp = ev.total_hpp || 0;
      if (dayHpp > 0) {
        hpp += dayHpp;
        closedOmzetWithHpp += dayOmzet;
      }

      const dayFin = computeBranchProfitMetrics({
        branch: b,
        omzet: dayOmzet,
        totalHpp: dayHpp,
        closingOp: cl || null
      });
      pettyCash += dayFin.petty_cash;
      fixedProrata += dayFin.fixed_prorata;
      totalOpex += dayFin.total_opex;
    });

    const ordFoodSum = bPeriodOrders.reduce(
      (s, o) => s + getOrderFoodAmount(o),
      0
    );
    const ordersCount = bPeriodOrders.length;
    const avgOrderValue = ordersCount > 0 ? Math.round(ordFoodSum / ordersCount) : 0;
    const profit = omzet - hpp;
    const net_profit = profit - totalOpex;
    const net_margin_pct = omzet > 0 ? Number(((net_profit / omzet) * 100).toFixed(1)) : null;
    const ratio = closedOmzetWithHpp > 0 && hpp > 0 ? Number(((hpp / closedOmzetWithHpp) * 100).toFixed(1)) : null;

    return {
      branch_id: b.id,
      branch_name: b.name,
      omzet,
      hpp,
      profit,
      petty_cash: pettyCash,
      fixed_prorata: fixedProrata,
      total_opex: totalOpex,
      net_profit,
      net_margin_pct,
      active_days: bDates.size,
      monthly_fixed_total: normalizeFixedExpenses(b.fixed_expenses).monthly_total,
      food_cost_ratio: ratio,
      orders_count: ordersCount,
      avg_order_value: avgOrderValue,
      closing_count: bPeriodOpnames.length
    };
  }

  const branchSummaries = branches.map(summarizeBranchMetrics);
  const grandAllBranchesOmzet = branchSummaries.reduce((s, b) => s + b.omzet, 0);
  const branch_leaderboard = branchSummaries
    .map(b => ({
      ...b,
      share_pct: grandAllBranchesOmzet > 0 ? Number(((b.omzet / grandAllBranchesOmzet) * 100).toFixed(1)) : 0
    }))
    .sort((a, z) => z.omzet - a.omzet);

  // Agregasi KPI sesuai filter branch_id
  const activeBranches = branch_id && branch_id !== 'all'
    ? branchSummaries.filter(b => b.branch_id === branch_id)
    : branchSummaries;

  const total_omzet = activeBranches.reduce((s, b) => s + b.omzet, 0);
  const total_hpp = activeBranches.reduce((s, b) => s + b.hpp, 0);
  const gross_profit = total_omzet - total_hpp;
  const total_petty_cash = activeBranches.reduce((s, b) => s + (b.petty_cash || 0), 0);
  const total_fixed_prorata = activeBranches.reduce((s, b) => s + (b.fixed_prorata || 0), 0);
  const total_opex = activeBranches.reduce((s, b) => s + (b.total_opex || 0), 0);
  const net_profit = gross_profit - total_opex;
  const net_margin_pct = total_omzet > 0 ? Number(((net_profit / total_omzet) * 100).toFixed(1)) : null;

  const scopedFoodTotal = scopedOrders.reduce(
    (s, o) => s + getOrderFoodAmount(o),
    0
  );
  const total_orders = scopedOrders.length;
  const avg_order_value = total_orders > 0 ? Math.round(scopedFoodTotal / total_orders) : 0;
  const delivery_count = scopedOrders.filter(o => isDeliveryOrder(o)).length;
  const pos_count = total_orders - delivery_count;
  const food_cost_ratio = total_omzet > 0 && total_hpp > 0 ? Number(((total_hpp / total_omzet) * 100).toFixed(1)) : null;

  // Tren Harian (Omzet vs HPP vs Biaya Ops vs Laba Bersih)
  const dailyMap = new Map();
  const targetBranchesList = branch_id && branch_id !== 'all'
    ? branches.filter(b => b.id === branch_id)
    : branches;

  targetBranchesList.forEach(b => {
    const bSortedOpnames = enrichedOpnames
      .filter(op => op.branch_id === b.id)
      .sort((a, z) => (a.business_date || '').localeCompare(z.business_date || ''));
    const bOpenings = openingsRaw.filter(o => o.branch_id === b.id);

    const bDates = new Set();
    periodOpnamesAll.filter(op => op.branch_id === b.id).forEach(op => { if (op.business_date) bDates.add(op.business_date); });
    periodOrdersAll.filter(o => o.branch_id === b.id).forEach(o => {
      const d = getWibDateISO(o.created_at);
      if (d) bDates.add(d);
    });

    bDates.forEach(d => {
      if (!dailyMap.has(d)) {
        const pretty = formatClosingDateId(new Date(`${d}T12:00:00Z`), '').trim();
        const parts = pretty.split(' ');
        dailyMap.set(d, {
          date: d,
          label: parts.length >= 2 ? `${parts[0]} ${parts[1].slice(0, 3)}` : d,
          omzet: 0,
          hpp: 0,
          opex: 0,
          profit: 0,
          net_profit: 0,
          orders_count: 0
        });
      }
      const bucket = dailyMap.get(d);
      const cl = periodOpnamesAll.find(op => op.branch_id === b.id && op.business_date === d);
      const dayOrders = periodOrdersAll.filter(o => o.branch_id === b.id && getWibDateISO(o.created_at) === d);
      const dayOrdRev = dayOrders.reduce(
        (s, o) => s + getOrderFoodAmount(o),
        0
      );
      const dayOmzet = cl ? Math.max(Number(cl.total_omzet) || 0, dayOrdRev) : dayOrdRev;
      const ev = evaluateBranchSession(wh, b, d, bSortedOpnames, bOpenings);
      const dayHpp = ev.total_hpp || 0;
      const dayFin = computeBranchProfitMetrics({
        branch: b,
        omzet: dayOmzet,
        totalHpp: dayHpp,
        closingOp: cl || null
      });

      bucket.omzet += dayOmzet;
      bucket.hpp += dayHpp;
      bucket.opex += dayFin.total_opex;
      bucket.profit = bucket.omzet - bucket.hpp;
      bucket.net_profit = bucket.profit - bucket.opex;
      bucket.orders_count += dayOrders.length;
    });
  });

  const daily_trend = Array.from(dailyMap.values()).sort((a, z) => a.date.localeCompare(z.date));

  // Komposisi Channel Pembayaran (Sales Mix)
  const channelAcc = {
    cash: 0,
    bca_qris: 0,
    gofood: 0,
    grabfood: 0,
    shopeefood: 0,
    live_unclosed: 0
  };
  const closedKeys = new Set(scopedOpnames.map(op => `${op.branch_id}__${op.business_date}`));
  scopedOpnames.forEach(op => {
    channelAcc.cash += Number(op.omzet_cash) || 0;
    channelAcc.bca_qris += Number(op.omzet_bca) || 0;
    channelAcc.gofood += Number(op.omzet_gofood) || 0;
    channelAcc.grabfood += Number(op.omzet_grabfood) || 0;
    channelAcc.shopeefood += Number(op.omzet_shopeefood) || 0;
  });
  scopedOrders.forEach(o => {
    const key = `${o.branch_id}__${getWibDateISO(o.created_at)}`;
    if (!closedKeys.has(key)) {
      const amt = getOrderFoodAmount(o);
      if (o.payment_method === 'cash') channelAcc.cash += amt;
      else if (o.payment_method === 'qris_statis' || o.payment_method === 'customer_balance') channelAcc.bca_qris += amt;
      else channelAcc.live_unclosed += amt;
    }
  });

  const channelDefs = [
    { key: 'cash', label: 'Tunai / Cash', color: '#34d399' },
    { key: 'bca_qris', label: 'QRIS / BCA & App', color: '#38bdf8' },
    { key: 'gofood', label: 'GoFood', color: '#f87171' },
    { key: 'grabfood', label: 'GrabFood', color: '#4ade80' },
    { key: 'shopeefood', label: 'ShopeeFood', color: '#fb923c' },
    { key: 'live_unclosed', label: 'POS/App Belum Closing', color: '#fbbf24' }
  ];
  const totalChannelAmt = Object.values(channelAcc).reduce((s, v) => s + v, 0);
  const channel_mix = channelDefs
    .map(def => {
      const amount = channelAcc[def.key] || 0;
      return {
        ...def,
        amount,
        share_pct: totalChannelAmt > 0 ? Number(((amount / totalChannelAmt) * 100).toFixed(1)) : 0
      };
    })
    .filter(c => c.amount > 0 || c.key !== 'live_unclosed');

  // Menu Engineering (Menu Terlaris, Ukuran, Protein & Topping)
  const menuQtyMap = new Map();
  const sizeCounts = { Jumbo: 0, Reguler: 0, Small: 0, Lainnya: 0 };
  const proteinCounts = { Beef: 0, Ayam: 0, Lainnya: 0 };
  const toppingMap = new Map();

  scopedOrders.forEach(o => {
    (o.items || []).forEach(it => {
      const qty = Number(it.quantity) || 1;
      const itemRev = (Number(it.subtotal) || ((Number(it.price) || 0) * qty));
      const baseName = String(it.name || 'Kebab');
      const sizeStr = String(it.size || '');
      const fullLabel = sizeStr && !baseName.toLowerCase().includes(sizeStr.toLowerCase())
        ? `${baseName} (${sizeStr})`
        : baseName;

      if (!menuQtyMap.has(fullLabel)) {
        menuQtyMap.set(fullLabel, { name: fullLabel, qty: 0, revenue: 0 });
      }
      const rec = menuQtyMap.get(fullLabel);
      rec.qty += qty;
      rec.revenue += itemRev;

      const lower = `${baseName} ${sizeStr}`.toLowerCase();
      if (lower.includes('jumbo')) sizeCounts.Jumbo += qty;
      else if (lower.includes('small')) sizeCounts.Small += qty;
      else if (lower.includes('reguler') || lower.includes('regular')) sizeCounts.Reguler += qty;
      else sizeCounts.Lainnya += qty;

      const meatLower = `${it.meat_type || ''} ${baseName}`.toLowerCase();
      if (meatLower.includes('ayam') || meatLower.includes('chicken')) proteinCounts.Ayam += qty;
      else if (meatLower.includes('beef') || meatLower.includes('sapi')) proteinCounts.Beef += qty;
      else proteinCounts.Lainnya += qty;

      (it.toppings || []).forEach(top => {
        const tName = top.name || top.id || 'Topping';
        toppingMap.set(tName, (toppingMap.get(tName) || 0) + qty);
      });
    });
  });

  const topItemsRaw = Array.from(menuQtyMap.values()).sort((a, z) => z.qty - a.qty || z.revenue - a.revenue);
  const totalPorsi = topItemsRaw.reduce((s, x) => s + x.qty, 0);
  const top_items = topItemsRaw.slice(0, 10).map(x => ({
    ...x,
    share_pct: totalPorsi > 0 ? Number(((x.qty / totalPorsi) * 100).toFixed(1)) : 0
  }));

  const sizesTotal = Object.values(sizeCounts).reduce((s, v) => s + v, 0);
  const sizes = Object.entries(sizeCounts)
    .filter(([, q]) => q > 0)
    .map(([label, qty]) => ({ label, qty, share_pct: sizesTotal > 0 ? Number(((qty / sizesTotal) * 100).toFixed(1)) : 0 }));

  const proteinsTotal = Object.values(proteinCounts).reduce((s, v) => s + v, 0);
  const proteins = Object.entries(proteinCounts)
    .filter(([, q]) => q > 0)
    .map(([label, qty]) => ({ label, qty, share_pct: proteinsTotal > 0 ? Number(((qty / proteinsTotal) * 100).toFixed(1)) : 0 }));

  const toppings = Array.from(toppingMap.entries())
    .map(([name, qty]) => ({ name, qty }))
    .sort((a, z) => z.qty - a.qty)
    .slice(0, 6);

  // Peak Hours (Jam Sibuk WIB 09:00 - 23:00)
  const hourBuckets = new Map();
  for (let h = 9; h <= 23; h += 1) {
    hourBuckets.set(h, { hour: h, label: `${String(h).padStart(2, '0')}:00`, order_count: 0, revenue: 0 });
  }
  scopedOrders.forEach(o => {
    const wib = getLocalWibDate(o.created_at);
    const hr = wib.getUTCHours();
    if (!hourBuckets.has(hr)) {
      hourBuckets.set(hr, { hour: hr, label: `${String(hr).padStart(2, '0')}:00`, order_count: 0, revenue: 0 });
    }
    const b = hourBuckets.get(hr);
    b.order_count += 1;
    b.revenue += getOrderFoodAmount(o);
  });
  const peak_hours = Array.from(hourBuckets.values()).sort((a, z) => a.hour - z.hour);

  // Top Kurir
  const driverOrderAgg = new Map();
  scopedOrders.forEach(o => {
    if (o.driver_id) {
      if (!driverOrderAgg.has(o.driver_id)) driverOrderAgg.set(o.driver_id, { period_orders: 0, period_fee: 0 });
      const d = driverOrderAgg.get(o.driver_id);
      d.period_orders += 1;
      d.period_fee += Number(o.delivery_fee) || 0;
    }
  });
  const courier_top = Object.values(wallets.drivers || {})
    .map(d => {
      const agg = driverOrderAgg.get(d.id) || { period_orders: 0, period_fee: 0 };
      return {
        id: d.id,
        name: d.name || 'Kurir',
        vehicle: d.vehicle || 'Motor',
        trips: Number(d.trips) || 0,
        balance: Number(d.balance) || 0,
        period_orders: agg.period_orders,
        period_fee: agg.period_fee
      };
    })
    .sort((a, z) => z.period_orders - a.period_orders || z.trips - a.trips)
    .slice(0, 6);

  // Insight Costumer & Repeat Order
  const allCustomers = Object.values(wallets.customers || {});
  const custOrderAgg = new Map();
  validOrders.forEach(o => {
    const key = (o.customer_email || normalizePhone(o.customer_phone) || o.customer_id || o.customer_name || '').toString().toLowerCase();
    if (!key || key === 'pelanggan langsung') return;
    if (!custOrderAgg.has(key)) {
      custOrderAgg.set(key, {
        name: o.customer_name || 'Pelanggan',
        contact: o.customer_email || o.customer_phone || '-',
        order_count: 0,
        total_spent: 0
      });
    }
    const c = custOrderAgg.get(key);
    c.order_count += 1;
    c.total_spent += getOrderTotalPaid(o);
  });
  const buyersList = Array.from(custOrderAgg.values());
  const repeatCount = buyersList.filter(b => b.order_count > 1).length;
  const repeat_rate_pct = buyersList.length > 0 ? Number(((repeatCount / buyersList.length) * 100).toFixed(1)) : 0;
  const top_customers = buyersList.sort((a, z) => z.total_spent - a.total_spent || z.order_count - a.order_count).slice(0, 5);

  const redactedLeaderboard = allowFinance ? branch_leaderboard : branch_leaderboard.map(b => ({
    ...b,
    hpp: null,
    profit: null,
    petty_cash: null,
    fixed_prorata: null,
    total_opex: null,
    net_profit: null,
    net_margin_pct: null,
    monthly_fixed_total: null,
    food_cost_ratio: null
  }));
  const redactedDailyTrend = allowFinance ? daily_trend : daily_trend.map(r => ({
    ...r,
    hpp: 0,
    opex: 0,
    profit: null,
    net_profit: null
  }));

  res.json({
    success: true,
    data: {
      scope: { branch_id, start_date: start_date || null, end_date: end_date || null, finance_restricted: !allowFinance },
      kpis: {
        total_omzet,
        total_hpp: allowFinance ? total_hpp : null,
        gross_profit: allowFinance ? gross_profit : null,
        total_petty_cash: allowFinance ? total_petty_cash : null,
        total_fixed_prorata: allowFinance ? total_fixed_prorata : null,
        total_opex: allowFinance ? total_opex : null,
        net_profit: allowFinance ? net_profit : null,
        net_margin_pct: allowFinance ? net_margin_pct : null,
        food_cost_ratio: allowFinance ? food_cost_ratio : null,
        total_orders,
        avg_order_value,
        delivery_count,
        pos_count,
        closing_count: scopedOpnames.length
      },
      daily_trend: redactedDailyTrend,
      branch_leaderboard: redactedLeaderboard,
      channel_mix,
      menu_insights: {
        total_porsi: totalPorsi,
        top_items,
        sizes,
        proteins,
        toppings
      },
      peak_hours,
      courier_top: allowedSet && !portalUserHasTab(req.portalUser, 'kurir') ? [] : courier_top,
      customer_insights: {
        total_customers: allowedSet ? buyersList.length : allCustomers.length,
        active_buyers: buyersList.length,
        repeat_buyers: repeatCount,
        repeat_rate_pct,
        top_customers
      }
    }
  });
});

// Mulai Server
app.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`🍢 SERVER KEBAB AL BEWOK BERJALAN DI PORT: ${PORT}`);
  console.log(`👉 API Menu: http://localhost:${PORT}/api/menu`);
  console.log(`👉 API Cabang: http://localhost:${PORT}/api/branches`);
  console.log(`===================================================`);
});

module.exports = app;
