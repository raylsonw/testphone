require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto'); // Built-in Node module

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-admin-secret', 'x-nervus-key', 'x-access-key', 'x-user-token', 'x-profile-id']
}));

app.use(express.json());

const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI;

// SENHAS
// SENHAS (SECURITY UPDATE: Using Env Vars)
const KEYS = {
    ifood: process.env.RAYO_SECRET_IFOOD,
    rayolife: process.env.RAYO_SECRET_RAYOLIFE,
    nervus: process.env.RAYO_SECRET_NERVUS,
    sorteios: process.env.RAYO_SECRET_SORTEIOS,
    moda: process.env.RAYO_SECRET_MODA // New Key for RayoWear
};
const ADMIN_SECRET = process.env.RAYO_ADMIN_SECRET;

// VALIDAÇÃO DE SEGURANÇA NA INICIALIZAÇÃO
if (!KEYS.ifood || !KEYS.rayolife || !KEYS.nervus || !ADMIN_SECRET) {
    console.warn("⚠️ ALERTA DE SEGURANÇA: Algumas chaves de ambiente (.env) não foram definidas!");
    console.warn("   O sistema pode não funcionar corretamente ou ficar vulnerável.");
    console.warn("   Verifique: RAYO_SECRET_IFOOD, RAYO_SECRET_RAYOLIFE, RAYO_SECRET_NERVUS, RAYO_ADMIN_SECRET");
}

// Simple In-Memory Token Store (limpa ao reiniciar server, mas ok para MVP)
// Map<token, { user: string, expires: number }>
const ACTIVE_SESSIONS = new Map();

// Map<username, lastSeenTimestamp>
const ONLINE_USERS = new Map();

// --- SORTEIOS SYSTEM STATE (In-Memory) ---
let SORTEIO = {
    active: false,        // If false, shows "Sistema fora do ar"
    state: 'REGISTRATION', // REGISTRATION | SPINNING | FINISHED
    prize: {
        name: "Prêmio Surpresa",
        image: "https://i.imgur.com/6buUpBc.png",
        description: "Descrição do prêmio aqui.",
        roomId: "0"
    },
    lcdText: "Participe do sorteio agora! * Boa sorte a todos! *",
    participants: new Map(), // Map<username, figure>
    winner: null,
    winnerFigure: null, // Store winner figure separately to persist even if map clears (optional)
    spinDuration: 10000 // ms
};

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function verifyToken(req, res, next) {
    const token = req.headers['x-user-token'];
    if (!token || !ACTIVE_SESSIONS.has(token)) {
        return res.status(403).json({ error: "Sessão inválida ou expirada. Bloqueando tela..." });
    }
    const session = ACTIVE_SESSIONS.get(token);
    // Verificar se o usuário da requisição bate com o do token (Spoofing Check)
    // Para rotas genéricas que usam req.body.user:
    if (req.body && req.body.user && req.body.user !== session.user) {
        return res.status(403).json({ error: "Tentativa de Impersonation detectada." });
    }

    // Injeta user validado no req
    req.authUser = session.user;
    next();
}

// MONGO
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Conectado!'))
    .catch(err => console.error('❌ Erro Mongo:', err));

// SCHEMAS
const Profile = mongoose.model('Profile', new mongoose.Schema({
    id: { type: String, unique: true },
    name: String,
    avatar: String,
    password: { type: String, required: false }, // Mantendo legado caso precise
    patternHash: { type: String }, // SHA-256 do pattern (ex: "1-2-3-4")
    status: { type: String, default: 'pending' },
    isAdmin: { type: Boolean, default: false },
    tokens: { type: Number, default: 0 }, // Token System
    priority: { type: Number, default: 0 }, // 0=Normal, 1=High (Top & Undelteable)
    createdAt: { type: Date, default: Date.now }
}));

// CONFIG GLOBAL
const SystemConfig = mongoose.model('SystemConfig', new mongoose.Schema({
    key: { type: String, unique: true },
    value: { type: mongoose.Schema.Types.Mixed }
}));

const MIN_CLIENT_VERSION = '3.0.0'; // Deve corresponder ao manifest.json
const DOWNLOAD_URL = "https://chromewebstore.google.com/detail/rayophone-pro/afckimmlpgohdjilceiecmgfijckhbij"; // URL de download/suporte

// IN-MEMORY STATE (Sync with DB on init)
let SYSTEM_STATUS = { rayolife: true };

// Sync Function
async function loadSystemConfig() {
    try {
        const conf = await SystemConfig.findOne({ key: 'rayolife_status' });
        if (conf && conf.value) SYSTEM_STATUS.rayolife = conf.value.active;
        else {
            // Default Create
            await SystemConfig.create({ key: 'rayolife_status', value: { active: true } });
            SYSTEM_STATUS.rayolife = true;
        }
        console.log("⚙️ SYSTEM STATUS LOADED:", SYSTEM_STATUS);
    } catch (e) { console.error("Error loading config:", e); }
}
mongoose.connection.once('open', loadSystemConfig);


function checkRayoLifeStatus(req, res, next) {
    // Admin bypass (optional, using secret header)
    if (req.headers['x-admin-secret'] === ADMIN_SECRET || req.headers['x-admin-secret'] === KEYS.rayolife) return next();

    if (!SYSTEM_STATUS.rayolife) {
        return res.status(503).json({ error: "RayoLife está em manutenção no momento. Volte em breve! 🚧" });
    }
    next();
}
const Template = mongoose.model('Template', new mongoose.Schema({ id: String, profileId: String, title: String, text: String, image: String, link: String }));
const ScheduledMessage = mongoose.model('ScheduledMessage', new mongoose.Schema({ id: { type: String, unique: true }, creatorId: String, timestamp: Number, payload: Object, status: { type: String, default: 'pending' } }));
const GlobalMessage = mongoose.model('GlobalMessage', new mongoose.Schema({ id: { type: String, unique: true }, senderName: String, senderAvatar: String, messageText: String, bodyImage: String, bodyLink: String, createdAt: { type: Date, default: Date.now } }));
const GlobalMessageLog = mongoose.model('GlobalMessageLog', new mongoose.Schema({
    id: String,
    senderName: String,
    messageText: String,
    bodyImage: String,
    bodyLink: String,
    originalCreatedAt: Date,
    action: { type: String, default: 'sent' }, // 'sent', 'cleared'
    loggedAt: { type: Date, default: Date.now }
}));
const Restaurant = mongoose.model('Restaurant', new mongoose.Schema({ id: String, name: String, image: String, banner: String, description: String, deliveryFee: Number }));

const FoodItem = mongoose.model('FoodItem', new mongoose.Schema({ id: String, restaurantId: String, name: String, image: String, description: String, price: Number, handitemId: Number }));
const Post = mongoose.model('Post', new mongoose.Schema({
    id: String,
    user: String,
    url: String,
    caption: String,
    likes: { type: Number, default: 0 },
    likedBy: { type: [String], default: [] },
    status: { type: String, default: 'active' }, // active, pending
    pinned: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
}));
const BannedUser = mongoose.model('BannedUser', new mongoose.Schema({ user: String }));
const OfficialAccount = mongoose.model('OfficialAccount', new mongoose.Schema({ user: String, avatar: String }));
const RayoWearCategory = mongoose.model('RayoWearCategory', new mongoose.Schema({ id: String, name: String, icon: String, banner: String, order: { type: Number, default: 0 } }));
const RayoWearItem = mongoose.model('RayoWearItem', new mongoose.Schema({
    id: String, name: String, price: Number, oldPrice: Number, look: String,
    discount: String, tags: [String], categoryIds: [String],
    description: String, seller: String
}));
const RayoWearPurchase = mongoose.model('RayoWearPurchase', new mongoose.Schema({
    username: String, itemId: String, date: { type: Date, default: Date.now }
}));

// SOCIAL GROUPS SCHEMA
const Group = mongoose.model('Group', new mongoose.Schema({
    id: { type: String, unique: true }, // group_TIMESTAMP_RANDOM
    name: String,
    owner: String, // User ID of the creator/admin
    members: [String], // Array of User IDs
    image: { type: String, default: "https://i.imgur.com/a4AWfCY.png" },
    createdAt: { type: Date, default: Date.now }
}));

const UserSettings = mongoose.model('UserSettings', new mongoose.Schema({
    user: { type: String, unique: true },
    mutedUsers: { type: [String], default: [] },
    following: { type: [String], default: [] }
}));

// ... (skipping unchanged lines) ...

app.get('/admin/officials', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" });
    const o = await OfficialAccount.find();
    // Retorna objeto completo { user, avatar }
    res.json(o);
});

app.post('/admin/official', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" });
    // Salva user e avatar
    await OfficialAccount.create({ user: req.body.user, avatar: req.body.avatar || "" });
    res.json({ success: true });
});

// NOVA ROTA: Atualizar Avatar de um Oficial
app.put('/admin/official/:user', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" });
    await OfficialAccount.updateOne({ user: req.params.user }, { avatar: req.body.avatar });
    res.json({ success: true });
});

app.delete('/admin/official/:user', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" });
    await OfficialAccount.deleteOne({ user: req.params.user });
    res.json({ success: true });
});

app.delete('/admin/user-content/:user', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await Post.deleteMany({ user: req.params.user }); res.json({ success: true }); });

// PUBLIC OFFICIALS CHECK
app.get('/check-official/:user', async (req, res) => { const o = await OfficialAccount.findOne({ user: req.params.user }); res.json({ isOfficial: !!o }); });
app.get('/officials', async (req, res) => {
    const o = await OfficialAccount.find();
    // Retorna lista com avatar também
    res.json(o);
});

// CRON JOB (SCHEDULER)
setInterval(async () => {
    try {
        const now = Date.now();
        const pending = await ScheduledMessage.find({ status: 'pending', timestamp: { $lte: now } });
        for (const msg of pending) {
            await GlobalMessage.create({ id: Date.now().toString() + Math.random().toString().slice(2, 5), ...msg.payload, createdAt: new Date() });
            msg.status = 'sent'; await msg.save();
        }
    } catch (e) { console.error("Cron Error:", e); }
}, 30000);

// --- ROTAS IFOOD ---
app.get('/ifood/data', async (req, res) => { const r = await Restaurant.find(); const i = await FoodItem.find(); res.json({ restaurants: r, items: i }); });
app.post('/ifood/restaurant', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.ifood) return res.status(403).json({ error: "Senha errada" }); await Restaurant.create({ id: Date.now().toString(), ...req.body }); res.json({ success: true }); });
app.put('/ifood/restaurant/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.ifood) return res.status(403).json({ error: "Senha errada" }); await Restaurant.updateOne({ id: req.params.id }, req.body); res.json({ success: true }); });
app.delete('/ifood/restaurant/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.ifood) return res.status(403).json({ error: "Senha errada" }); await Restaurant.deleteOne({ id: req.params.id }); await FoodItem.deleteMany({ restaurantId: req.params.id }); res.json({ success: true }); });
app.post('/ifood/item', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.ifood) return res.status(403).json({ error: "Senha errada" }); await FoodItem.create({ id: Date.now().toString(), ...req.body }); res.json({ success: true }); });
app.put('/ifood/item/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.ifood) return res.status(403).json({ error: "Senha errada" }); await FoodItem.updateOne({ id: req.params.id }, req.body); res.json({ success: true }); });
app.delete('/ifood/item/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.ifood) return res.status(403).json({ error: "Senha errada" }); await FoodItem.deleteOne({ id: req.params.id }); res.json({ success: true }); });

// --- RAYOWEAR ROUTES ---
app.get('/rayowear/data', async (req, res) => {
    // PUBLIC AGGREGATED ENDPOINT
    // For Home: Random 10 items? Or just all?
    // Let's return all for now, frontend handles randomization.
    const cats = await RayoWearCategory.find();
    const items = await RayoWearItem.find();
    res.json({ categories: cats, items: items });
});

app.get('/rayowear/admin/data', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.moda) return res.status(403).json({ error: "Acesso Negado" });
    const cats = await RayoWearCategory.find();
    const items = await RayoWearItem.find();
    res.json({ categories: cats, items: items });
});

app.post('/rayowear/category', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.moda) return res.status(403).json({ error: "Acesso Negado" });
    const { id, name, icon, banner, order } = req.body;
    if (id) {
        await RayoWearCategory.updateOne({ id }, { name, icon, banner, order: parseInt(order || 0) });
    } else {
        await RayoWearCategory.create({ id: Date.now().toString(), name, icon, banner, order: parseInt(order || 0) });
    }
    res.json({ success: true });
});

app.delete('/rayowear/category/:id', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.moda) return res.status(403).json({ error: "Acesso Negado" });
    await RayoWearCategory.deleteOne({ id: req.params.id });
    res.json({ success: true });
});

app.post('/rayowear/item', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.moda) return res.status(403).json({ error: "Acesso Negado" });
    // item: { id?, name, price, oldPrice, look, tags, categoryIds }
    // AUTO CALC DISCOUNT
    let { id, price, oldPrice, description, seller, ...data } = req.body;
    price = parseFloat(price);
    oldPrice = parseFloat(oldPrice);

    let discount = "";
    if (oldPrice > price) {
        const p = Math.floor(((oldPrice - price) / oldPrice) * 100);
        discount = `${p}% OFF`;
    }

    const payload = { ...data, price, oldPrice, discount, description, seller };

    if (id) {
        await RayoWearItem.updateOne({ id }, payload);
    } else {
        await RayoWearItem.create({ id: Date.now().toString(), ...payload });
    }
    res.json({ success: true });
});

// --- SOCIAL GROUPS ROUTES ---
app.post('/groups', async (req, res) => {
    try {
        const { id, name, members, image, owner } = req.body;
        if (!id || !name || !members) return res.status(400).json({ error: "Missing fields" });

        // Build Payload
        const payload = { name, members, image: image || "https://i.imgur.com/a4AWfCY.png" };
        if (owner) payload.owner = owner;

        // Upsert Group
        await Group.findOneAndUpdate(
            { id: id },
            payload,
            { upsert: true, new: true }
        );
        console.log(`[Groups] Group Synced: ${name} (${id})`);
        res.json({ success: true });
    } catch (e) {
        console.error("Group Sync Error:", e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/groups/kick', async (req, res) => {
    try {
        const { groupId, userId, requesterId } = req.body;
        if (!groupId || !userId) return res.status(400).json({ error: "Missing fields" });

        const group = await Group.findOne({ id: groupId });
        if (!group) return res.status(404).json({ error: "Group not found" });

        // SECURITY CHECK
        if (group.owner) {
            if (!requesterId || requesterId.toString() !== group.owner.toString()) {
                console.warn(`[Security] Kick blocked. Requester=${requesterId} Owner=${group.owner}`);
                return res.status(403).json({ error: "Only Admin can kick" });
            }
        }

        await Group.updateOne(
            { id: groupId },
            { $pull: { members: userId } }
        );
        console.log(`[Groups] User ${userId} KICKED from ${groupId} (by ${requesterId || 'Unknown'})`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/groups/add', async (req, res) => {
    try {
        const { groupId, userId, requesterId } = req.body;
        if (!groupId || !userId) return res.status(400).json({ error: "Missing fields" });

        const group = await Group.findOne({ id: groupId });
        if (!group) return res.status(404).json({ error: "Group not found" });

        // SECURITY CHECK
        if (group.owner) {
            if (!requesterId || requesterId.toString() !== group.owner.toString()) {
                console.warn(`[Security] Add blocked. Requester=${requesterId} Owner=${group.owner}`);
                return res.status(403).json({ error: "Only Admin can add" });
            }
        }

        if (group.members.length >= 10) return res.status(400).json({ error: "Group full" });
        if (group.members.includes(userId)) return res.json({ success: true }); // Already matched

        group.members.push(userId);
        await group.save();
        console.log(`[Groups] User ${userId} ADDED to ${groupId} (by ${requesterId || 'Unknown'})`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/groups/leave', async (req, res) => {
    try {
        const { groupId, userId } = req.body;
        if (!groupId || !userId) return res.status(400).json({ error: "Missing fields" });

        await Group.updateOne(
            { id: groupId },
            { $pull: { members: userId } }
        );
        console.log(`[Groups] Member ${userId} left ${groupId}`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/groups/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        // Find groups where members array contains userId
        const groups = await Group.find({ members: userId });
        res.json(groups);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/rayowear/buy', async (req, res) => {
    const { username, itemId } = req.body;
    if (!username || !itemId) return res.status(400).json({ error: "Dados inválidos" });

    // Check duplicate
    const exists = await RayoWearPurchase.findOne({ username, itemId });
    if (exists) return res.json({ success: true, message: "Já possui" }); // Treat as success

    await RayoWearPurchase.create({ username, itemId });
    res.json({ success: true });
});

app.get('/rayowear/inventory/:username', async (req, res) => {
    const { username } = req.params;
    const purchases = await RayoWearPurchase.find({ username });
    const itemIds = purchases.map(p => p.itemId);

    // Return full item objects
    const items = await RayoWearItem.find({ id: { $in: itemIds } });
    res.json({ items });
});

app.delete('/rayowear/inventory', async (req, res) => {
    const { username, itemId } = req.body;
    if (!username || !itemId) return res.status(400).json({ error: "Dados inválidos" });
    await RayoWearPurchase.deleteOne({ username, itemId });
    res.json({ success: true });
});

app.delete('/rayowear/item/:id', async (req, res) => {
    if (req.headers['x-admin-secret'] !== KEYS.moda) return res.status(403).json({ error: "Acesso Negado" });
    await RayoWearItem.deleteOne({ id: req.params.id });
    res.json({ success: true });
});

// --- OUTRAS ROTAS ---
app.post('/profiles/request', async (req, res) => { try { await Profile.create({ id: Date.now().toString(), ...req.body, status: 'pending', isAdmin: false, priority: 0 }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/profiles/active', async (req, res) => { const p = await Profile.find({ status: 'active' }).sort({ priority: -1, createdAt: -1 }); res.json(p.map(x => ({ id: x.id, name: x.name, avatar: x.avatar, priority: x.priority || 0 }))); });
app.get('/profiles/priorities', async (req, res) => {
    // Public endpoint for client to know who is VIP
    const p = await Profile.find({ status: 'active', priority: 1 });
    res.json(p.map(x => x.name)); // Retorna NOMES para construir ID global no front
});
// SEPARATE SCHEMA FOR PHONE AUTH (Locks, Patterns)
// This prevents polluting the main 'Profile' collection which is used for older MSGS system
const PhoneAuth = mongoose.model('PhoneAuth', new mongoose.Schema({
    user: { type: String, unique: true }, // Username (myName)
    patternHash: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
}));


// ... (Existing routes) ...


// NOVA ROTA DE AUTH (PATTERN LOCK) - UPDATED TO USE PhoneAuth
app.get('/settings/:user', verifyToken, async (req, res) => {
    try {
        const { user } = req.params;
        // Verify identity
        if (req.authUser !== user) return res.status(403).json({ error: "Acesso negado" });

        const settings = await UserSettings.findOne({ user }) || { mutedUsers: [], following: [] };
        res.json({ mutedUsers: settings.mutedUsers || [], following: settings.following || [] });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/settings/follow', verifyToken, async (req, res) => {
    try {
        const { user, target, action, pattern } = req.body;
        if (!user || !target || !action || !pattern) return res.status(400).json({ error: "Dados inválidos" });

        if (req.authUser !== user) return res.status(403).json({ error: "Acesso negado" });

        // PATTERN VALIDATION
        const hash = crypto.createHash('sha256').update(pattern).digest('hex');
        const auth = await PhoneAuth.findOne({ user });
        if (!auth || auth.patternHash !== hash) return res.status(403).json({ error: "Senha incorreta" });

        let settings = await UserSettings.findOne({ user });
        if (!settings) settings = await UserSettings.create({ user, mutedUsers: [], following: [] });

        if (!settings.following) settings.following = [];

        if (action === 'follow') {
            if (!settings.following.includes(target)) {
                settings.following.push(target);
                await settings.save();
            }
        } else if (action === 'unfollow') {
            settings.following = settings.following.filter(u => u !== target);
            await settings.save();
        }

        res.json({ success: true, following: settings.following });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/settings/mute', verifyToken, async (req, res) => {
    try {
        const { user, target, action, pattern } = req.body;
        if (!user || !target || !action || !pattern) return res.status(400).json({ error: "Dados inválidos" });

        if (req.authUser !== user) return res.status(403).json({ error: "Acesso negado" });

        // 1. RE-VALIDATE PATTERN (Security Requirement)
        const hash = crypto.createHash('sha256').update(pattern).digest('hex');
        const auth = await PhoneAuth.findOne({ user });

        if (!auth || auth.patternHash !== hash) {
            return res.status(403).json({ error: "Senha incorreta. Ação bloqueada." });
        }

        // 2. APPLY MUTE/UNMUTE
        let settings = await UserSettings.findOne({ user });
        if (!settings) settings = await UserSettings.create({ user, mutedUsers: [] });

        if (action === 'mute') {
            if (!settings.mutedUsers.includes(target)) {
                settings.mutedUsers.push(target);
                await settings.save();
            }
        } else if (action === 'unmute') {
            settings.mutedUsers = settings.mutedUsers.filter(u => u !== target);
            await settings.save();
        }

        res.json({ success: true, mutedUsers: settings.mutedUsers });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { user, pattern } = req.body;
        console.log(`🔒 [AUTH] Tentativa de login: ${user}`);

        if (!user || !pattern) return res.status(400).json({ error: "Dados incompletos" });

        // Hash do Pattern recebido
        const hash = crypto.createHash('sha256').update(pattern).digest('hex');

        // BUSCA NO MODELO ESPECÍFICO DE SEGURANÇA
        let authProfile = await PhoneAuth.findOne({ user: user });

        if (!authProfile) {
            console.log(`🔒 [AUTH] Novo registro de segurança para: ${user}`);
            // CRIAR NOVO REGISTRO DE SEGURANÇA
            authProfile = await PhoneAuth.create({
                user: user,
                patternHash: hash
            });
        } else {
            // VERIFICAR SENHA
            if (authProfile.patternHash !== hash) {
                console.log(`🔒 [AUTH] Senha incorreta para: ${user}`);
                return res.status(403).json({ error: "Senha incorreta" });
            }
            // Atualiza last login
            authProfile.lastLogin = new Date();
            await authProfile.save();
        }

        // GERA TOKEN
        console.log(`🔒 [AUTH] Sucesso. Token gerado para: ${user}`);
        const token = generateToken();
        ACTIVE_SESSIONS.set(token, { user: user, expires: Date.now() + 1000 * 60 * 60 * 24 }); // 24h

        res.json({ success: true, token, isAdmin: authProfile.isAdmin });

    } catch (e) {
        console.error("Auth Error:", e);
        res.status(500).json({ error: "Erro interno" });
    }
});

app.post('/profiles/login', async (req, res) => {
    const p = await Profile.findOne({ id: req.body.id, password: req.body.password, status: 'active' });
    if (p) res.json({ success: true, isAdmin: p.isAdmin, tokens: p.tokens || 0 }); // Retorna tokens
    else res.status(403).json({ error: "Inválido" });
});

app.get('/nervus/profiles', async (req, res) => { if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Negado" }); const l = await Profile.find().sort({ status: -1 }); res.json(l); });
app.post('/nervus/approve/:id', async (req, res) => { if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Negado" }); await Profile.updateOne({ id: req.params.id }, { status: 'active' }); res.json({ success: true }); });
app.post('/nervus/toggle-admin/:id', async (req, res) => {
    if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Senha errada" });
    const p = await Profile.findOne({ id: req.params.id });
    if (p) { p.isAdmin = !p.isAdmin; await p.save(); }
    res.json({ success: true });
});

app.post('/nervus/toggle-priority/:id', async (req, res) => {
    if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Senha errada" });
    const p = await Profile.findOne({ id: req.params.id });
    if (p) {
        p.priority = (p.priority === 1) ? 0 : 1;
        await p.save();
    }
    res.json({ success: true });
});

app.post('/nervus/update-password/:id', async (req, res) => {
    if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Senha errada" });
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "Senha vazia" });

    const p = await Profile.findOne({ id: req.params.id });
    if (p) {
        p.password = password;
        await p.save();
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "Perfil não encontrado" });
    }
});

app.post('/nervus/update-tokens/:id', async (req, res) => {
    if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Senha errada" });
    const { tokens } = req.body;
    if (tokens === undefined) return res.status(400).json({ error: "Valor inválido" });

    await Profile.updateOne({ id: req.params.id }, { tokens: parseInt(tokens) });
    res.json({ success: true });
});
app.delete('/nervus/delete/:id', async (req, res) => { if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Negado" }); await Profile.deleteOne({ id: req.params.id }); res.json({ success: true }); });

app.get('/templates/:pid', async (req, res) => { const t = await Template.find({ profileId: req.params.pid }).sort({ _id: -1 }); res.json(t); });
app.post('/templates', async (req, res) => { await Template.create({ id: Date.now().toString(), ...req.body }); res.json({ success: true }); });
app.delete('/templates/:id', async (req, res) => { await Template.deleteOne({ id: req.params.id }); res.json({ success: true }); });

app.get('/schedules', async (req, res) => { const s = await ScheduledMessage.find().sort({ timestamp: 1 }); res.json(s); });
app.post('/schedule', async (req, res) => {
    const { creatorId } = req.body;
    // Verifica Tokens
    const p = await Profile.findOne({ id: creatorId });
    if (!p) return res.status(404).json({ error: "Perfil não encontrado" });

    if (!p.isAdmin && (!p.tokens || p.tokens <= 0)) {
        return res.status(403).json({ error: "Limite de agendamentos esgotado!" });
    }

    if (!p.isAdmin) {
        p.tokens = (p.tokens || 0) - 1;
        await p.save();
    }

    await ScheduledMessage.create({ id: Date.now().toString(), ...req.body });
    res.json({ success: true, remainingTokens: p.tokens });
});
app.delete('/schedule/:id', async (req, res) => { await ScheduledMessage.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.put('/schedule/:id', async (req, res) => { await ScheduledMessage.updateOne({ id: req.params.id }, { status: req.body.status }); res.json({ success: true }); });

app.get('/admin/global-log', async (req, res) => {
    // Requires Admin Secret
    if (req.headers['x-admin-secret'] !== KEYS.rayolife && req.headers['x-admin-secret'] !== ADMIN_SECRET)
        return res.status(403).json({ error: "Acesso negado" });

    // Return last 100 logs
    const logs = await GlobalMessageLog.find().sort({ loggedAt: -1 }).limit(100);
    res.json(logs);
});

app.post('/admin/global-message', async (req, res) => {
    const secret = req.headers['x-admin-secret'];

    // 1. Tentar achar Perfil associado a este envio (se houver senderId no body? Não tem no payload original do MSGS.html)
    // O MSGS.html manda senderName, senderAvatar, etc. mas não manda o ID do perfil logado na requisição global...
    // Mas espere! O MSGS.html usa o 'x-admin-secret' que pode ser a "SENHA MESTRA GLOBAL"
    // Se for a senha mestra (ADMIN_SECRET ou KEYS.nervus), é ilimitado (DeusMode).

    // Se não for senha mestra, pode ser um "token de perfil"? Não, o sistema atual usa Password auth.
    // O novo sistema em MSGS.html quando "Logar" num perfil salva sessionStorage. 
    // Mas no `sendBroadcast` ele tenta pegar o `rayo_global_secret`.

    // Precisamos mudar isso. Para cobrar tokens, precisamos saber QUEM está mandando.
    // Vou checar se o header 'x-profile-id' foi enviado (vou adicionar isso no frontend).

    if (secret === ADMIN_SECRET || secret === KEYS.nervus) {
        // Modo Deus (Ilimitado)

        // --- LOG LOGIC ---
        await GlobalMessageLog.create({
            id: Date.now().toString(),
            senderName: req.body.senderName,
            messageText: req.body.messageText,
            bodyImage: req.body.bodyImage,
            bodyLink: req.body.bodyLink,
            action: req.body.messageText === "%clear%" ? 'clear_command' : 'sent'
        });

        // --- CLEAR LOGIC ---
        if (req.body.messageText === "%clear%") {
            // Delete ALL messages from this senderName in the LIVE collection
            await GlobalMessage.deleteMany({ senderName: req.body.senderName });
            // Create the clear message so clients sync
        }

        await GlobalMessage.create({ id: Date.now().toString(), ...req.body });
        return res.json({ success: true });
    }

    // Se não é Admin Global, tenta checar Profile ID
    const profileId = req.headers['x-profile-id'];
    const p = await Profile.findOne({ id: profileId });

    if (p) {
        // Valida se o secret bate com a senha do perfil? 
        // O frontend manda a "rayo_global_secret" que às vezes é a senha do painel, não do perfil.
        // Mas se o usuário logou no perfil, ele deveria usar as credenciais desse perfil.

        // Vamos confiar no 'x-profile-id' SE e SOMENTE SE o 'x-admin-secret' for a senha desse perfil (nova lógica)
        // OU se o MSGS.html frontend garantir que só manda se estiver logado.

        // simplificação: O sistema original confiava 100% no 'x-admin-secret' ser uma chave mestra.
        // O usuário quer limitar "perfis". 
        // Vou exigir que o frontend mande 'x-profile-id' E 'x-profile-password' no lugar do secret global se for usuário comum?
        // Ou, manter o flow e só checar o ID.

        // Como o MSGS.html funciona:
        // Ele pede Login no Perfil -> Salva auth_ID na session.
        // Na hora de enviar, ele pega o `rayo_global_secret` (que é a chave mestra) DO CACHE.
        // Se o usuário comum não tem a chave mestra, ele NÃO CONSEGUE ENVIAR nada hoje.
        // Então HOJE, só quem tem a chave Mestra envia.

        // MUDANÇA: O usuário quer que "perfis dos canais globais" (usuários comuns) usem o sistema.
        // Então eles NÃO TERÃO a chave ADMIN_SECRET. Eles terão a SENHA DO PERFIL.

        // Lógica Híbrida:
        // Se 'x-admin-secret' == p.password (do perfil ID), então deixa enviar e gasta token.

        if (p.password === secret) {
            if (!p.isAdmin && (!p.tokens || p.tokens <= 0)) {
                return res.status(403).json({ error: "Limite de mensagens esgotado!" });
            }

            // --- LOG LOGIC ---
            await GlobalMessageLog.create({
                id: Date.now().toString(),
                senderName: req.body.senderName, // Trust body or enforce p.name? Body for now.
                messageText: req.body.messageText,
                bodyImage: req.body.bodyImage,
                bodyLink: req.body.bodyLink,
                action: req.body.messageText === "%clear%" ? 'clear_command' : 'sent'
            });

            // --- CLEAR LOGIC ---
            if (req.body.messageText === "%clear%") {
                await GlobalMessage.deleteMany({ senderName: req.body.senderName });
            }

            if (!p.isAdmin) {
                p.tokens = (p.tokens || 0) - 1;
                await p.save();
            }

            await GlobalMessage.create({ id: Date.now().toString(), ...req.body });
            return res.json({ success: true, remainingTokens: p.tokens });
        }
    }

    return res.status(403).json({ error: "Senha errada ou Perfil inválido" });
});
app.get('/global-messages', async (req, res) => { const m = await GlobalMessage.find().sort({ createdAt: -1 }).limit(20); res.json(m); });

// --- RAYOLIFE ROUTES ---
app.get('/posts', checkRayoLifeStatus, async (req, res) => {
    const { q } = req.query;
    let query = { status: 'active' };

    if (q) {
        const regex = new RegExp(q, 'i');
        query.$or = [{ user: regex }, { caption: regex }];
    }

    const p = await Post.find(query).sort({ pinned: -1, createdAt: -1 });
    res.json(p);
});

// === ROTA DE POSTAGEM (AGORA COM PROTEÇÃO DE BAN) ===
// === ROTA DE POSTAGEM (PROTEGIDA POR TOKEN) ===
app.post('/posts', verifyToken, checkRayoLifeStatus, async (req, res) => {
    try {
        let { user, url, caption } = req.body;
        if (!user) user = req.authUser; // Fallback to token user (Reliable)

        // Middleware verifyToken já checou Impersonation (body.user vs token.user)
        // e já checou se user existe na sessão.

        // 1. Verifica se está banido
        const isBanned = await BannedUser.findOne({ user: user });
        if (isBanned) return res.status(403).json({ error: "Você está banido do RayoLife." });

        // 2. RATE LIMITING (Anti-Spam)
        // Máximo 2 posts por minuto
        const recentPosts = await Post.countDocuments({
            user: user,
            createdAt: { $gte: new Date(Date.now() - 60 * 1000) }
        });

        if (recentPosts >= 2) {
            return res.status(429).json({ error: "Muitas postagens! Aguarde um minuto." });
        }

        // --- SECURITY: PATTERN VALIDATION ---
        const { pattern } = req.body;
        console.log(`[POST /posts] User: ${user}`);
        console.log(`[POST /posts] Pattern: '${pattern}'`);
        if (!pattern) return res.status(403).json({ error: "Senha não fornecida. Bloqueie e desbloqueie o celular." });

        const hash = crypto.createHash('sha256').update(pattern).digest('hex');
        const auth = await PhoneAuth.findOne({ user });

        if (!auth || auth.patternHash !== hash) {
            return res.status(403).json({ error: "Senha incorreta. Ação bloqueada." });
        }
        // ------------------------------------

        if (!url) return res.status(400).json({ error: "Dados incompletos" });

        // 3. Define Status (Moderação)
        const isSafeDomain = url.startsWith("https://images.habblet.city/habblet-camera/photos/");
        const status = isSafeDomain ? 'active' : 'pending';

        // 4. Cria Post
        await Post.create({ id: Date.now().toString(), user, url, caption, likes: 0, likedBy: [], status, pinned: false });
        res.json({ success: true, status });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// === ROTA ADMIN DE POSTAGEM (BYPASS TOKEN) ===
app.post('/admin/create-post', async (req, res) => {
    // Valida Senha Admin
    if (req.headers['x-admin-secret'] !== KEYS.rayolife) {
        return res.status(403).json({ error: "Senha Admin Incorreta" });
    }

    try {
        const { user, url, caption } = req.body;
        if (!user || !url) return res.status(400).json({ error: "Dados incompletos" });

        // Admin não tem rate limit e não checa ban (ou checa mas permite? Admin é Deus)
        // Vamos checar ban só pra avisar? Não, Admin força.

        // Status sempre ACTIVE pois é ADMIN
        const status = 'active';

        await Post.create({ id: Date.now().toString(), user, url, caption, likes: 0, likedBy: [], status, pinned: false });
        res.json({ success: true, status });

    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/posts/:id/like', async (req, res) => { const p = await Post.findOne({ id: req.params.id }); if (!p) return res.status(404).json({ error: "Not found" }); let lb = p.likedBy || []; if (lb.includes(req.body.user)) return res.json({ success: true }); lb.push(req.body.user); await Post.updateOne({ id: req.params.id }, { likes: (p.likes || 0) + 1, likedBy: lb }); res.json({ success: true }); });

// ROTA USUÁRIO APAGAR O PRÓPRIO POST
app.delete('/posts/:id', async (req, res) => {
    try {
        const { user } = req.body;
        const post = await Post.findOne({ id: req.params.id });
        if (!post) return res.status(404).json({ error: "Post não encontrado" });
        if (post.user !== user) return res.status(403).json({ error: "Sem permissão" });
        await Post.deleteOne({ id: req.params.id });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- ADMIN ROUTES ---
app.delete('/admin/posts/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await Post.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.put('/admin/posts/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await Post.updateOne({ id: req.params.id }, { caption: req.body.caption }); res.json({ success: true }); });

// MODERATION
app.get('/admin/pending-posts', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); const p = await Post.find({ status: 'pending' }).sort({ createdAt: 1 }); res.json(p); });
app.post('/admin/approve/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await Post.updateOne({ id: req.params.id }, { status: 'active' }); res.json({ success: true }); });
app.post('/admin/pin/:id', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); const p = await Post.findOne({ id: req.params.id }); await Post.updateOne({ id: req.params.id }, { pinned: !p.pinned }); res.json({ success: true }); });

// USERS
app.get('/admin/banned', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); const b = await BannedUser.find(); res.json(b.map(x => x.user)); });
app.post('/admin/ban', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await BannedUser.create({ user: req.body.user }); res.json({ success: true }); });
app.delete('/admin/ban/:user', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await BannedUser.deleteOne({ user: req.params.user }); res.json({ success: true }); });

app.get('/admin/officials', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); const o = await OfficialAccount.find(); res.json(o.map(x => x.user)); });
app.post('/admin/official', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await OfficialAccount.create({ user: req.body.user }); res.json({ success: true }); });
app.delete('/admin/official/:user', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await OfficialAccount.deleteOne({ user: req.params.user }); res.json({ success: true }); });

app.delete('/admin/user-content/:user', async (req, res) => { if (req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Senha errada" }); await Post.deleteMany({ user: req.params.user }); res.json({ success: true }); });

// PUBLIC OFFICIALS CHECK
app.get('/check-official/:user', async (req, res) => { const o = await OfficialAccount.findOne({ user: req.params.user }); res.json({ isOfficial: !!o }); });
app.get('/officials', async (req, res) => { const o = await OfficialAccount.find(); res.json(o.map(x => x.user)); });

// --- ONLINE USER SYSTEM (HEARTBEAT) ---
app.post('/ping', (req, res) => {
    // Light endpoint: Update timestamp AND store figure
    const { user, figure } = req.body;
    if (user) {
        ONLINE_USERS.set(user, {
            timestamp: Date.now(),
            figure: figure || ""
        });
    }
    res.sendStatus(200);
});

app.get('/admin/online-count', (req, res) => {
    // Public or Admin-only? Requirement implies checking from admin panel.
    // If strict admin, verify header. For now, public stats is low risk.

    const now = Date.now();
    const threshold = now - 60000; // 1 minute
    let count = 0;
    const usersList = [];

    // Prune and Collect
    for (const [user, data] of ONLINE_USERS.entries()) {
        // Handle legacy data (if value is just number) or new object
        const lastSeen = (typeof data === 'number') ? data : data.timestamp;
        const figure = (typeof data === 'object') ? data.figure : "";

        if (lastSeen > threshold) {
            count++;
            usersList.push({ name: user, figure: figure, lastSeen: lastSeen });
        } else {
            ONLINE_USERS.delete(user); // Cleanup
        }
    }

    res.json({ count, users: usersList });
});

// --- SORTEIOS ROUTES ---

// 1. PUBLIC STATUS (Polling)
app.get('/sorteio/status', (req, res) => {
    // Get winner figure from Map if not stored explicitly (or if we want to ensure fresh)
    let wFigure = SORTEIO.winner && SORTEIO.participants.has(SORTEIO.winner)
        ? SORTEIO.participants.get(SORTEIO.winner)
        : null;

    res.json({
        active: SORTEIO.active,
        state: SORTEIO.state,
        prize: SORTEIO.prize,
        lcdText: SORTEIO.lcdText,
        participantCount: SORTEIO.participants.size,
        // Only send winner if finished
        winner: SORTEIO.state === 'FINISHED' ? SORTEIO.winner : null,
        winnerFigure: (SORTEIO.state === 'FINISHED') ? wFigure : null,
        // If Spinning, clients need the list to animate.
        participantsList: (SORTEIO.state === 'SPINNING') ? Array.from(SORTEIO.participants.keys()) : []
    });
});

// 2. JOIN/LEAVE (User)
app.post('/sorteio/join', verifyToken, (req, res) => {
    if (!SORTEIO.active || SORTEIO.state !== 'REGISTRATION') {
        return res.status(400).json({ error: "Inscrições fechadas." });
    }
    const user = req.authUser;
    const { figure } = req.body; // Expect figure in body

    if (SORTEIO.participants.has(user)) {
        SORTEIO.participants.delete(user); // Output: Toggles participation
        return res.json({ joined: false, count: SORTEIO.participants.size });
    } else {
        SORTEIO.participants.set(user, figure || ""); // Store figure
        return res.json({ joined: true, count: SORTEIO.participants.size });
    }
});

// 3. CHECK USER STATUS (Is Joined?)
app.get('/sorteio/check/:user', (req, res) => {
    if (!SORTEIO.active) return res.json({ joined: false });
    const isJoined = SORTEIO.participants.has(req.params.user);
    res.json({ joined: isJoined });
});


// 4. ADMIN CONFIG
app.post('/admin/sorteio/config', (req, res) => {
    // Auth Check: Requires SORTEIOS Secret
    const { secret, active, prizeName, prizeImage, prizeDesc, prizeRoomId, lcdText } = req.body;
    if (secret !== KEYS.sorteios) return res.sendStatus(403);

    if (typeof active === 'boolean') SORTEIO.active = active;
    if (prizeName) SORTEIO.prize.name = prizeName;
    if (prizeImage) SORTEIO.prize.image = prizeImage;
    if (prizeDesc) SORTEIO.prize.description = prizeDesc;
    if (prizeRoomId) SORTEIO.prize.roomId = prizeRoomId;
    if (lcdText) SORTEIO.lcdText = lcdText;

    if (active === false) {
        SORTEIO.state = 'REGISTRATION';
    }

    res.json({ success: true, apiState: SORTEIO });
});

// 5. ADMIN CONTROL (Start/Stop)
app.post('/admin/sorteio/action', (req, res) => {
    const { secret, action } = req.body;
    if (secret !== KEYS.sorteios) return res.sendStatus(403);

    if (action === 'START_SPIN') {
        if (SORTEIO.participants.size === 0) return res.status(400).json({ error: "Sem participantes." });
        SORTEIO.state = 'SPINNING';
        SORTEIO.winner = null;
    } else if (action === 'STOP_SPIN') {
        const pool = Array.from(SORTEIO.participants.keys());
        if (pool.length > 0) {
            const r = Math.floor(Math.random() * pool.length);
            SORTEIO.winner = pool[r];
            SORTEIO.state = 'FINISHED';
        } else {
            SORTEIO.state = 'REGISTRATION';
        }
    } else if (action === 'RESET') {
        SORTEIO.state = 'REGISTRATION';
        SORTEIO.winner = null;
        SORTEIO.participants.clear();
    }

    res.json({ success: true, state: SORTEIO.state, winner: SORTEIO.winner });
});

// 6. ADMIN PARTICIPANTS LIST
app.get('/admin/sorteio/participants', (req, res) => {
    // Return objects now? Or just names? Admin panel might like figures later, but for now names.
    // Actually, Admin panel had an image preview too that was using Habbo avatar.
    // Let's return list of object {name, figure} if helpful, or just strings if legacy.
    // The previous code returned array of strings.
    // BUT the admin panel in `sorteios.html` was updated to iterate and show "p-item".
    // It used `u.look`? Wait, admin panel uses "figure" or "look"?
    // Checking `sorteios.html`... It mapped `u` directly. It probably expects strings.
    // If I return simple strings, `u.look` is undefined.
    // I should upgrade this to return obbjects { name, look}

    const list = Array.from(SORTEIO.participants.entries()).map(([name, figure]) => ({ name, look: figure }));
    res.json({ list: list });
});


// --- SYSTEM ADMIN ---
app.get('/system/status', (req, res) => {
    res.json(SYSTEM_STATUS);
});

app.get('/system/version', (req, res) => {
    res.json({
        minVersion: MIN_CLIENT_VERSION,
        currentVersion: MIN_CLIENT_VERSION,
        url: DOWNLOAD_URL,
        critical: true
    });
});

app.post('/admin/system/toggle', async (req, res) => {
    // Basic Admin Secret Check (Header must match env var)
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET && req.headers['x-admin-secret'] !== KEYS.rayolife) return res.status(403).json({ error: "Access Denied" });
    const { app, active } = req.body;
    if (app === 'rayolife') {
        SYSTEM_STATUS.rayolife = active;
        // Upsert Config
        try {
            await SystemConfig.findOneAndUpdate(
                { key: 'rayolife_status' },
                { key: 'rayolife_status', value: { active } },
                { upsert: true, new: true }
            );
            console.log(`[SYSTEM] RayoLife Active: ${active}`);
            return res.json({ success: true, status: SYSTEM_STATUS });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    }
    res.status(400).json({ error: "Unknown app" });
});

app.listen(PORT, () => console.log(`🔥 Server v29 (System Lock) rodando na porta ${PORT}`));