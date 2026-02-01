require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto'); // Built-in Node module

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-admin-secret', 'x-nervus-key', 'x-access-key', 'x-user-token']
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
    sorteios: process.env.RAYO_SECRET_SORTEIOS
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
        image: "https://i.imgur.com/example.png",
        description: "Descrição do prêmio aqui.",
        roomId: "0"
    },
    lcdText: "Participe do sorteio agora! * Boa sorte a todos! *",
    participants: new Set(), // Set<username>
    winner: null,
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
    createdAt: { type: Date, default: Date.now }
}));
const Template = mongoose.model('Template', new mongoose.Schema({ id: String, profileId: String, title: String, text: String, image: String, link: String }));
const ScheduledMessage = mongoose.model('ScheduledMessage', new mongoose.Schema({ id: { type: String, unique: true }, creatorId: String, timestamp: Number, payload: Object, status: { type: String, default: 'pending' } }));
const GlobalMessage = mongoose.model('GlobalMessage', new mongoose.Schema({ id: { type: String, unique: true }, senderName: String, senderAvatar: String, messageText: String, bodyImage: String, bodyLink: String, createdAt: { type: Date, default: Date.now } }));
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

// --- OUTRAS ROTAS ---
app.post('/profiles/request', async (req, res) => { try { await Profile.create({ id: Date.now().toString(), ...req.body, status: 'pending', isAdmin: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/profiles/active', async (req, res) => { const p = await Profile.find({ status: 'active' }).sort({ createdAt: -1 }); res.json(p.map(x => ({ id: x.id, name: x.name, avatar: x.avatar }))); });
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

app.post('/profiles/login', async (req, res) => { const p = await Profile.findOne({ id: req.body.id, password: req.body.password, status: 'active' }); if (p) res.json({ success: true, isAdmin: p.isAdmin }); else res.status(403).json({ error: "Inválido" }); });

app.get('/nervus/profiles', async (req, res) => { if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Negado" }); const l = await Profile.find().sort({ status: -1 }); res.json(l); });
app.post('/nervus/approve/:id', async (req, res) => { if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Negado" }); await Profile.updateOne({ id: req.params.id }, { status: 'active' }); res.json({ success: true }); });
app.post('/nervus/toggle-admin/:id', async (req, res) => {
    if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Senha errada" });
    const p = await Profile.findOne({ id: req.params.id });
    if (p) { p.isAdmin = !p.isAdmin; await p.save(); }
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
app.delete('/nervus/delete/:id', async (req, res) => { if (req.headers['x-nervus-key'] !== KEYS.nervus) return res.status(403).json({ error: "Negado" }); await Profile.deleteOne({ id: req.params.id }); res.json({ success: true }); });

app.get('/templates/:pid', async (req, res) => { const t = await Template.find({ profileId: req.params.pid }).sort({ _id: -1 }); res.json(t); });
app.post('/templates', async (req, res) => { await Template.create({ id: Date.now().toString(), ...req.body }); res.json({ success: true }); });
app.delete('/templates/:id', async (req, res) => { await Template.deleteOne({ id: req.params.id }); res.json({ success: true }); });

app.get('/schedules', async (req, res) => { const s = await ScheduledMessage.find().sort({ timestamp: 1 }); res.json(s); });
app.post('/schedule', async (req, res) => { await ScheduledMessage.create({ id: Date.now().toString(), ...req.body }); res.json({ success: true }); });
app.delete('/schedule/:id', async (req, res) => { await ScheduledMessage.deleteOne({ id: req.params.id }); res.json({ success: true }); });
app.put('/schedule/:id', async (req, res) => { await ScheduledMessage.updateOne({ id: req.params.id }, { status: req.body.status }); res.json({ success: true }); });

app.post('/admin/global-message', async (req, res) => { if (req.headers['x-admin-secret'] !== ADMIN_SECRET && req.headers['x-admin-secret'] !== KEYS.nervus) return res.status(403).json({ error: "Senha errada" }); await GlobalMessage.create({ id: Date.now().toString(), ...req.body }); res.json({ success: true }); });
app.get('/global-messages', async (req, res) => { const m = await GlobalMessage.find().sort({ createdAt: -1 }).limit(20); res.json(m); });

// --- RAYOLIFE ROUTES ---
app.get('/posts', async (req, res) => {
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
app.post('/posts', verifyToken, async (req, res) => {
    try {
        const { user, url, caption } = req.body;

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
    // Light endpoint: Just update timestamp
    const { user } = req.body;
    if (user) {
        ONLINE_USERS.set(user, Date.now());
    }
    res.sendStatus(200);
});

app.get('/admin/online-count', (req, res) => {
    // Public or Admin-only? Requirement implies checking from admin panel.
    // If strict admin, verify header. For now, public stats is low risk.
    // But let's check header if possible, or leave open if index.html is static.
    // Given the context, we'll leave it open or check rayolife key.
    // Checking key for safety.
    // if (req.headers['x-admin-secret'] !== KEYS.rayolife) ... (Optional)

    const now = Date.now();
    const threshold = now - 60000; // 1 minute
    let count = 0;

    // Prune and Count
    for (const [user, lastSeen] of ONLINE_USERS.entries()) {
        if (lastSeen > threshold) {
            count++;
        } else {
            ONLINE_USERS.delete(user); // Cleanup
        }
    }

    res.json({ count });
});

// --- SORTEIOS ROUTES ---

// 1. PUBLIC STATUS (Polling)
app.get('/sorteio/status', (req, res) => {
    res.json({
        active: SORTEIO.active,
        state: SORTEIO.state,
        prize: SORTEIO.prize,
        lcdText: SORTEIO.lcdText,
        participantCount: SORTEIO.participants.size,
        // Only send winner if finished
        winner: SORTEIO.state === 'FINISHED' ? SORTEIO.winner : null,
        // If Spinning, clients need the list to animate. 
        participantsList: (SORTEIO.state === 'SPINNING') ? Array.from(SORTEIO.participants) : []
    });
});

// 2. JOIN/LEAVE (User)
app.post('/sorteio/join', verifyToken, (req, res) => {
    if (!SORTEIO.active || SORTEIO.state !== 'REGISTRATION') {
        return res.status(400).json({ error: "Inscrições fechadas." });
    }
    const user = req.authUser;
    if (SORTEIO.participants.has(user)) {
        SORTEIO.participants.delete(user); // Output: Toggles participation
        return res.json({ joined: false, count: SORTEIO.participants.size });
    } else {
        SORTEIO.participants.add(user);
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
        const pool = Array.from(SORTEIO.participants);
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
    res.json({ list: Array.from(SORTEIO.participants) });
});

app.listen(PORT, () => console.log(`🔥 Server v28 (Ban Guard) rodando na porta ${PORT}`));