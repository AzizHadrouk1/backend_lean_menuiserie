require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '2mb' }));

// ─── CONNEXION MONGODB ───────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error('❌ FATAL: MONGO_URI manquant dans les variables d\'environnement');
  process.exit(1);
}

mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log('✅ MongoDB connecté — lean_menuiserie'))
  .catch(err => {
    console.error('❌ Erreur MongoDB:', err.message);
    console.error('   URI utilisée (masquée):', MONGO_URI.replace(/:([^@]+)@/, ':****@'));
  });

mongoose.connection.on('error', err => console.error('❌ MongoDB runtime error:', err.message));
mongoose.connection.on('disconnected', () => console.warn('⚠️  MongoDB déconnecté — tentative reconnexion…'));
mongoose.connection.on('reconnected', () => console.log('✅ MongoDB reconnecté'));

// ─── MIDDLEWARE DB CHECK ─────────────────────────────────────────
function dbCheck(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      error: 'Base de données non disponible. Réessayez dans quelques secondes.',
      dbState: mongoose.connection.readyState
    });
  }
  next();
}

// ─── MODÈLES ────────────────────────────────────────────────────
const ResponseSchema = new mongoose.Schema({
  answers: { type: Object, required: true },
  submittedAt: { type: Date, default: Date.now },
  ip: { type: String, default: '' }
});
const Response = mongoose.model('Response', ResponseSchema);

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', AdminSchema);

// ─── MIDDLEWARE AUTH JWT ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant — accès refusé' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expirée — reconnectez-vous' });
    }
    return res.status(401).json({ error: 'Token invalide' });
  }
}

// ─── ROUTES PUBLIQUES ────────────────────────────────────────────

// Health check — indique l'état réel de la DB
app.get('/api/health', (req, res) => {
  const states = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  res.json({
    status: 'ok',
    db: states[mongoose.connection.readyState] || 'unknown',
    dbState: mongoose.connection.readyState,
    env: {
      hasMongoUri: !!process.env.MONGO_URI,
      hasJwtSecret: !!process.env.JWT_SECRET,
      port: process.env.PORT || 5000
    }
  });
});

// Soumettre une réponse (formulaire public)
app.post('/api/responses', dbCheck, async (req, res) => {
  try {
    console.log('📥 Nouvelle réponse reçue, body keys:', Object.keys(req.body || {}));

    const answers = req.body;
    if (!answers || typeof answers !== 'object' || Object.keys(answers).length === 0) {
      return res.status(400).json({ error: 'Corps de la requête vide ou invalide' });
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '';
    const doc = await Response.create({ answers, ip });

    console.log('✅ Réponse sauvegardée:', doc._id);
    res.status(201).json({ success: true, id: doc._id });
  } catch (err) {
    console.error('❌ Erreur save response:', err.name, err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la sauvegarde', detail: err.message });
  }
});

// ─── ROUTES ADMIN ────────────────────────────────────────────────

// Login admin
app.post('/api/admin/login', dbCheck, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    if (!process.env.JWT_SECRET) {
      console.error('❌ JWT_SECRET manquant');
      return res.status(500).json({ error: 'Configuration serveur incomplète' });
    }

    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin) {
      console.warn('⚠️  Tentative login avec email inconnu:', email);
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const valid = bcrypt.compareSync(password, admin.password);
    if (!valid) {
      console.warn('⚠️  Mot de passe incorrect pour:', email);
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const token = jwt.sign(
      { email: admin.email, id: admin._id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    console.log('✅ Login admin réussi:', admin.email);
    res.json({ success: true, token, email: admin.email });
  } catch (err) {
    console.error('❌ Erreur login:', err.message);
    res.status(500).json({ error: 'Erreur serveur', detail: err.message });
  }
});

// Vérifier token
app.get('/api/admin/verify', authMiddleware, (req, res) => {
  res.json({ valid: true, email: req.admin.email });
});

// Lire toutes les réponses (paginées)
app.get('/api/responses', authMiddleware, dbCheck, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const skip = (Number(page) - 1) * Number(limit);

    let query = {};
    if (search) {
      query = {
        $or: [
          { 'answers.id_nom': { $regex: search, $options: 'i' } },
          { 'answers.id_fonction': { $regex: search, $options: 'i' } },
          { 'answers.id_service': { $regex: search, $options: 'i' } }
        ]
      };
    }

    const [data, total] = await Promise.all([
      Response.find(query).sort({ submittedAt: -1 }).skip(skip).limit(Number(limit)),
      Response.countDocuments(query)
    ]);

    res.json({ data, total, page: Number(page), pages: Math.ceil(total / Number(limit)) });
  } catch (err) {
    console.error('❌ Erreur get responses:', err.message);
    res.status(500).json({ error: 'Erreur serveur', detail: err.message });
  }
});

// Stats agrégées
app.get('/api/responses/stats', authMiddleware, dbCheck, async (req, res) => {
  try {
    const total = await Response.countDocuments();
    const all = await Response.find({}, { answers: 1 });

    let sumQ4 = 0, sumQ24 = 0, sumQ33 = 0;
    let countQ4 = 0, countQ24 = 0, countQ33 = 0;
    const levierCount = {}, formatsCount = {};

    all.forEach(r => {
      const a = r.answers || {};
      if (a.Q4  && !isNaN(a.Q4))  { sumQ4  += Number(a.Q4);  countQ4++;  }
      if (a.Q24 && !isNaN(a.Q24)) { sumQ24 += Number(a.Q24); countQ24++; }
      if (a.Q33 && !isNaN(a.Q33)) { sumQ33 += Number(a.Q33); countQ33++; }
      if (a.Q2) levierCount[a.Q2] = (levierCount[a.Q2] || 0) + 1;
      if (Array.isArray(a.Q26)) {
        a.Q26.forEach(f => { formatsCount[f] = (formatsCount[f] || 0) + 1; });
      }
    });

    const topLevier = Object.entries(levierCount).sort((a, b) => b[1] - a[1])[0];
    const topFormat = Object.entries(formatsCount).sort((a, b) => b[1] - a[1])[0];

    res.json({
      total,
      avgSatisfaction: countQ4  ? (sumQ4  / countQ4).toFixed(1)  : null,
      avgConfiance:    countQ24 ? (sumQ24 / countQ24).toFixed(1) : null,
      avgOptimisme:    countQ33 ? (sumQ33 / countQ33).toFixed(1) : null,
      topLevier:  topLevier ? topLevier[0] : null,
      topFormat:  topFormat ? topFormat[0] : null,
    });
  } catch (err) {
    console.error('❌ Erreur stats:', err.message);
    res.status(500).json({ error: 'Erreur serveur', detail: err.message });
  }
});

// Supprimer une réponse
app.delete('/api/responses/:id', authMiddleware, dbCheck, async (req, res) => {
  try {
    const result = await Response.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: 'Réponse introuvable' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur', detail: err.message });
  }
});

// Supprimer toutes les réponses
app.delete('/api/responses', authMiddleware, dbCheck, async (req, res) => {
  try {
    const result = await Response.deleteMany({});
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur', detail: err.message });
  }
});

// ─── 404 ─────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route inconnue: ${req.method} ${req.path}` });
});

// ─── DÉMARRAGE ───────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 API Lean Menuiserie — port ${PORT}`);
  console.log(`   MONGO_URI défini : ${!!process.env.MONGO_URI}`);
  console.log(`   JWT_SECRET défini: ${!!process.env.JWT_SECRET}`);
});