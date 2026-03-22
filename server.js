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
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connecté — lean_menuiserie'))
  .catch(err => console.error('❌ Erreur MongoDB:', err.message));

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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

// Soumettre une réponse (formulaire public)
app.post('/api/responses', async (req, res) => {
  try {
    const answers = req.body;
    if (!answers || Object.keys(answers).length === 0) {
      return res.status(400).json({ error: 'Réponses vides' });
    }
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const doc = await Response.create({ answers, ip });
    res.status(201).json({ success: true, id: doc._id });
  } catch (err) {
    console.error('Erreur save response:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── ROUTES ADMIN (protégées) ────────────────────────────────────

// Login admin
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis' });
    }
    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }
    const valid = bcrypt.compareSync(password, admin.password);
    if (!valid) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }
    const token = jwt.sign(
      { email: admin.email, id: admin._id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ success: true, token, email: admin.email });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Vérifier token (pour auto-login)
app.get('/api/admin/verify', authMiddleware, (req, res) => {
  res.json({ valid: true, email: req.admin.email });
});

// Lire toutes les réponses
app.get('/api/responses', authMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const skip = (page - 1) * limit;

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

    res.json({ data, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('Erreur get responses:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Stats agrégées
app.get('/api/responses/stats', authMiddleware, async (req, res) => {
  try {
    const total = await Response.countDocuments();
    const all = await Response.find({}, { answers: 1 });

    let sumQ4 = 0, sumQ24 = 0, sumQ33 = 0, countQ4 = 0, countQ24 = 0, countQ33 = 0;
    const levierCount = {};
    const formatsCount = {};

    all.forEach(r => {
      const a = r.answers;
      if (a.Q4)  { sumQ4  += Number(a.Q4);  countQ4++;  }
      if (a.Q24) { sumQ24 += Number(a.Q24); countQ24++; }
      if (a.Q33) { sumQ33 += Number(a.Q33); countQ33++; }
      if (a.Q2)  { levierCount[a.Q2] = (levierCount[a.Q2] || 0) + 1; }
      if (Array.isArray(a.Q26)) {
        a.Q26.forEach(f => { formatsCount[f] = (formatsCount[f] || 0) + 1; });
      }
    });

    const topLevier = Object.entries(levierCount).sort((a,b) => b[1]-a[1])[0];
    const topFormat = Object.entries(formatsCount).sort((a,b) => b[1]-a[1])[0];

    res.json({
      total,
      avgSatisfaction: countQ4  ? (sumQ4  / countQ4).toFixed(1)  : null,
      avgConfiance:    countQ24 ? (sumQ24 / countQ24).toFixed(1) : null,
      avgOptimisme:    countQ33 ? (sumQ33 / countQ33).toFixed(1) : null,
      topLevier:  topLevier  ? topLevier[0]  : null,
      topFormat:  topFormat  ? topFormat[0]  : null,
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Supprimer une réponse
app.delete('/api/responses/:id', authMiddleware, async (req, res) => {
  try {
    await Response.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Supprimer toutes les réponses
app.delete('/api/responses', authMiddleware, async (req, res) => {
  try {
    const result = await Response.deleteMany({});
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── DÉMARRAGE ───────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 API Lean Menuiserie — port ${PORT}`);
  console.log(`📋 Routes disponibles:`);
  console.log(`   GET  /api/health`);
  console.log(`   POST /api/responses`);
  console.log(`   POST /api/admin/login`);
  console.log(`   GET  /api/responses  [protégé]`);
  console.log(`   GET  /api/responses/stats  [protégé]`);
  console.log(`   DELETE /api/responses/:id  [protégé]`);
  console.log(`   DELETE /api/responses  [protégé]`);
});
