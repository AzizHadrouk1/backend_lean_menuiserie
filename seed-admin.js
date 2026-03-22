require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', AdminSchema);

async function seed() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ Connecté à MongoDB');

    // Supprimer admin existant si besoin
    await Admin.deleteMany({ email: process.env.ADMIN_EMAIL });

    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    await Admin.create({
      email: process.env.ADMIN_EMAIL,
      password: hash
    });

    console.log('✅ Compte admin créé :');
    console.log('   Email    :', process.env.ADMIN_EMAIL);
    console.log('   Password :', process.env.ADMIN_PASSWORD);
    console.log('\n⚠️  Gardez ces identifiants en lieu sûr !');
  } catch (err) {
    console.error('❌ Erreur:', err.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

seed();
