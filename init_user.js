// node init_user.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');

async function main(){
  await mongoose.connect(process.env.MONGO_URI);
  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASS;

  const existing = await User.findOne({ username });
  if(existing){
    console.log('User already exists:', username);
    process.exit(0);
  }

  const hash = await bcrypt.hash(password, 12);
  await User.create({ username, passwordHash: hash });
  console.log('Created user:', username);
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
