require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const argon2 = require('argon2');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';
const SERVER_PEPPER = process.env.PEPPER || '';

// -------------------- Utils --------------------
async function hashPassword(plain) {
  return argon2.hash(plain + SERVER_PEPPER, { type: argon2.argon2id });
}
async function verifyPassword(plain, hash) {
  try { return await argon2.verify(hash, plain + SERVER_PEPPER); }
  catch { return false; }
}
function signJWT(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); }
function verifyJWT(token) { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } }
function hmacSha256Hex(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest('hex'); }
function hexToBits(hex) { 
  const buf = Buffer.from(hex, 'hex'); 
  const bits = [];
  for (const b of buf) for (let i=7;i>=0;i--) bits.push((b>>i)&1);
  return bits;
}

// -------------------- Middleware --------------------
async function authMiddleware(req,res,next){
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({ error:'Missing auth' });
  const parts = auth.split(' ');
  if(parts.length!==2 || parts[0]!=='Bearer') return res.status(401).json({ error:'Malformed auth' });
  const payload = verifyJWT(parts[1]);
  if(!payload) return res.status(401).json({ error:'Invalid token' });
  req.user = payload;
  next();
}

// -------------------- Auth Routes --------------------
app.post('/api/register', async (req,res)=>{
  const { username, password } = req.body;
  if(!username||!password) return res.status(400).json({ error:'Missing fields' });
  const client = await pool.connect();
  try{
    const hash = await hashPassword(password);
    const q = await client.query(
      'INSERT INTO users(username,password_hash,balance) VALUES($1,$2,0) RETURNING id, username, balance',
      [username, hash]
    );
    const user = q.rows[0];
    const token = signJWT({ id:user.id, username:user.username });
    res.json({ token, user });
  }catch(e){
    console.error(e);
    if(e.code==='23505') return res.status(400).json({ error:'Username taken' });
    res.status(500).json({ error:'Server error' });
  }finally{ client.release(); }
});

app.post('/api/login', async (req,res)=>{
  const { username,password } = req.body;
  if(!username||!password) return res.status(400).json({ error:'Missing fields' });
  const client = await pool.connect();
  try{
    const q = await client.query('SELECT id,username,password_hash,balance FROM users WHERE username=$1',[username]);
    if(q.rowCount===0) return res.status(401).json({ error:'Invalid creds' });
    const u = q.rows[0];
    const ok = await verifyPassword(password,u.password_hash);
    if(!ok) return res.status(401).json({ error:'Invalid creds' });
    const token = signJWT({id:u.id, username:u.username});
    res.json({ token, user:{ id:u.id, username:u.username, balance:(u.balance/100).toFixed(2) } });
  }catch(e){ console.error(e); res.status(500).json({ error:'Server error' }); }
  finally{ client.release(); }
});

// -------------------- Admin --------------------
app.post('/api/admin/add-funds', authMiddleware, async (req, res) => {
  if (req.user.username !== 'admin')
    return res.status(403).json({ error: 'Forbidden' });

  const userId = Number(req.body.userId);
  const amount = Number(req.body.amount);

  if (!Number.isInteger(userId) || amount <= 0)
    return res.status(400).json({ error: 'Invalid input' });

  // ?? conversion SAFE en centimes
  const cents = Math.trunc(amount * 100);

  if (cents <= 0)
    return res.status(400).json({ error: 'Amount too small' });

  try {
    await withBalanceLock(userId, async (client, balance) => {
      const newBalance = balance + cents;

      await client.query(
        'UPDATE users SET balance=$1 WHERE id=$2',
        [newBalance, userId]
      );

      await client.query(
        `INSERT INTO transactions (user_id, type, amount, balance_after, metadata)
         VALUES ($1,$2,$3,$4,$5)`,
        [userId, 'admin_deposit', cents, newBalance, { by: 'admin' }]
      );

      res.json({
        success: true,
        balance: (newBalance / 100).toFixed(2)
      });
    });
  } catch (e) {
    console.error('ADMIN ADD FUNDS ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', authMiddleware, async (req,res)=>{ 
  if(req.user.username!=='admin') 
    return res.status(403).json({ error:'Forbidden' }); 
const q = await pool.query('SELECT id,username,balance FROM users ORDER BY id'); 
res.json(q.rows.map(u=>({ ...u, balance:(u.balance/100).toFixed(2) }))); });

// -------------------- User Balance --------------------
app.get('/api/user/balance', authMiddleware, async (req,res)=>{
  const q = await pool.query('SELECT balance FROM users WHERE id=$1',[req.user.id]);
  if(q.rowCount===0) return res.status(404).json({ error:'User not found' });
  res.json({ balance:(q.rows[0].balance/100).toFixed(2) });
});

app.post('/api/user/add-funds', authMiddleware, async (req,res)=>{
  const { amount } = req.body;
  if(!amount) return res.status(400).json({ error:'Missing amount' });
  const cents = Math.round(parseFloat(amount)*100);
  if(cents<=0) return res.status(400).json({ error:'Invalid amount' });

  await withBalanceLock(req.user.id, async (client,balance)=>{
    const newBalance = balance+cents;
    await client.query('UPDATE users SET balance=$1 WHERE id=$2',[newBalance,req.user.id]);
    await client.query(
      'INSERT INTO transactions(user_id,type,amount,balance_after,metadata) VALUES($1,$2,$3,$4,$5)',
      [req.user.id,'deposit',cents,newBalance,{ note:'User added funds' }]
    );
    res.json({ balance:(newBalance/100).toFixed(2) });
  });
});

// -------------------- DB Lock Helper --------------------
async function withBalanceLock(userId,fn){
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const q = await client.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE',[userId]);
    if(q.rowCount===0){ await client.query('ROLLBACK'); client.release(); throw new Error('User not found'); }
    const balance = q.rows[0].balance;
    const result = await fn(client,balance);
    await client.query('COMMIT');
    return result;
  }catch(e){ try{ await client.query('ROLLBACK'); }catch{} throw e; }finally{ client.release(); }
}

// -------------------- Game Engines --------------------

// Plinko
function plinkoCompute(seed,roundId,levels){
  const bits = hexToBits(hmacSha256Hex(seed,roundId));
  let rights=0;
  for(let i=0;i<levels;i++) rights+=bits[i]||0;
  const table = Array.from({length:levels+1},(_,i)=>Math.max(0,2-Math.abs(i-Math.floor(levels/2))/levels)+i*0.1);
  return {rights,multiplier:table[rights]};
}

// Limbo
function limboCompute(seed,roundId){
  const h = hmacSha256Hex(seed,roundId);
  const num = parseInt(h.slice(0,8),16)/0xffffffff;
  return { multiplier: Math.max(1,Math.floor((1/(1-num))*100)/100) };
}

// Blackjack
function blackjackCompute(seed,roundId){
  const h = hmacSha256Hex(seed,roundId);
  const result = ['win','loss','push'][parseInt(h[0],16)%3];
  return { cards:[h[0],h[1],h[2],h[3]], result };
}

// -------------------- Play Game --------------------
app.post('/api/game/:game/play', authMiddleware, async (req,res)=>{
  const game = req.params.game;
  const { bet, roundId } = req.body;
  if(!bet || !roundId) return res.status(400).json({ error:'Missing bet or roundId' });
  const betCents = Math.round(parseFloat(bet)*100);
  if(betCents<=0) return res.status(400).json({ error:'Invalid bet' });

  try{
    const result = await withBalanceLock(req.user.id, async (client,balance)=>{
      if(balance<betCents) throw new Error('Insufficient funds');
      let newBalance = balance - betCents;
      await client.query('UPDATE users SET balance=$1 WHERE id=$2',[newBalance,req.user.id]);

      const serverSeed = crypto.randomBytes(32).toString('hex');
      let outcome,payout=0;

      if(game==='plinko'){
        outcome = plinkoCompute(serverSeed,roundId,9);
        payout = Math.round(betCents*outcome.multiplier);
      }else if(game==='limbo'){
        outcome = limboCompute(serverSeed,roundId);
        payout = Math.round(betCents*outcome.multiplier);
      }else if(game==='blackjack'){
        outcome = blackjackCompute(serverSeed,roundId);
        payout = outcome.result==='win'?betCents*2: outcome.result==='push'?betCents:0;
      }else throw new Error('Unsupported game');

      if(payout>0){
        newBalance += payout;
        await client.query('UPDATE users SET balance=$1 WHERE id=$2',[newBalance,req.user.id]);
      }

      await client.query(
        'INSERT INTO transactions(user_id,type,amount,balance_after,metadata) VALUES($1,$2,$3,$4,$5)',
        [req.user.id,'bet',-betCents,newBalance,{ game, outcome }]
      );

      return { outcome, payout:(payout/100).toFixed(2), balance_before:(balance/100).toFixed(2), balance_after:(newBalance/100).toFixed(2) };
    });

    res.json({ success:true, result });
  }catch(e){
    console.error(e);
    if(e.message==='Insufficient funds') return res.status(400).json({ error:'Insufficient funds' });
    res.status(500).json({ error:e.message||'Server error' });
  }
});

// -------------------- Start Server --------------------
const PORT = process.env.PORT||3000;
app.listen(PORT,'0.0.0.0',()=>console.log('Server listening on',PORT));
