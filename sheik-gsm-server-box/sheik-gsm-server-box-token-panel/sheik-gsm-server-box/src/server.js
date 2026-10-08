const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { query, initDb, pool } = require("./db");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) console.warn("JWT_SECRET não configurado.");

const hashToken = v => crypto.createHash("sha256").update(v).digest("hex");
const newToken = () => crypto.randomBytes(24).toString("base64url");

function signUser(u) {
  return jwt.sign({id:u.id,email:u.email,name:u.name,role:u.role}, JWT_SECRET, {expiresIn:"12h"});
}
function auth(req,res,next) {
  const h=req.headers.authorization||"", t=h.startsWith("Bearer ")?h.slice(7):null;
  if(!t) return res.status(401).json({error:"Não autenticado"});
  try { req.user=jwt.verify(t,JWT_SECRET); next(); }
  catch { res.status(401).json({error:"Sessão inválida ou expirada"}); }
}
function adminOnly(req,res,next) {
  if(req.user?.role!=="admin") return res.status(403).json({error:"Apenas administrador"});
  next();
}
async function log(uid,action,details={}) {
  await query("INSERT INTO logs(user_id,action,details) VALUES($1,$2,$3)",[uid||null,action,JSON.stringify(details)]);
}
async function ensureAdmin() {
  const {ADMIN_EMAIL:email,ADMIN_PASSWORD:password}=process.env;
  if(!email||!password) return;
  const e=await query("SELECT id FROM users WHERE email=$1",[email]);
  if(!e.rowCount) {
    const h=await bcrypt.hash(password,12);
    await query("INSERT INTO users(email,password_hash,name,role) VALUES($1,$2,$3,'admin')",[email,h,"Administrador"]);
  }
}

app.get("/health",async(_req,res)=>{
  try { await query("SELECT 1"); res.json({ok:true,service:"SHEIK GSM SERVER BOX"}); }
  catch { res.status(503).json({ok:false,database:false}); }
});

app.post("/api/auth/login",async(req,res)=>{
  const {email,password}=req.body||{};
  const r=await query("SELECT * FROM users WHERE email=$1 AND active=true",[email]);
  const u=r.rows[0];
  if(!u||!(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"E-mail ou senha inválidos"});
  await log(u.id,"login");
  res.json({token:signUser(u),user:{id:u.id,email:u.email,name:u.name,role:u.role}});
});
app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));

app.get("/api/boxes",auth,async(_req,res)=>{
  const r=await query("SELECT id,name,serial,model,status,last_heartbeat,created_at FROM boxes ORDER BY id");
  res.json(r.rows);
});
app.post("/api/boxes",auth,adminOnly,async(req,res)=>{
  const {name,serial,model,agentKey}=req.body||{};
  if(!name||!agentKey) return res.status(400).json({error:"name e agentKey são obrigatórios"});
  const r=await query("INSERT INTO boxes(name,serial,model,agent_key_hash) VALUES($1,$2,$3,$4) RETURNING id,name,serial,model,status",
    [name,serial||null,model||null,hashToken(agentKey)]);
  await log(req.user.id,"box_created",{boxId:r.rows[0].id});
  res.status(201).json(r.rows[0]);
});

app.post("/api/tokens",auth,async(req,res)=>{
  const value=newToken(), minutes=Math.min(Math.max(Number(req.body?.minutes||10),1),60);
  const exp=new Date(Date.now()+minutes*60000);
  const r=await query("INSERT INTO tokens(token_hash,user_id,expires_at) VALUES($1,$2,$3) RETURNING id,expires_at",
    [hashToken(value),req.user.id,exp]);
  await log(req.user.id,"token_created",{tokenId:r.rows[0].id});
  res.json({token:value,expiresAt:r.rows[0].expires_at});
});

app.post("/api/token/access",async(req,res)=>{
  const {token,boxId}=req.body||{};
  if(!token||!boxId)return res.status(400).json({error:"token e boxId são obrigatórios"});
  const c=await pool.connect();
  try{
    await c.query("BEGIN");
    const t=await c.query("SELECT * FROM tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE",[hashToken(token)]);
    if(!t.rowCount){await c.query("ROLLBACK");return res.status(400).json({error:"Token inválido, usado ou expirado"});}
    const b=await c.query("SELECT * FROM boxes WHERE id=$1 FOR UPDATE",[boxId]);
    if(!b.rowCount||b.rows[0].status!=="online"){await c.query("ROLLBACK");return res.status(400).json({error:"Box não está online/disponível"});}
    const busy=await c.query("SELECT id FROM sessions WHERE box_id=$1 AND status IN ('pending','active') FOR UPDATE",[boxId]);
    if(busy.rowCount){await c.query("ROLLBACK");return res.status(409).json({error:"Box ocupada"});}
    await c.query("UPDATE tokens SET used_at=NOW() WHERE id=$1",[t.rows[0].id]);
    const s=await c.query("INSERT INTO sessions(user_id,box_id,token_id,status,started_at) VALUES($1,$2,$3,'active',NOW()) RETURNING *",[t.rows[0].user_id,boxId,t.rows[0].id]);
    await c.query("UPDATE boxes SET status='busy' WHERE id=$1",[boxId]);
    await c.query("COMMIT");
    await log(t.rows[0].user_id,"token_session_started",{sessionId:s.rows[0].id,boxId});
    res.status(201).json({sessionId:s.rows[0].id,expiresAt:t.rows[0].expires_at});
  }catch(e){await c.query("ROLLBACK");res.status(500).json({error:"Não foi possível iniciar o acesso"});}
  finally{c.release();}
});

app.post("/api/sessions",auth,async(req,res)=>{
  const {token,boxId}=req.body||{};
  if(!token||!boxId) return res.status(400).json({error:"token e boxId são obrigatórios"});
  const c=await pool.connect();
  try {
    await c.query("BEGIN");
    const t=await c.query("SELECT * FROM tokens WHERE token_hash=$1 AND user_id=$2 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE",[hashToken(token),req.user.id]);
    if(!t.rowCount){await c.query("ROLLBACK");return res.status(400).json({error:"Token inválido, usado ou expirado"});}
    const b=await c.query("SELECT * FROM boxes WHERE id=$1 FOR UPDATE",[boxId]);
    if(!b.rowCount||b.rows[0].status!=="online"){await c.query("ROLLBACK");return res.status(400).json({error:"Box não está online/disponível"});}
    const busy=await c.query("SELECT id FROM sessions WHERE box_id=$1 AND status IN ('pending','active') FOR UPDATE",[boxId]);
    if(busy.rowCount){await c.query("ROLLBACK");return res.status(409).json({error:"Box ocupada"});}
    await c.query("UPDATE tokens SET used_at=NOW() WHERE id=$1",[t.rows[0].id]);
    const s=await c.query("INSERT INTO sessions(user_id,box_id,token_id,status,started_at) VALUES($1,$2,$3,'active',NOW()) RETURNING *",[req.user.id,boxId,t.rows[0].id]);
    await c.query("UPDATE boxes SET status='busy' WHERE id=$1",[boxId]);
    await c.query("COMMIT"); await log(req.user.id,"session_started",{sessionId:s.rows[0].id,boxId});
    res.status(201).json(s.rows[0]);
  } catch(e){await c.query("ROLLBACK");res.status(500).json({error:"Não foi possível iniciar a sessão"});}
  finally{c.release();}
});

app.get("/api/sessions",auth,async(req,res)=>{
  const admin=req.user.role==="admin";
  const r=await query(`SELECT s.*,b.name box_name,u.email user_email FROM sessions s JOIN boxes b ON b.id=s.box_id JOIN users u ON u.id=s.user_id ${admin?"":"WHERE s.user_id=$1"} ORDER BY s.id DESC LIMIT 100`,admin?[]:[req.user.id]);
  res.json(r.rows);
});
app.post("/api/sessions/:id/end",auth,async(req,res)=>{
  const r=await query("UPDATE sessions SET status='ended',ended_at=NOW() WHERE id=$1 AND (user_id=$2 OR $3='admin') AND status IN ('pending','active') RETURNING box_id",[req.params.id,req.user.id,req.user.role]);
  if(!r.rowCount)return res.status(404).json({error:"Sessão não encontrada"});
  await query("UPDATE boxes SET status='online' WHERE id=$1",[r.rows[0].box_id]);
  await log(req.user.id,"session_ended",{sessionId:req.params.id});
  res.json({ok:true});
});

app.post("/api/agent/heartbeat",async(req,res)=>{
  const key=req.headers["x-agent-key"],{boxId}=req.body||{};
  if(!key||!boxId)return res.status(400).json({error:"boxId e X-Agent-Key são obrigatórios"});
  const r=await query("SELECT agent_key_hash FROM boxes WHERE id=$1",[boxId]);
  if(!r.rowCount||r.rows[0].agent_key_hash!==hashToken(key))return res.status(401).json({error:"Agent não autorizado"});
  await query("UPDATE boxes SET last_heartbeat=NOW(),status=CASE WHEN status='offline' THEN 'online' ELSE status END WHERE id=$1",[boxId]);
  res.json({ok:true,serverTime:new Date().toISOString()});
});

app.get("/api/admin/logs",auth,adminOnly,async(_req,res)=>{
  const r=await query("SELECT l.id,l.action,l.details,l.created_at,u.email FROM logs l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 200");
  res.json(r.rows);
});

async function telegram() {
  const t=process.env.TELEGRAM_BOT_TOKEN;
  if(!t||process.env.TELEGRAM_POLLING!=="true")return;
  const TelegramBot=require("node-telegram-bot-api"),bot=new TelegramBot(t,{polling:true});
  bot.onText(/^\/start$/,m=>bot.sendMessage(m.chat.id,"SHEIK GSM SERVER BOX\nUse /token para solicitar um token temporário."));
  bot.onText(/^\/token$/,async m=>{
    const r=await query("SELECT u.* FROM telegram_users t JOIN users u ON u.id=t.user_id WHERE t.telegram_chat_id=$1 AND t.active=true AND u.active=true",[String(m.chat.id)]);
    if(!r.rowCount)return bot.sendMessage(m.chat.id,"Seu Telegram ainda não está vinculado.");
    const v=newToken(),e=new Date(Date.now()+600000);
    await query("INSERT INTO tokens(token_hash,user_id,expires_at) VALUES($1,$2,$3)",[hashToken(v),r.rows[0].id,e]);
    await bot.sendMessage(m.chat.id,`Seu token temporário:\n\n${v}\n\nValidade: 10 minutos.`);
  });
}

async function boot(){
  if(!process.env.DATABASE_URL){console.error("DATABASE_URL não configurada");process.exit(1);}
  await initDb(); await ensureAdmin(); await telegram();
  app.listen(PORT,"0.0.0.0",()=>console.log(`SHEIK GSM SERVER BOX online na porta ${PORT}`));
}
boot().catch(e=>{console.error(e);process.exit(1);});
