import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-railway';
const DATABASE_URL = process.env.DATABASE_URL;
const pool = DATABASE_URL ? new pg.Pool({ connectionString: DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized:false } : false }) : null;

app.use(express.json({limit:'2mb'}));
app.use(express.static(path.join(__dirname,'public')));

async function db(sql, params=[]){ if(!pool) throw new Error('DATABASE_URL belum diset'); return pool.query(sql,params); }
async function init(){
 if(!pool) return;
 await db(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,name TEXT NOT NULL,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'student',created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS access_codes(id SERIAL PRIMARY KEY,code TEXT NOT NULL,active BOOLEAN DEFAULT TRUE,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS tasks(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE CASCADE,title TEXT NOT NULL,course TEXT,description TEXT,deadline TIMESTAMPTZ,priority TEXT DEFAULT 'medium',status TEXT DEFAULT 'todo',created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS courses(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,lecturer TEXT,sks INT DEFAULT 0,room TEXT,schedule TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS schedules(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE CASCADE,title TEXT NOT NULL,type TEXT DEFAULT 'study',start_at TIMESTAMPTZ,end_at TIMESTAMPTZ,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS materials(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE CASCADE,course_id INT REFERENCES courses(id) ON DELETE SET NULL,file_name TEXT NOT NULL,file_type TEXT,extracted_text TEXT,ai_summary TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS study_sessions(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE CASCADE,started_at TIMESTAMPTZ,duration_seconds INT DEFAULT 0,topic TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS ai_conversations(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE CASCADE,title TEXT DEFAULT 'Percakapan Baru',created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS ai_messages(id SERIAL PRIMARY KEY,conversation_id INT REFERENCES ai_conversations(id) ON DELETE CASCADE,role TEXT NOT NULL,content TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS audit_logs(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id) ON DELETE SET NULL,action TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());`);
 const ac=await db('SELECT COUNT(*)::int AS n FROM access_codes'); if(ac.rows[0].n===0) await db("INSERT INTO access_codes(code,active) VALUES('2026',true)");
 const au=await db("SELECT id FROM users WHERE username='Rifqi'"); if(au.rowCount===0){ const hash=await bcrypt.hash('12345678',12); await db("INSERT INTO users(name,username,password_hash,role) VALUES($1,$2,$3,'admin')",['Rifqi','Rifqi',hash]); }
}
function auth(req,res,next){ try{const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return res.status(401).json({error:'Unauthorized'}); req.user=jwt.verify(h.slice(7),JWT_SECRET); next();}catch{return res.status(401).json({error:'Token tidak valid'});}}
function admin(req,res,next){ if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'}); next(); }

app.get('/api/health',(req,res)=>res.json({ok:true,service:'StudyFlow'}));
app.post('/api/auth/register',async(req,res)=>{try{const {code,name,username,password}=req.body;if(!code||!name||!username||!password||password.length<8)return res.status(400).json({error:'Data tidak lengkap atau password minimal 8 karakter'});const c=await db('SELECT id FROM access_codes WHERE code=$1 AND active=true LIMIT 1',[code]);if(!c.rowCount)return res.status(400).json({error:'Kode pendaftaran salah atau tidak aktif'});const hash=await bcrypt.hash(password,12);const r=await db('INSERT INTO users(name,username,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,name,username,role',[name,username,hash,'student']);res.status(201).json(r.rows[0]);}catch(e){res.status(400).json({error:e.code==='23505'?'Username sudah digunakan':e.message});}});
app.post('/api/auth/login',async(req,res)=>{try{const {username,password}=req.body;const r=await db('SELECT * FROM users WHERE username=$1',[username]);if(!r.rowCount||!(await bcrypt.compare(password,r.rows[0].password_hash)))return res.status(401).json({error:'Username atau password salah'});const u=r.rows[0];const token=jwt.sign({id:u.id,name:u.name,username:u.username,role:u.role},JWT_SECRET,{expiresIn:'7d'});await db('INSERT INTO audit_logs(user_id,action) VALUES($1,$2)',[u.id,'LOGIN']);res.json({token,user:{id:u.id,name:u.name,username:u.username,role:u.role}});}catch(e){res.status(500).json({error:e.message});}});
app.get('/api/me',auth,(req,res)=>res.json(req.user));
app.get('/api/dashboard',auth,async(req,res)=>{try{const [t,c,s,m]=await Promise.all([db('SELECT COUNT(*)::int n FROM tasks WHERE user_id=$1',[req.user.id]),db('SELECT COUNT(*)::int n FROM courses WHERE user_id=$1',[req.user.id]),db('SELECT COUNT(*)::int n FROM schedules WHERE user_id=$1',[req.user.id]),db('SELECT COUNT(*)::int n FROM materials WHERE user_id=$1',[req.user.id])]);res.json({tasks:t.rows[0].n,courses:c.rows[0].n,schedules:s.rows[0].n,materials:m.rows[0].n});}catch(e){res.status(500).json({error:e.message});}});
app.get('/api/tasks',auth,async(req,res)=>{const r=await db('SELECT * FROM tasks WHERE user_id=$1 ORDER BY deadline NULLS LAST,created_at DESC',[req.user.id]);res.json(r.rows)});
app.post('/api/tasks',auth,async(req,res)=>{const {title,course,description,deadline,priority}=req.body;const r=await db('INSERT INTO tasks(user_id,title,course,description,deadline,priority) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[req.user.id,title,course||null,description||null,deadline||null,priority||'medium']);res.status(201).json(r.rows[0]);});
app.patch('/api/tasks/:id',auth,async(req,res)=>{const {status}=req.body;const r=await db('UPDATE tasks SET status=$1 WHERE id=$2 AND user_id=$3 RETURNING *',[status,req.params.id,req.user.id]);res.json(r.rows[0]||null)});
app.delete('/api/tasks/:id',auth,async(req,res)=>{await db('DELETE FROM tasks WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);res.json({ok:true})});
app.get('/api/courses',auth,async(req,res)=>{const r=await db('SELECT * FROM courses WHERE user_id=$1 ORDER BY name',[req.user.id]);res.json(r.rows)});
app.post('/api/courses',auth,async(req,res)=>{const {name,lecturer,sks,room,schedule}=req.body;const r=await db('INSERT INTO courses(user_id,name,lecturer,sks,room,schedule) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[req.user.id,name,lecturer||null,sks||0,room||null,schedule||null]);res.status(201).json(r.rows[0]);});
app.get('/api/schedules',auth,async(req,res)=>{const r=await db('SELECT * FROM schedules WHERE user_id=$1 ORDER BY start_at',[req.user.id]);res.json(r.rows)});
app.post('/api/schedules',auth,async(req,res)=>{const {title,type,start_at,end_at}=req.body;const r=await db('INSERT INTO schedules(user_id,title,type,start_at,end_at) VALUES($1,$2,$3,$4,$5) RETURNING *',[req.user.id,title,type||'study',start_at||null,end_at||null]);res.status(201).json(r.rows[0]);});
app.get('/api/admin/stats',auth,admin,async(req,res)=>{const [u,t,c,m]=await Promise.all([db('SELECT COUNT(*)::int n FROM users'),db('SELECT COUNT(*)::int n FROM tasks'),db('SELECT COUNT(*)::int n FROM courses'),db('SELECT COUNT(*)::int n FROM materials')]);res.json({users:u.rows[0].n,tasks:t.rows[0].n,courses:c.rows[0].n,materials:m.rows[0].n});});
app.get('/api/admin/users',auth,admin,async(req,res)=>{const r=await db('SELECT id,name,username,role,created_at FROM users ORDER BY created_at DESC');res.json(r.rows)});
app.get('/api/admin/access-code',auth,admin,async(req,res)=>{const r=await db('SELECT * FROM access_codes ORDER BY id DESC LIMIT 1');res.json(r.rows[0])});
app.patch('/api/admin/access-code',auth,admin,async(req,res)=>{const {code,active}=req.body;await db('UPDATE access_codes SET code=$1,active=$2 WHERE id=(SELECT id FROM access_codes ORDER BY id DESC LIMIT 1)',[code,active!==false]);res.json({ok:true});});
app.use((req,res,next)=>{if(req.method==='GET'&&req.accepts('html'))return res.sendFile(path.join(__dirname,'public','index.html'));next()});
init().then(()=>app.listen(PORT,()=>console.log(`StudyFlow running on ${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
