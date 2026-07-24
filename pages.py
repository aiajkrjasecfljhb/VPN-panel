# ============================================
# X4G PANEL v9.2 · FULL ORIGINAL + SOCKS5
# ============================================

import json
import os
import uuid
import hashlib
import secrets
import time
import struct
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Request, Response, Depends, Cookie, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from pydantic import BaseModel
import uvicorn

# ============================================
# تنظیمات
# ============================================

LOGO_URL = "https://abrehamrahi.ir/o/public/CcmPXCvr/"
PASSWORD = "123456"
SESSION_EXPIRE_DAYS = 7
DATA_FILE = "data.json"
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", 1080))

# ============================================
# SOCKS5 Constants
# ============================================
SOCKS5_VERSION = 0x05
SOCKS_CMD_CONNECT = 0x01
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAINNAME = 0x03
SOCKS_ATYP_IPV6 = 0x04
SOCKS5_SUCCEEDED = 0x00
SOCKS5_SERVER_FAILURE = 0x01
SOCKS5_CMD_NOT_SUPPORTED = 0x07

# ============================================
# SOCKS5 State
# ============================================
socks_connections: Dict[str, dict] = {}
socks_bytes: Dict[str, int] = {}

# ============================================
# مدل‌های داده
# ============================================

class Link(BaseModel):
    uuid: str
    label: str
    note: str = ""
    protocol: str = "vless-ws"
    fingerprint: str = "chrome"
    alpn: str = ""
    port: int = 443
    ip_limit: int = 0
    limit_bytes: float = 0
    used_bytes: float = 0
    created_at: str
    expires_at: Optional[str] = None
    active: bool = True
    sub_id: Optional[str] = None
    connected_ips: List[str] = []
    vless_link: str = ""
    sub_url: str = ""

class SubGroup(BaseModel):
    sub_id: str
    name: str
    desc: str = ""
    has_password: bool = False
    password_hash: str = ""
    link_ids: List[str] = []
    created_at: str
    public_url: str = ""
    sub_url: str = ""

class Data(BaseModel):
    links: List[Link] = []
    subs: List[SubGroup] = []
    socks_configs: List[Dict] = []
    total_traffic: float = 0
    activity_logs: List[Dict] = []
    error_logs: List[Dict] = []

# ============================================
# مدیریت داده
# ============================================

def load_data() -> Data:
    if not os.path.exists(DATA_FILE):
        return Data()
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
            if 'socks_configs' not in raw:
                raw['socks_configs'] = []
            return Data(**raw)
    except:
        return Data()

def save_data(data: Data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data.dict(), f, ensure_ascii=False, indent=2)

def get_base_url(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"

def generate_vless_link(link: Link, base_url: str) -> str:
    uuid_str = link.uuid
    host = base_url.replace("https://", "").replace("http://", "").split(":")[0]
    port = link.port or 443
    
    if link.protocol == "vless-ws":
        path = "/ws"
        transport = "ws"
        header = ""
    elif link.protocol == "xhttp-packet-up":
        path = "/xhttp"
        transport = "xhttp"
        header = "packet-up"
    elif link.protocol == "xhttp-stream-up":
        path = "/xhttp"
        transport = "xhttp"
        header = "stream-up"
    elif link.protocol == "xhttp-stream-one":
        path = "/xhttp"
        transport = "xhttp"
        header = "stream-one"
    else:
        path = "/ws"
        transport = "ws"
        header = ""
    
    vless = f"vless://{uuid_str}@{host}:{port}?encryption=none&security=tls&sni={host}&fp={link.fingerprint or 'chrome'}&type={transport}&host={host}&path={path}"
    
    if header:
        vless += f"&header={header}"
    if link.alpn:
        vless += f"&alpn={link.alpn}"
    
    vless += f"#X4G-{link.label.replace(' ', '-')}"
    
    return vless

def generate_sub_url(link: Link, base_url: str) -> str:
    return f"{base_url}/sub/{link.uuid}"

def generate_public_url(sub: SubGroup, base_url: str) -> str:
    return f"{base_url}/public/{sub.sub_id}"

def generate_sub_group_url(sub: SubGroup, base_url: str) -> str:
    return f"{base_url}/sub-group/{sub.sub_id}"

def hash_password(password: str) -> str:
    salt = "X4G_SALT_2024"
    return hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def get_session_user(request: Request) -> Optional[str]:
    session = request.cookies.get("x4g_session")
    if not session:
        return None
    try:
        data = json.loads(session)
        if data.get("expires") > time.time():
            return data.get("user")
    except:
        pass
    return None

def create_session() -> str:
    return json.dumps({
        "user": "admin",
        "expires": time.time() + (SESSION_EXPIRE_DAYS * 24 * 3600)
    })

def format_bytes(bytes_val: float) -> str:
    if bytes_val == 0:
        return "0 B"
    if bytes_val < 1024:
        return f"{bytes_val:.0f} B"
    if bytes_val < 1024 * 1024:
        return f"{bytes_val/1024:.1f} KB"
    if bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val/(1024*1024):.2f} MB"
    return f"{bytes_val/(1024*1024*1024):.2f} GB"

# ============================================
# SOCKS5 Server
# ============================================

async def start_socks5_server():
    try:
        server = await asyncio.start_server(
            handle_socks5_connection,
            host="0.0.0.0",
            port=SOCKS_PORT,
        )
        print(f"[SOCKS5] Server started on port {SOCKS_PORT}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"[SOCKS5] Failed to start: {e}")

async def handle_socks5_connection(reader, writer):
    config_id = None
    username = None
    bytes_transferred = 0
    addr = writer.get_extra_info('peername')
    client_ip_str = addr[0] if addr else "unknown"
    
    try:
        data = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        version, nmethods = data[0], data[1]
        
        if version != SOCKS5_VERSION:
            writer.close()
            return
        
        methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=5.0)
        
        if 0x02 in methods:
            writer.write(bytes([SOCKS5_VERSION, 0x02]))
            await writer.drain()
            
            data = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            auth_version, ulen = data[0], data[1]
            
            if auth_version != 0x01:
                writer.write(bytes([0x01, 0x01]))
                await writer.drain()
                return
            
            username_bytes = await asyncio.wait_for(reader.readexactly(ulen), timeout=5.0)
            username = username_bytes.decode('utf-8', errors='ignore')
            
            plen_byte = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            plen = plen_byte[0]
            password_bytes = await asyncio.wait_for(reader.readexactly(plen), timeout=5.0)
            password = password_bytes.decode('utf-8', errors='ignore')
            
            data_obj = load_data()
            for cfg in data_obj.socks_configs:
                if cfg.get("username") == username and cfg.get("active", True):
                    pw_hash = hashlib.sha256(f"{password}".encode()).hexdigest()
                    if cfg.get("password_hash") == pw_hash:
                        if cfg.get("limit_bytes", 0) > 0 and cfg.get("used_bytes", 0) >= cfg.get("limit_bytes", 0):
                            continue
                        config_id = cfg.get("config_id")
                        break
            
            if config_id:
                writer.write(bytes([0x01, 0x00]))
                await writer.drain()
            else:
                writer.write(bytes([0x01, 0x01]))
                await writer.drain()
                return
        else:
            writer.write(bytes([SOCKS5_VERSION, 0xFF]))
            await writer.drain()
            return
        
        data = await asyncio.wait_for(reader.readexactly(4), timeout=30.0)
        ver, cmd, rsv, atyp = data[0], data[1], data[2], data[3]
        
        if ver != SOCKS5_VERSION or cmd != SOCKS_CMD_CONNECT:
            reply = bytes([SOCKS5_VERSION, SOCKS5_CMD_NOT_SUPPORTED, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            writer.write(reply)
            await writer.drain()
            return
        
        if atyp == SOCKS_ATYP_IPV4:
            addr_data = await reader.readexactly(4)
            target_addr = ".".join(str(b) for b in addr_data)
        elif atyp == SOCKS_ATYP_DOMAINNAME:
            dlen_byte = await reader.readexactly(1)
            dlen = dlen_byte[0]
            domain = await reader.readexactly(dlen)
            target_addr = domain.decode('utf-8', errors='ignore')
        elif atyp == SOCKS_ATYP_IPV6:
            addr_data = await reader.readexactly(16)
            target_addr = ":".join(f"{addr_data[i]:02x}{addr_data[i+1]:02x}" for i in range(0, 16, 2))
        else:
            reply = bytes([SOCKS5_VERSION, SOCKS5_SERVER_FAILURE, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            writer.write(reply)
            await writer.drain()
            return
        
        port_data = await reader.readexactly(2)
        target_port = int.from_bytes(port_data, 'big')
        
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(target_addr, target_port),
                timeout=15.0
            )
        except:
            reply = bytes([SOCKS5_VERSION, SOCKS5_SERVER_FAILURE, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            writer.write(reply)
            await writer.drain()
            return
        
        reply = bytes([SOCKS5_VERSION, SOCKS5_SUCCEEDED, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        writer.write(reply)
        await writer.drain()
        
        async def relay(src, dst):
            nonlocal bytes_transferred
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    bytes_transferred += len(chunk)
            except:
                pass
        
        await asyncio.gather(
            relay(reader, remote_writer),
            relay(remote_reader, writer),
        )
        
        if config_id:
            data_obj = load_data()
            for cfg in data_obj.socks_configs:
                if cfg.get("config_id") == config_id:
                    cfg["used_bytes"] = cfg.get("used_bytes", 0) + bytes_transferred
                    break
            save_data(data_obj)
            
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[SOCKS5] Error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

# ============================================
# صفحات HTML (کامل - نسخه اصلی)
# ============================================

LOGIN_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ورود · X4G</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#060f1d;--card:rgba(10,22,40,0.9);--accent:#3B82F6;--text:#E8F4FF;--dim:#3D6B8E;--mid:#7BAED4;--border:rgba(59,130,246,0.2)}
html,body{height:100%;overflow:hidden}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);display:flex;align-items:center;justify-content:center;padding:20px}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% 0%,rgba(59,130,246,0.1),transparent 70%),var(--bg);z-index:0}
.grid{position:fixed;inset:0;background-image:linear-gradient(rgba(59,130,246,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,0.04) 1px,transparent 1px);background-size:44px 44px;z-index:0}
.orb{position:fixed;border-radius:50%;filter:blur(90px);z-index:0;animation:fl 9s ease-in-out infinite}
.o1{width:380px;height:380px;background:rgba(59,130,246,0.07);top:-100px;right:-80px}
.o2{width:280px;height:280px;background:rgba(16,185,129,0.04);bottom:-60px;left:-60px;animation-delay:4s}
@keyframes fl{0%,100%{transform:translateY(0)}50%{transform:translateY(-18px)}}
.wrap{position:relative;z-index:10;width:100%;max-width:400px}
.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:38px 34px 34px;backdrop-filter:blur(24px);box-shadow:0 0 80px rgba(59,130,246,0.07),0 20px 60px rgba(0,0,0,.5)}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.brand-img{width:48px;height:48px;border-radius:50%;overflow:hidden;border:1px solid var(--border);box-shadow:0 0 20px rgba(139,92,246,0.35),0 0 12px rgba(59,130,246,0.3);flex-shrink:0}
.brand-img img{width:100%;height:100%;object-fit:cover}
.brand-name{font-size:16px;font-weight:700;color:var(--text)}
.brand-sub{font-size:11px;color:var(--dim);margin-top:2px}
h1{font-size:21px;font-weight:700;color:var(--text);margin-bottom:5px;letter-spacing:-.02em}
.sub{font-size:12px;color:var(--mid);margin-bottom:24px;line-height:1.6}
.hint{display:flex;align-items:center;gap:10px;background:rgba(59,130,246,0.07);border:1px solid rgba(59,130,246,0.15);border-radius:10px;padding:10px 14px;margin-bottom:20px}
.hint-label{font-size:11px;color:var(--dim);flex:1}
.hint-val{font-family:ui-monospace,monospace;font-size:14px;font-weight:700;color:var(--accent);background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);padding:3px 11px;border-radius:7px;cursor:pointer;transition:.15s;letter-spacing:.08em}
.hint-val:hover{background:rgba(59,130,246,0.22)}
.field{margin-bottom:18px}
.field label{display:block;font-size:10.5px;font-weight:600;color:var(--mid);margin-bottom:7px;text-transform:uppercase;letter-spacing:.06em}
.inp-wrap{position:relative}
input[type=password]{width:100%;padding:13px 44px 13px 16px;border-radius:11px;border:1px solid var(--border);background:rgba(0,0,0,.3);color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:.2s}
input[type=password]:focus{border-color:rgba(59,130,246,.55);background:rgba(0,0,0,.4);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.ic{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--dim);font-size:18px;pointer-events:none;transition:.2s}
input:focus+.ic{color:var(--accent)}
.err{display:none;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:12px;color:#F87171;align-items:center;gap:8px}
.err.show{display:flex}
.btn{width:100%;padding:13px;border-radius:11px;border:none;cursor:pointer;background:linear-gradient(135deg,#2F8FFF,#8B5CF6);color:#fff;font-family:inherit;font-size:14px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 20px rgba(139,92,246,.35);transition:.2s;position:relative;overflow:hidden}
.btn::before{content:'';position:absolute;inset:0;background:rgba(255,255,255,.08);opacity:0;transition:.2s}
.btn:hover::before{opacity:1}
.btn:disabled{opacity:.5;cursor:not-allowed}
.footer{margin-top:22px;padding-top:18px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;gap:8px;font-size:11px;color:var(--dim)}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="bg"></div><div class="grid"></div>
<div class="orb o1"></div><div class="orb o2"></div>
<div class="wrap">
  <div class="card">
    <div class="brand">
      <div class="brand-img"><img src="__LOGO_URL__" alt="X4G"></div>
      <div><div class="brand-name">X4G</div><div class="brand-sub">v9.2 + SOCKS5</div></div>
    </div>
    <h1>ورود به پنل</h1>
    <p class="sub">رمز عبور را برای دسترسی به داشبورد وارد کنید</p>
    <div class="err" id="err"><i class="ti ti-alert-circle"></i><span id="err-text"></span></div>
    <div class="hint">
      <span class="hint-label">رمز پیش‌فرض سیستم</span>
      <span class="hint-val" onclick="document.getElementById('pw').value='123456';document.getElementById('pw').focus()">123456</span>
    </div>
    <form id="form">
      <div class="field">
        <label>رمز عبور</label>
        <div class="inp-wrap">
          <input type="password" id="pw" placeholder="رمز عبور را وارد کنید" autofocus required>
          <i class="ti ti-lock ic"></i>
        </div>
      </div>
      <button class="btn" type="submit" id="btn"><i class="ti ti-login-2"></i> ورود به داشبورد</button>
    </form>
    <div class="footer">X4G v9.2 · VLESS + XHTTP + SOCKS5</div>
  </div>
</div>
<script>
document.getElementById('form').addEventListener('submit',async e=>{
  e.preventDefault();
  const btn=document.getElementById('btn'),err=document.getElementById('err'),et=document.getElementById('err-text');
  err.classList.remove('show');btn.disabled=true;
  btn.innerHTML='<i class="ti ti-loader-2" style="animation:spin 1s linear infinite"></i> در حال ورود...';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'خطا');}
    location.href='/dashboard';
  }catch(e){
    et.textContent=e.message;err.classList.add('show');
    btn.disabled=false;btn.innerHTML='<i class="ti ti-login-2"></i> ورود به داشبورد';
  }
});
</script>
</body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X4G Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#060f1d;--bg2:#0a1628;--bg3:#0e1e35;
  --card:#0d1b2e;--card-b:rgba(59,130,246,0.13);--card-bh:rgba(59,130,246,0.28);
  --accent:#3B82F6;--accent2:#60A5FA;--accent-d:rgba(59,130,246,0.12);
  --green:#10B981;--green-bg:rgba(16,185,129,0.1);--green-t:#34D399;
  --red:#EF4444;--red-bg:rgba(239,68,68,0.1);--red-t:#F87171;
  --amber:#F59E0B;--amber-bg:rgba(245,158,11,0.1);--amber-t:#FCD34D;
  --purple:#8B5CF6;--purple-bg:rgba(139,92,246,0.1);
  --t1:#E8F4FF;--t2:#7BAED4;--t3:#3D6B8E;
  --sidebar-w:248px;--radius:16px;
  --shadow:0 4px 24px rgba(0,0,0,0.35);
}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;display:flex;font-size:14px}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg3);border-radius:3px}
.sidebar{width:var(--sidebar-w);min-height:100vh;background:var(--bg2);border-left:1px solid var(--card-b);display:flex;flex-direction:column;flex-shrink:0;position:fixed;right:0;top:0;bottom:0;z-index:200}
.logo{display:flex;align-items:center;gap:12px;padding:20px 16px 16px;border-bottom:1px solid var(--card-b)}
.logo-img{width:38px;height:38px;border-radius:50%;overflow:hidden;border:1px solid var(--card-b);box-shadow:0 0 14px rgba(139,92,246,.3),0 0 8px rgba(59,130,246,.25);flex-shrink:0}
.logo-img img{width:100%;height:100%;object-fit:cover}
.logo-name{font-size:13.5px;font-weight:700;color:var(--t1)}
.logo-sub{font-size:10px;color:var(--t3);margin-top:1px}
.nav-wrap{flex:1;overflow-y:auto;padding:6px 0 8px}
.nav-sec{padding:14px 14px 4px;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);font-weight:700}
.nav-it{display:flex;align-items:center;gap:9px;padding:9px 14px;color:var(--t3);font-size:12.5px;cursor:pointer;border-right:2px solid transparent;transition:all .15s;margin:1px 6px}
.nav-it i{font-size:16px;width:18px;text-align:center;flex-shrink:0}
.nav-it:hover{background:var(--accent-d);color:var(--t2)}
.nav-it.on{background:var(--accent-d);color:var(--t1);border-right-color:var(--accent);font-weight:600}
.nav-badge{margin-right:auto;background:rgba(59,130,246,0.15);color:var(--accent2);font-size:9px;padding:1px 6px;border-radius:20px;font-weight:700}
.sb-foot{padding:12px 14px;border-top:1px solid var(--card-b)}
.logout-btn{display:flex;align-items:center;justify-content:center;gap:7px;background:var(--red-bg);color:var(--red-t);border-radius:9px;padding:8px;font-size:12px;font-weight:500;font-family:inherit;border:1px solid rgba(239,68,68,0.2);cursor:pointer;width:100%;transition:.15s;margin-top:6px}
.logout-btn:hover{background:rgba(239,68,68,0.2)}
.main{margin-right:var(--sidebar-w);flex:1;padding:28px 28px 60px;min-width:0}
.pg{display:none}
.pg.on{display:block;animation:fi .2s ease}
@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:12px}
.tb-title{font-size:18px;font-weight:700;color:var(--t1);display:flex;align-items:center;gap:8px;letter-spacing:-.02em}
.tb-title i{color:var(--accent);font-size:20px}
.tb-sub{font-size:11px;color:var(--t3);margin-top:4px}
.tb-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{font-size:10px;padding:3px 10px;border-radius:20px;font-weight:700;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
.bg-green{background:var(--green-bg);color:var(--green-t)}
.bg-blue{background:var(--accent-d);color:var(--accent2)}
.bg-amber{background:var(--amber-bg);color:var(--amber-t)}
.bg-red{background:var(--red-bg);color:var(--red-t)}
.bg-purple{background:var(--purple-bg);color:#A78BFA}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.dg{background:var(--green)}.dr{background:var(--red)}.da{background:var(--amber)}.db{background:var(--accent)}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:18px}
.metric{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:17px 17px 14px;transition:all .2s;cursor:default}
.metric:hover{border-color:var(--card-bh);transform:translateY(-2px);box-shadow:var(--shadow)}
.m-icon{width:34px;height:34px;border-radius:8px;background:var(--accent-d);display:flex;align-items:center;justify-content:center;margin-bottom:11px;color:var(--accent);font-size:17px}
.m-label{font-size:10px;color:var(--t3);margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.m-val{font-size:25px;font-weight:700;color:var(--t1);line-height:1;letter-spacing:-.02em}
.m-unit{font-size:12px;font-weight:400;color:var(--t3)}
.card{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:18px 20px;transition:border-color .2s;margin-bottom:16px}
.card:hover{border-color:var(--card-bh)}
.card-title{font-size:12.5px;font-weight:700;color:var(--t1);margin-bottom:15px;display:flex;align-items:center;gap:7px}
.card-title i{font-size:16px;color:var(--accent)}
.btn{font-family:inherit;font-size:12px;font-weight:500;border-radius:9px;padding:8px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .15s;white-space:nowrap}
.btn i{font-size:13px}
.btn-p{background:linear-gradient(135deg,#2F8FFF,#8B5CF6);color:#fff;box-shadow:0 2px 14px rgba(139,92,246,.35)}
.btn-p:hover{background:#2563EB}
.btn-o{background:transparent;border:1px solid var(--card-b);color:var(--t2)}
.btn-o:hover{background:var(--accent-d)}
.btn-g{background:var(--accent-d);color:var(--accent2);border:1px solid rgba(59,130,246,.15)}
.btn-d{background:var(--red-bg);color:var(--red-t);border:1px solid rgba(239,68,68,.2)}
.btn-sm{padding:5px 9px;font-size:10.5px;border-radius:7px}
.btn-icon{width:30px;height:30px;padding:0;justify-content:center;border-radius:5px}
.form-row{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end;margin-bottom:12px}
.fg{display:flex;flex-direction:column;gap:5px;flex:1}
.fg label{font-size:10px;color:var(--t3);font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.fi,.fs{padding:9px 12px;border-radius:9px;border:1px solid var(--card-b);background:rgba(0,0,0,.18);color:var(--t1);font-family:inherit;font-size:12px;outline:none;transition:.15s;min-width:100px}
.fi:focus,.fs:focus{border-color:rgba(59,130,246,.45);background:rgba(0,0,0,.25);box-shadow:0 0 0 3px rgba(59,130,246,.08)}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:10px 12px;text-align:right;border-bottom:1px solid rgba(59,130,246,.08)}
th{color:var(--t3);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em}
td{color:var(--t1)}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(40px);background:var(--card);border:1px solid var(--card-b);color:var(--t1);border-radius:10px;padding:10px 18px;font-size:12.5px;opacity:0;transition:all .25s;z-index:999;pointer-events:none;display:flex;align-items:center;gap:8px;box-shadow:var(--shadow);white-space:nowrap}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(16,185,129,.3);background:var(--green-bg);color:var(--green-t)}
.toast.err{border-color:rgba(239,68,68,.3);background:var(--red-bg);color:var(--red-t)}
.sub-box{background:rgba(139,92,246,.07);border:1px solid rgba(139,92,246,.2);border-radius:10px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:11px}
.sub-url{font-family:ui-monospace,monospace;font-size:10.5px;color:#A78BFA;word-break:break-all;flex:1}
@media(max-width:1050px){
  .sidebar{transform:translateX(100%)}
  .main{margin-right:0}
  .metrics{grid-template-columns:1fr 1fr}
}
@media(max-width:500px){
  .metrics{grid-template-columns:1fr}
  .main{padding:62px 12px 50px}
}
</style>
</head>
<body>
<div class="toast" id="toast"></div>
<aside class="sidebar" id="sb">
  <div class="logo">
    <div class="logo-img"><img src="__LOGO_URL__" alt="X4G"></div>
    <div><div class="logo-name">X4G</div><div class="logo-sub">v9.2 + SOCKS5</div></div>
  </div>
  <div class="nav-wrap">
    <div class="nav-sec">پنل</div>
    <div class="nav-it on" data-pg="overview"><i class="ti ti-layout-dashboard"></i> داشبورد</div>
    <div class="nav-it" data-pg="links"><i class="ti ti-link-plus"></i> کانفیگ‌ها <span class="nav-badge" id="links-nb">0</span></div>
    <div class="nav-it" data-pg="subs"><i class="ti ti-folders"></i> گروه‌های ساب <span class="nav-badge" id="subs-nb">0</span></div>
    <div class="nav-it" data-pg="socks"><i class="ti ti-sock"></i> SOCKS5 <span class="nav-badge" id="socks-nb">0</span></div>
    <div class="nav-it" data-pg="subscriptions"><i class="ti ti-rss"></i> سابسکریپشن</div>
    <div class="nav-it" data-pg="settings"><i class="ti ti-settings"></i> تنظیمات</div>
  </div>
  <div class="sb-foot">
    <button class="logout-btn" onclick="logout()"><i class="ti ti-logout"></i> خروج</button>
  </div>
</aside>
<main class="main">

<!-- Overview Page -->
<section class="pg on" id="pg-overview">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-layout-dashboard"></i> داشبورد</div><div class="tb-sub">X4G v9.2 · VLESS + XHTTP + SOCKS5</div></div>
    <div class="tb-right"><span class="badge bg-green"><span class="dot dg pulse"></span> فعال</span></div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="m-icon"><i class="ti ti-plug-connected"></i></div><div class="m-label">اتصالات فعال</div><div class="m-val" id="m-conns">—</div></div>
    <div class="metric"><div class="m-icon"><i class="ti ti-link"></i></div><div class="m-label">کانفیگ‌های فعال</div><div class="m-val" id="m-alinks">—</div></div>
    <div class="metric"><div class="m-icon" style="background:var(--purple-bg);color:var(--purple)"><i class="ti ti-folders"></i></div><div class="m-label">گروه‌های ساب</div><div class="m-val" id="m-subs">—</div></div>
    <div class="metric"><div class="m-icon" style="background:rgba(245,158,11,.1);color:#F59E0B"><i class="ti ti-sock"></i></div><div class="m-label">SOCKS5</div><div class="m-val" id="m-socks">—</div></div>
  </div>
  <button class="btn btn-p" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
</section>

<!-- Links Page -->
<section class="pg" id="pg-links">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-link-plus"></i> کانفیگ‌ها</div><div class="tb-sub">ساخت و مدیریت کانفیگ با سهمیه و انقضا</div></div>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-plus"></i> ساخت کانفیگ جدید</div>
    <div class="form-row">
      <div class="fg"><label>عنوان</label><input class="fi" id="nl-label" placeholder="مثلاً: کاربر علی"></div>
      <div class="fg"><label>پروتکل</label><select class="fs" id="nl-proto"><option value="vless-ws">VLESS/WS</option><option value="xhttp-packet-up">XHTTP packet-up</option><option value="xhttp-stream-up">XHTTP stream-up</option></select></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>سهمیه (0=نامحدود)</label><input class="fi" id="nl-limit" type="number" value="0" min="0"></div>
      <div class="fg"><label>واحد</label><select class="fs" id="nl-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div>
      <div class="fg"><label>انقضا (روز)</label><input class="fi" id="nl-exp" type="number" value="0" min="0"></div>
    </div>
    <button class="btn btn-p" onclick="createLink()"><i class="ti ti-plus"></i> ساخت کانفیگ</button>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-list"></i> لیست کانفیگ‌ها <span class="badge bg-blue" id="links-count">0</span></div>
    <div id="links-list">در حال بارگذاری...</div>
  </div>
</section>

<!-- Subs Page -->
<section class="pg" id="pg-subs">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-folders"></i> گروه‌های ساب</div></div>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-plus"></i> ساخت گروه جدید</div>
    <div class="form-row">
      <div class="fg"><label>نام گروه</label><input class="fi" id="ns-name" placeholder="مثلاً: کانال تلگرام"></div>
      <div class="fg"><label>رمز (اختیاری)</label><input class="fi" id="ns-pw" type="password" placeholder="خالی = بدون رمز"></div>
    </div>
    <button class="btn btn-p" onclick="createSub()"><i class="ti ti-plus"></i> ساخت گروه</button>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-list"></i> لیست گروه‌ها</div>
    <div id="subs-list">در حال بارگذاری...</div>
  </div>
</section>

<!-- SOCKS5 Page -->
<section class="pg" id="pg-socks">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-sock"></i> SOCKS5 Proxy</div><div class="tb-sub">مدیریت پروکسی‌های SOCKS5 با احراز هویت</div></div>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-plus"></i> ساخت کانفیگ SOCKS5 جدید</div>
    <div class="form-row">
      <div class="fg"><label>عنوان</label><input class="fi" id="sk-label" placeholder="مثلاً: پروکسی شخصی"></div>
      <div class="fg"><label>نام کاربری</label><input class="fi" id="sk-user" placeholder="username"></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>رمز عبور</label><input class="fi" id="sk-pass" type="password" placeholder="password"></div>
      <div class="fg"><label>سهمیه (0=نامحدود)</label><input class="fi" id="sk-limit" type="number" value="0" min="0"></div>
      <div class="fg"><label>واحد</label><select class="fs" id="sk-unit"><option value="GB">GB</option><option value="MB">MB</option></select></div>
    </div>
    <button class="btn btn-p" onclick="createSocks()"><i class="ti ti-plus"></i> ساخت SOCKS5</button>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-list"></i> کانفیگ‌های SOCKS5 <span class="badge bg-purple" id="socks-count">0</span></div>
    <div id="socks-list">در حال بارگذاری...</div>
  </div>
</section>

<!-- Subscriptions Page -->
<section class="pg" id="pg-subscriptions">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-rss"></i> سابسکریپشن</div></div></div>
  <div class="card">
    <div class="card-title"><i class="ti ti-database"></i> سابسکریپشن کامل (ادمین)</div>
    <div class="sub-box"><span class="sub-url" id="sub-all-url">در حال دریافت...</span>
      <button class="btn btn-g btn-sm" onclick="navigator.clipboard.writeText(location.protocol+'//'+location.host+'/sub-all')"><i class="ti ti-copy"></i> کپی</button>
    </div>
  </div>
</section>

<!-- Settings Page -->
<section class="pg" id="pg-settings">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-settings"></i> تنظیمات</div></div></div>
  <div class="card">
    <div class="card-title"><i class="ti ti-key"></i> تغییر رمز عبور</div>
    <div class="form-row">
      <div class="fg"><label>رمز فعلی</label><input class="fi" type="password" id="cp-cur"></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>رمز جدید</label><input class="fi" type="password" id="cp-new"></div>
      <div class="fg"><label>تکرار رمز جدید</label><input class="fi" type="password" id="cp-cf"></div>
    </div>
    <button class="btn btn-p" onclick="changePw()"><i class="ti ti-check"></i> ذخیره</button>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-server"></i> اطلاعات سرور</div>
    <div style="font-size:12px;color:var(--t2)">
      <p>🌐 هاست: <strong id="set-host">—</strong></p>
      <p>🔌 پورت VLESS: <strong>443</strong></p>
      <p>🧦 پورت SOCKS5: <strong>SOCKS_PORT_PLACEHOLDER</strong></p>
      <p>📦 نسخه: <strong>v9.2 + SOCKS5</strong></p>
    </div>
  </div>
</section>

</main>

<script>
// Navigation
document.querySelectorAll('.nav-it[data-pg]').forEach(el=>{
  el.addEventListener('click',()=>{
    document.querySelectorAll('.nav-it').forEach(n=>n.classList.remove('on'));
    document.querySelectorAll('.pg').forEach(p=>p.classList.remove('on'));
    el.classList.add('on');
    document.getElementById('pg-'+el.dataset.pg).classList.add('on');
    if(el.dataset.pg==='links')loadLinks();
    if(el.dataset.pg==='subs')loadSubs();
    if(el.dataset.pg==='socks')loadSocks();
    if(el.dataset.pg==='subscriptions')document.getElementById('sub-all-url').textContent=location.protocol+'//'+location.host+'/sub-all';
  });
});

function toast(msg,ok=true){
  const t=document.getElementById('toast');
  t.textContent=msg;t.className='toast show'+(ok?' ok':' err');
  setTimeout(()=>t.classList.remove('show'),2500);
}

async function api(url,opts={}){
  const r=await fetch(url,opts);
  if(r.status===401){location.href='/login';throw new Error('unauthorized')}
  return r;
}

function fmtB(b){if(!b||b===0)return'0 B';if(b<1024)return b+' B';if(b<1024**2)return(b/1024).toFixed(1)+' KB';if(b<1024**3)return(b/1024**2).toFixed(2)+' MB';return(b/1024**3).toFixed(2)+' GB'}

// Links
async function loadLinks(){
  try{
    const r=await api('/api/links'),d=await r.json();
    document.getElementById('links-count').textContent=d.links.length;
    document.getElementById('links-nb').textContent=d.links.length;
    const links=d.links||[];
    if(!links.length){document.getElementById('links-list').innerHTML='<p style="color:var(--t3);padding:20px">هنوز کانفیگی وجود ندارد</p>';return}
    document.getElementById('links-list').innerHTML=`
      <table><thead><tr><th>عنوان</th><th>پروتکل</th><th>مصرف</th><th>سهمیه</th><th>وضعیت</th><th>عملیات</th></tr></thead>
      <tbody>${links.map(l=>`
        <tr>
          <td><strong>${l.label}</strong></td>
          <td>${l.protocol}</td>
          <td>${fmtB(l.used_bytes)}</td>
          <td>${l.limit_bytes==0?'∞':fmtB(l.limit_bytes)}</td>
          <td><span class="badge ${l.active&&!l.expired?'bg-green':l.expired?'bg-amber':'bg-red'}">${l.active&&!l.expired?'فعال':l.expired?'منقضی':'غیرفعال'}</span></td>
          <td>
            <button class="btn btn-o btn-sm" onclick="navigator.clipboard.writeText('${l.vless_link.replace(/'/g,"\\'")}')">📋</button>
            <button class="btn btn-d btn-sm" onclick="deleteLink('${l.uuid}')">🗑</button>
          </td>
        </tr>
      `).join('')}</tbody></table>`;
  }catch(e){}
}

async function createLink(){
  const label=document.getElementById('nl-label').value.trim()||'کانفیگ جدید';
  const protocol=document.getElementById('nl-proto').value;
  const limit=parseFloat(document.getElementById('nl-limit').value)||0;
  const unit=document.getElementById('nl-unit').value;
  const exp=parseInt(document.getElementById('nl-exp').value)||0;
  try{
    await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,protocol,limit_value:limit,limit_unit:unit,expires_days:exp})});
    toast('✅ کانفیگ ساخته شد');
    document.getElementById('nl-label').value='';
    loadLinks();
  }catch(e){toast('خطا',false)}
}

async function deleteLink(uuid){
  if(!confirm('حذف شود؟'))return;
  try{await api('/api/links/'+uuid,{method:'DELETE'});toast('✅ حذف شد');loadLinks();}catch(e){toast('خطا',false)}
}

// Subs
async function loadSubs(){
  try{
    const r=await api('/api/subs'),d=await r.json();
    document.getElementById('subs-nb').textContent=d.subs.length;
    const subs=d.subs||[];
    if(!subs.length){document.getElementById('subs-list').innerHTML='<p style="color:var(--t3);padding:20px">هنوز گروهی وجود ندارد</p>';return}
    document.getElementById('subs-list').innerHTML=subs.map(s=>`
      <div style="padding:12px;border:1px solid var(--card-b);border-radius:10px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
        <div><strong>${s.name}</strong> <span style="font-size:11px;color:var(--t3)">${s.links_count} کانفیگ · ${s.active_count} فعال</span> ${s.has_password?'🔒':''}</div>
        <div>
          <button class="btn btn-o btn-sm" onclick="navigator.clipboard.writeText('${s.public_url}')">📋</button>
          <button class="btn btn-d btn-sm" onclick="deleteSub('${s.sub_id}')">🗑</button>
        </div>
      </div>
    `).join('');
  }catch(e){}
}

async function createSub(){
  const name=document.getElementById('ns-name').value.trim()||'گروه جدید';
  const password=document.getElementById('ns-pw').value;
  try{
    await api('/api/subs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,password})});
    toast('✅ گروه ساخته شد');
    document.getElementById('ns-name').value='';document.getElementById('ns-pw').value='';
    loadSubs();
  }catch(e){toast('خطا',false)}
}

async function deleteSub(id){
  if(!confirm('حذف شود؟'))return;
  try{await api('/api/subs/'+id,{method:'DELETE'});toast('✅ حذف شد');loadSubs();}catch(e){toast('خطا',false)}
}

// SOCKS5
async function loadSocks(){
  try{
    const r=await api('/api/socks'),d=await r.json();
    document.getElementById('socks-count').textContent=d.socks?.length||0;
    document.getElementById('socks-nb').textContent=d.socks?.length||0;
    const socks=d.socks||[];
    if(!socks.length){document.getElementById('socks-list').innerHTML='<p style="color:var(--t3);padding:20px">هنوز کانفیگ SOCKS5 وجود ندارد</p>';return}
    document.getElementById('socks-list').innerHTML=`
      <table><thead><tr><th>عنوان</th><th>یوزرنیم</th><th>مصرف</th><th>سهمیه</th><th>وضعیت</th><th>عملیات</th></tr></thead>
      <tbody>${socks.map(s=>`
        <tr>
          <td><strong>${s.label}</strong></td>
          <td><code>${s.username}</code></td>
          <td>${s.used_fmt}</td>
          <td>${s.limit_fmt}</td>
          <td><span class="badge ${s.active?'bg-green':'bg-red'}">${s.active?'فعال':'غیرفعال'}</span></td>
          <td>
            <button class="btn btn-o btn-sm" onclick="toggleSocks('${s.config_id}',${!s.active})">🔄</button>
            <button class="btn btn-d btn-sm" onclick="deleteSocks('${s.config_id}')">🗑</button>
          </td>
        </tr>
      `).join('')}</tbody></table>`;
  }catch(e){}
}

async function createSocks(){
  const label=document.getElementById('sk-label').value.trim()||'SOCKS5';
  const username=document.getElementById('sk-user').value.trim()||'user_'+Math.random().toString(36).slice(2,8);
  const password=document.getElementById('sk-pass').value||Math.random().toString(36).slice(2,14);
  const limit=parseFloat(document.getElementById('sk-limit').value)||0;
  const unit=document.getElementById('sk-unit').value;
  try{
    const r=await api('/api/socks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,username,password,limit_value:limit,limit_unit:unit})});
    if(!r.ok)throw new Error();
    const d=await r.json();
    toast(`✅ SOCKS5 ساخته شد\\nکاربر: ${d.username} | رمز: ${d.password}\\nپورت: ${d.port}`);
    document.getElementById('sk-label').value='';document.getElementById('sk-user').value='';document.getElementById('sk-pass').value='';
    loadSocks();
  }catch(e){toast('خطا',false)}
}

async function toggleSocks(id,active){
  try{await api('/api/socks/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active})});toast('✅ بروز شد');loadSocks();}catch(e){toast('خطا',false)}
}

async function deleteSocks(id){
  if(!confirm('حذف شود؟'))return;
  try{await api('/api/socks/'+id,{method:'DELETE'});toast('✅ حذف شد');loadSocks();}catch(e){toast('خطا',false)}
}

// Change Password
async function changePw(){
  const cur=document.getElementById('cp-cur').value;
  const nw=document.getElementById('cp-new').value;
  const cf=document.getElementById('cp-cf').value;
  if(!cur||!nw||!cf){toast('همه فیلدها را پر کنید',false);return}
  if(nw!==cf){toast('تکرار رمز اشتباه',false);return}
  if(nw.length<4){toast('حداقل ۴ کاراکتر',false);return}
  try{
    await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
    toast('✅ رمز تغییر کرد');
    document.getElementById('cp-cur').value='';document.getElementById('cp-new').value='';document.getElementById('cp-cf').value='';
  }catch(e){toast('خطا',false)}
}

async function refreshAll(){
  try{
    const r=await api('/stats'),d=await r.json();
    document.getElementById('m-conns').textContent=d.active_connections||0;
    document.getElementById('m-alinks').textContent=d.active_links||0;
    document.getElementById('m-subs').textContent=d.subs_count||0;
    document.getElementById('m-socks').textContent=d.socks_count||0;
  }catch(e){}
  loadLinks();loadSubs();loadSocks();
}

async function logout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/login';
}

// Init
document.getElementById('set-host').textContent=location.host;
document.getElementById('sub-all-url').textContent=location.protocol+'//'+location.host+'/sub-all';
document.querySelector('.card:has(#set-host) p:contains("SOCKS5")').innerHTML='🧦 پورت SOCKS5: <strong>SOCKS_PORT_PLACEHOLDER</strong>';
refreshAll();
</script>
</body></html>"""

# ============================================
# FastAPI App
# ============================================

app = FastAPI(title="X4G Panel", version="9.2")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(LOGIN_HTML.replace("__LOGO_URL__", LOGO_URL))

@app.post("/api/login")
async def api_login(request: Request):
    data = await request.json()
    password = data.get("password", "")
    if password == PASSWORD:
        session = create_session()
        response = JSONResponse({"success": True})
        response.set_cookie("x4g_session", session, httponly=True, max_age=SESSION_EXPIRE_DAYS*86400, path="/")
        return response
    raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")

@app.post("/api/logout")
async def api_logout():
    response = JSONResponse({"success": True})
    response.delete_cookie("x4g_session", path="/")
    return response

@app.get("/api/me")
async def api_me(request: Request):
    user = get_session_user(request)
    return {"authenticated": bool(user), "user": user}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not get_session_user(request):
        return RedirectResponse(url="/login")
    html = DASHBOARD_HTML.replace("__LOGO_URL__", LOGO_URL)
    html = html.replace("SOCKS_PORT_PLACEHOLDER", str(SOCKS_PORT))
    return HTMLResponse(html)

# ============================================
# VLESS Links API
# ============================================

@app.get("/api/links")
async def get_links(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    links_with_status = []
    for l in data.links:
        l_dict = l.dict()
        l_dict["expired"] = l.expires_at and datetime.fromisoformat(l.expires_at) < datetime.now()
        links_with_status.append(l_dict)
    return {"links": links_with_status}

@app.post("/api/links")
async def create_link(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    body = await request.json()
    data = load_data()
    new_uuid = str(uuid.uuid4())
    
    limit_value = float(body.get("limit_value", 0))
    limit_unit = body.get("limit_unit", "GB")
    if limit_value > 0:
        mult = 1024**3 if limit_unit == "GB" else 1024**2
        limit_bytes = limit_value * mult
    else:
        limit_bytes = 0
    
    expires_days = int(body.get("expires_days", 0))
    expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    
    base_url = get_base_url(request)
    link = Link(
        uuid=new_uuid,
        label=body.get("label", "کانفیگ جدید"),
        protocol=body.get("protocol", "vless-ws"),
        fingerprint=body.get("fingerprint", "chrome"),
        alpn=body.get("alpn", ""),
        port=int(body.get("port", 443)),
        ip_limit=int(body.get("ip_limit", 0)),
        limit_bytes=limit_bytes,
        used_bytes=0,
        created_at=datetime.now().isoformat(),
        expires_at=expires_at,
        active=True,
        sub_id=body.get("sub_id"),
    )
    link.vless_link = generate_vless_link(link, base_url)
    link.sub_url = generate_sub_url(link, base_url)
    data.links.append(link)
    save_data(data)
    return {"success": True, "uuid": new_uuid}

@app.patch("/api/links/{link_uuid}")
async def update_link(link_uuid: str, request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    body = await request.json()
    data = load_data()
    link = next((l for l in data.links if l.uuid == link_uuid), None)
    if not link:
        raise HTTPException(status_code=404, detail="یافت نشد")
    
    for field in ["label","note","active","fingerprint","alpn","sub_id"]:
        if field in body:
            setattr(link, field, body[field])
    if "port" in body: link.port = int(body["port"])
    if "ip_limit" in body: link.ip_limit = int(body["ip_limit"])
    if "reset_usage" in body and body["reset_usage"]: link.used_bytes = 0
    if "limit_value" in body:
        lv = float(body["limit_value"])
        lu = body.get("limit_unit", "GB")
        link.limit_bytes = lv * (1024**3 if lu == "GB" else 1024**2) if lv > 0 else 0
    if "expires_days" in body:
        ed = int(body["expires_days"])
        link.expires_at = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
    
    base_url = get_base_url(request)
    link.vless_link = generate_vless_link(link, base_url)
    save_data(data)
    return {"success": True}

@app.delete("/api/links/{link_uuid}")
async def delete_link(link_uuid: str, request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    data.links = [l for l in data.links if l.uuid != link_uuid]
    save_data(data)
    return {"success": True}

# ============================================
# Sub Groups API
# ============================================

@app.get("/api/subs")
async def get_subs(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    base_url = get_base_url(request)
    subs_list = []
    for sub in data.subs:
        sub_dict = sub.dict()
        links_in_sub = [l for l in data.links if l.uuid in sub.link_ids]
        sub_dict["links_count"] = len(links_in_sub)
        sub_dict["active_count"] = len([l for l in links_in_sub if l.active])
        total_used = sum(l.used_bytes for l in links_in_sub)
        sub_dict["total_used_fmt"] = format_bytes(total_used)
        sub_dict["public_url"] = generate_public_url(sub, base_url)
        sub_dict["sub_url"] = generate_sub_group_url(sub, base_url)
        subs_list.append(sub_dict)
    return {"subs": subs_list}

@app.post("/api/subs")
async def create_sub(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    body = await request.json()
    data = load_data()
    
    new_sub_id = str(uuid.uuid4())[:8]
    password = body.get("password", "")
    
    sub = SubGroup(
        sub_id=new_sub_id,
        name=body.get("name", "گروه جدید"),
        desc=body.get("desc", ""),
        has_password=bool(password),
        password_hash=hash_password(password) if password else "",
        link_ids=[],
        created_at=datetime.now().isoformat(),
    )
    
    data.subs.append(sub)
    save_data(data)
    return {"success": True, "sub_id": new_sub_id}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    body = await request.json()
    data = load_data()
    sub = next((s for s in data.subs if s.sub_id == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404)
    if "name" in body: sub.name = body["name"]
    if "desc" in body: sub.desc = body["desc"]
    if "link_ids" in body: sub.link_ids = body["link_ids"]
    save_data(data)
    return {"success": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    data.subs = [s for s in data.subs if s.sub_id != sub_id]
    save_data(data)
    return {"success": True}

# ============================================
# SOCKS5 API
# ============================================

@app.get("/api/socks")
async def get_socks(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    socks_list = []
    for cfg in data.socks_configs:
        socks_list.append({
            "config_id": cfg.get("config_id"),
            "label": cfg.get("label"),
            "username": cfg.get("username"),
            "used_bytes": cfg.get("used_bytes", 0),
            "used_fmt": format_bytes(cfg.get("used_bytes", 0)),
            "limit_bytes": cfg.get("limit_bytes", 0),
            "limit_fmt": "∞" if cfg.get("limit_bytes", 0) == 0 else format_bytes(cfg.get("limit_bytes", 0)),
            "active": cfg.get("active", True),
            "created_at": cfg.get("created_at"),
            "port": SOCKS_PORT,
        })
    return {"socks": socks_list, "port": SOCKS_PORT}

@app.post("/api/socks")
async def create_socks(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    body = await request.json()
    data = load_data()
    
    config_id = f"socks_{secrets.token_hex(6)}"
    username = body.get("username") or f"user_{secrets.token_hex(4)}"
    password = body.get("password") or secrets.token_urlsafe(10)
    
    lv = float(body.get("limit_value", 0))
    lu = body.get("limit_unit", "GB")
    limit_bytes = lv * (1024**3 if lu == "GB" else 1024**2) if lv > 0 else 0
    
    cfg = {
        "config_id": config_id,
        "label": body.get("label", "SOCKS5"),
        "username": username,
        "password_hash": hashlib.sha256(f"{password}".encode()).hexdigest(),
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "created_at": datetime.now().isoformat(),
        "active": True,
    }
    data.socks_configs.append(cfg)
    save_data(data)
    
    return {
        "success": True,
        "config_id": config_id,
        "username": username,
        "password": password,
        "port": SOCKS_PORT,
        "socks_link": f"socks5://{username}:{password}@{request.url.hostname}:{SOCKS_PORT}",
    }

@app.patch("/api/socks/{config_id}")
async def update_socks(config_id: str, request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    body = await request.json()
    data = load_data()
    for cfg in data.socks_configs:
        if cfg.get("config_id") == config_id:
            if "label" in body: cfg["label"] = body["label"]
            if "active" in body: cfg["active"] = bool(body["active"])
            if "reset_usage" in body: cfg["used_bytes"] = 0
            if "limit_value" in body:
                lv = float(body["limit_value"])
                lu = body.get("limit_unit", "GB")
                cfg["limit_bytes"] = lv * (1024**3 if lu == "GB" else 1024**2) if lv > 0 else 0
            break
    save_data(data)
    return {"success": True}

@app.delete("/api/socks/{config_id}")
async def delete_socks(config_id: str, request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    data.socks_configs = [c for c in data.socks_configs if c.get("config_id") != config_id]
    save_data(data)
    return {"success": True}

# ============================================
# Stats & Other APIs
# ============================================

@app.get("/stats")
async def get_stats(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    return {
        "active_connections": len(socks_connections),
        "total_traffic_mb": 0,
        "active_links": len([l for l in data.links if l.active]),
        "links_count": len(data.links),
        "subs_count": len(data.subs),
        "socks_count": len(data.socks_configs),
        "total_errors": len(data.error_logs),
        "uptime": "فعال",
        "recent_errors": [],
        "hourly": {},
    }

@app.get("/api/activity")
async def get_activity(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    return {"logs": data.activity_logs[-50:]}

@app.get("/api/connections")
async def get_connections(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    return {"connections": [], "count": 0}

@app.post("/api/change-password")
async def change_password(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    global PASSWORD
    body = await request.json()
    if body.get("current_password") != PASSWORD:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = body.get("new_password", "")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="حداقل ۴ کاراکتر")
    PASSWORD = new
    return {"success": True}

# ============================================
# Subscription Endpoints
# ============================================

@app.get("/sub/{link_uuid}")
async def sub_link(link_uuid: str):
    data = load_data()
    link = next((l for l in data.links if l.uuid == link_uuid and l.active), None)
    if not link:
        raise HTTPException(status_code=404)
    return PlainTextResponse(link.vless_link)

@app.get("/sub-all")
async def sub_all(request: Request):
    if not get_session_user(request):
        raise HTTPException(status_code=401)
    data = load_data()
    return PlainTextResponse("\n".join([l.vless_link for l in data.links if l.active]))

@app.get("/sub-group/{sub_id}")
async def sub_group(sub_id: str, request: Request, pw: str = ""):
    data = load_data()
    sub = next((s for s in data.subs if s.sub_id == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404)
    if sub.has_password and (not pw or not verify_password(pw, sub.password_hash)):
        raise HTTPException(status_code=403)
    links_in_sub = [l for l in data.links if l.uuid in sub.link_ids and l.active]
    return PlainTextResponse("\n".join([l.vless_link for l in links_in_sub]))

@app.get("/public/{sub_id}", response_class=HTMLResponse)
async def public_page(sub_id: str):
    return HTMLResponse(f"<h1>گروه {sub_id}</h1><p>صفحه پابلیک</p>")

@app.get("/api/public/sub/{sub_id}")
async def get_public_sub(sub_id: str, request: Request, pw: str = ""):
    data = load_data()
    sub = next((s for s in data.subs if s.sub_id == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404)
    if sub.has_password:
        if not pw or not verify_password(pw, sub.password_hash):
            return {"locked": True, "name": sub.name}
    
    links_in_sub = [l for l in data.links if l.uuid in sub.link_ids]
    total_used = sum(l.used_bytes for l in links_in_sub)
    base_url = get_base_url(request)
    
    return {
        "locked": False,
        "name": sub.name,
        "desc": sub.desc,
        "links": [{"uuid": l.uuid, "label": l.label, "active": l.active, "used_fmt": format_bytes(l.used_bytes), "vless_link": l.vless_link} for l in links_in_sub],
        "total_used_fmt": format_bytes(total_used),
        "active_connections": 0,
        "sub_url": generate_sub_group_url(sub, base_url),
    }

# ============================================
# WebSocket
# ============================================

@app.websocket("/ws/{link_uuid}")
async def websocket_endpoint(websocket: WebSocket, link_uuid: str):
    await websocket.accept()
    data = load_data()
    link = next((l for l in data.links if l.uuid == link_uuid), None)
    if not link or not link.active:
        await websocket.close(code=1008)
        return
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass

# ============================================
# Startup
# ============================================

@app.on_event("startup")
async def startup():
    asyncio.create_task(start_socks5_server())
    print(f"🚀 X4G v9.2 started | SOCKS5 on port {SOCKS_PORT}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
