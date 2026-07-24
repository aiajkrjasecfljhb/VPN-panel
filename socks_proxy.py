"""
SOCKS5 Proxy - کانفیگ‌های پروکسی SOCKS5 با پشتیبانی کاربری و محدودیت حجم
"""
import asyncio
import struct
import time
import hashlib
from typing import Dict, Optional, Tuple
from collections import defaultdict

# SOCKS5 Constants
SOCKS5_VERSION = 0x05
SOCKS_CMD_CONNECT = 0x01
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAINNAME = 0x03
SOCKS_ATYP_IPV6 = 0x04
SOCKS5_SUCCEEDED = 0x00
SOCKS5_SERVER_FAILURE = 0x01
SOCKS5_CMD_NOT_SUPPORTED = 0x07

class SOCKS5ProxyManager:
    def __init__(self):
        self.configs: Dict[str, dict] = {}  # config_id -> config_data
        self.users: Dict[str, dict] = {}    # username -> {password_hash, config_id}
        self.traffic: Dict[str, int] = defaultdict(int)  # username -> bytes
        self.connections: Dict[str, dict] = {}  # connection_id -> {username, start_time, bytes}

    def create_config(self, config_id: str, label: str, username: str, password: str, 
                     limit_bytes: int = 0) -> dict:
        """ایجاد یک کانفیگ SOCKS5 جدید"""
        password_hash = hashlib.sha256(f"{password}".encode()).hexdigest()
        
        config = {
            "config_id": config_id,
            "label": label,
            "username": username,
            "password_hash": password_hash,
            "limit_bytes": limit_bytes,  # 0 = نامحدود
            "used_bytes": 0,
            "created_at": time.time(),
            "active": True,
            "connections": 0,
        }
        
        self.configs[config_id] = config
        self.users[username] = {
            "password_hash": password_hash,
            "config_id": config_id,
        }
        
        return config

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """تصدیق هویت کاربر. برگشت: config_id یا None"""
        if username not in self.users:
            return None
        
        user = self.users[username]
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if user["password_hash"] != password_hash:
            return None
        
        config_id = user["config_id"]
        config = self.configs.get(config_id)
        
        if not config or not config["active"]:
            return None
        
        # بررسی محدودیت حجم
        if config["limit_bytes"] > 0 and config["used_bytes"] >= config["limit_bytes"]:
            return None
        
        return config_id

    def record_traffic(self, config_id: str, username: str, bytes_used: int):
        """ثبت مصرف حجم"""
        if config_id in self.configs:
            self.configs[config_id]["used_bytes"] += bytes_used
        
        if username:
            self.traffic[username] += bytes_used

    def get_config_stats(self, config_id: str) -> dict:
        """آمار مصرف کانفیگ"""
        if config_id not in self.configs:
            return {}
        
        config = self.configs[config_id]
        used = config.get("used_bytes", 0)
        limit = config.get("limit_bytes", 0)
        
        return {
            "config_id": config_id,
            "label": config.get("label"),
            "username": config.get("username"),
            "used_bytes": used,
            "limit_bytes": limit,
            "used_fmt": self._fmt_bytes(used),
            "limit_fmt": "∞" if limit == 0 else self._fmt_bytes(limit),
            "percentage": round((used / limit * 100), 2) if limit > 0 else 0,
            "active": config.get("active", True),
        }

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        if b < 1024 ** 2:
            return f"{b / 1024:.1f} KB"
        if b < 1024 ** 3:
            return f"{b / 1024 ** 2:.2f} MB"
        return f"{b / 1024 ** 3:.2f} GB"

    def list_configs(self) -> list:
        """لیست تمام کانفیگ‌ها"""
        result = []
        for config in self.configs.values():
            stat = self.get_config_stats(config["config_id"])
            result.append(stat)
        return result


# Global instance
socks_manager = SOCKS5ProxyManager()


class SOCKS5Handler:
    """هندلر SOCKS5 برای اتصالات تکی"""
    
    def __init__(self, reader, writer, manager: SOCKS5ProxyManager):
        self.reader = reader
        self.writer = writer
        self.manager = manager
        self.username: Optional[str] = None
        self.config_id: Optional[str] = None
        self.bytes_transferred = 0

    async def handle(self):
        try:
            # مرحله 1: تصدیق SOCKS5
            await self._handle_greeting()
            
            # مرحله 2: احراز هویت
            await self._handle_auth()
            
            # مرحله 3: پردازش درخواست اتصال
            await self._handle_connect_request()
            
        except Exception as e:
            print(f"SOCKS5 Error: {e}")
        finally:
            self.manager.record_traffic(self.config_id, self.username, self.bytes_transferred)
            self.writer.close()
            await self.writer.wait_closed()

    async def _handle_greeting(self):
        """VER | NMETHODS | METHODS"""
        data = await self.reader.readexactly(2)
        version, nmethods = data[0], data[1]
        
        if version != SOCKS5_VERSION:
            raise ValueError("Invalid SOCKS version")
        
        methods = await self.reader.readexactly(nmethods)
        
        # ما فقط USERNAME/PASSWORD رو پشتیبانی می‌کنیم (0x02)
        if 0x02 not in methods:
            self.writer.write(bytes([SOCKS5_VERSION, 0xFF]))
            await self.writer.drain()
            raise ValueError("No supported auth method")
        
        # Select USERNAME/PASSWORD authentication
        self.writer.write(bytes([SOCKS5_VERSION, 0x02]))
        await self.writer.drain()

    async def _handle_auth(self):
        """USERNAME/PASSWORD Authentication (RFC 1929)"""
        # VER | ULEN | UNAME | PLEN | PASSWD
        data = await self.reader.readexactly(2)
        version, ulen = data[0], data[1]
        
        if version != 0x01:
            raise ValueError("Invalid auth version")
        
        username = await self.reader.readexactly(ulen)
        username_str = username.decode('utf-8', errors='ignore')
        
        plen_byte = await self.reader.readexactly(1)
        plen = plen_byte[0]
        
        password = await self.reader.readexactly(plen)
        password_str = password.decode('utf-8', errors='ignore')
        
        # تصدیق هویت
        config_id = self.manager.authenticate(username_str, password_str)
        
        if config_id:
            self.username = username_str
            self.config_id = config_id
            # Success: VER | STATUS (0x00)
            self.writer.write(bytes([0x01, 0x00]))
            await self.writer.drain()
        else:
            # Failure: VER | STATUS (non-zero)
            self.writer.write(bytes([0x01, 0x01]))
            await self.writer.drain()
            raise ValueError("Authentication failed")

    async def _handle_connect_request(self):
        """CONNECT request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT"""
        data = await self.reader.readexactly(4)
        version, cmd, _, atyp = data[0], data[1], data[2], data[3]
        
        if version != SOCKS5_VERSION:
            raise ValueError("Invalid SOCKS version")
        
        if cmd != SOCKS_CMD_CONNECT:
            await self._send_reply(SOCKS5_CMD_NOT_SUPPORTED)
            raise ValueError("Only CONNECT is supported")
        
        # Parse destination address
        if atyp == SOCKS_ATYP_IPV4:  # IPv4
            addr_data = await self.reader.readexactly(4)
            addr = ".".join(str(b) for b in addr_data)
        elif atyp == SOCKS_ATYP_DOMAINNAME:  # Domain name
            dlen_byte = await self.reader.readexactly(1)
            dlen = dlen_byte[0]
            domain = await self.reader.readexactly(dlen)
            addr = domain.decode('utf-8', errors='ignore')
        elif atyp == SOCKS_ATYP_IPV6:  # IPv6
            addr_data = await self.reader.readexactly(16)
            addr = ":".join(f"{int.from_bytes(addr_data[i:i+2], 'big'):x}" for i in range(0, 16, 2))
        else:
            await self._send_reply(SOCKS5_SERVER_FAILURE)
            raise ValueError("Unsupported address type")
        
        # Parse port
        port_data = await self.reader.readexactly(2)
        port = int.from_bytes(port_data, 'big')
        
        # اتصال به سرور خروج
        try:
            remote_reader, remote_writer = await asyncio.open_connection(addr, port)
        except Exception as e:
            await self._send_reply(SOCKS5_SERVER_FAILURE)
            raise e
        
        # ارسال پاسخ موفق
        await self._send_reply(SOCKS5_SUCCEEDED, addr, port)
        
        # عبور ترافیک دو طرفه
        await asyncio.gather(
            self._relay(self.reader, remote_writer),
            self._relay(remote_reader, self.writer),
        )

    async def _send_reply(self, status: int, addr: str = "0.0.0.0", port: int = 0):
        """ارسال SOCKS5 reply"""
        reply = bytes([SOCKS5_VERSION, status, 0x00, SOCKS_ATYP_IPV4])
        addr_bytes = bytes(int(x) for x in addr.split("."))
        port_bytes = port.to_bytes(2, 'big')
        self.writer.write(reply + addr_bytes + port_bytes)
        await self.writer.drain()

    async def _relay(self, reader, writer):
        """عبور دادن ترافیک"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                self.bytes_transferred += len(data)
        except:
            pass
        finally:
            writer.close()
            await writer.wait_closed()
