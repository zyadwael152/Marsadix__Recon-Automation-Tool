import asyncio
import json
import logging
import urllib.request
from typing import Set, List, Dict, Tuple
from .merger import merge_and_track

logger = logging.getLogger(__name__)

async def run_cli_tool(tool_name: str, command: List[str]) -> Tuple[str, Set[str]]:
    """تشغيل أداة من سطر الأوامر واستخراج النطاقات"""
    subdomains = set()
    logger.info(f"[*] جاري تشغيل {tool_name}...")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        
        if stdout:
            for line in stdout.decode().splitlines():
                sub = line.strip().lower()
                if sub:
                    subdomains.add(sub)
        logger.info(f"[+] {tool_name} اكتشفت {len(subdomains)} نطاق.")
    except Exception as e:
        logger.warning(f"[-] تم تخطي {tool_name} بسبب خطأ: {e}")
    
    return tool_name, subdomains

async def fetch_crtsh(domain: str) -> Tuple[str, Set[str]]:
    """الاستعلام من crt.sh عبر الـ API"""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info("[*] جاري الاستعلام من crt.sh...")
    try:
        loop = asyncio.get_event_loop()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = await loop.run_in_executor(None, urllib.request.urlopen, req)
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            for entry in data:
                name_value = entry.get('name_value', '').lower()
                for sub in name_value.split('\n'):
                    sub = sub.strip()
                    if sub and not sub.startswith('*'):
                        subdomains.add(sub)
        logger.info(f"[+] crt.sh اكتشفت {len(subdomains)} نطاق.")
    except Exception as e:
        logger.warning(f"[-] تم تخطي crt.sh بسبب خطأ: {e}")
        
    return "crt.sh", subdomains

async def _async_discover(domain: str) -> Dict[str, List[str]]:
    """تشغيل الأدوات وجمع النتائج"""
    tasks = [
        run_cli_tool("subfinder", ["subfinder", "-d", domain, "-silent"]),
        run_cli_tool("assetfinder", ["assetfinder", "--subs-only", domain]),
        fetch_crtsh(domain)
    ]
    results = await asyncio.gather(*tasks)
    tool_outputs = {tool_name: subs for tool_name, subs in results}
    
    # دمج النتائج
    return merge_and_track(tool_outputs)

def discover_subdomains(domain: str, *args, **kwargs) -> Dict[str, List[str]]:
    """نقطة الدخول (Entry Point) الأساسية التي سيتم استدعاؤها من الـ CLI"""
    return asyncio.run(_async_discover(domain))
