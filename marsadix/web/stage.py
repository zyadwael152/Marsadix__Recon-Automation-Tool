import logging
import asyncio
from .probe import run_httpx

logger = logging.getLogger(__name__)

def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage ===")
    
    subdomains = set()
    
    # استخراج النطاقات من قاعدة بيانات الأداة SQLite (ctx.conn)
    if hasattr(ctx, 'conn'):
        try:
            cur = ctx.conn.cursor()
            # 1. البحث عن اسم الجدول (assets أو nodes)
            cur.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            
            target_table = None
            for t in ['assets', 'nodes', 'subdomains', 'recon']:
                if t in tables:
                    target_table = t
                    break
                    
            if target_table:
                # 2. معرفة اسم العمود اللي متخزن فيه النطاق
                cur.execute(f"PRAGMA table_info({target_table})")
                columns = [c[1] for c in cur.fetchall()]
                
                col_name = None
                for candidate in ['name', 'domain', 'host', 'asset', 'subdomain']:
                    if candidate in columns:
                        col_name = candidate
                        break
                        
                # 3. سحب النطاقات
                if col_name:
                    if 'scan_id' in columns and hasattr(ctx, 'scan'):
                        scan_id = getattr(ctx.scan, 'id', ctx.scan)
                        if isinstance(scan_id, int):
                            cur.execute(f"SELECT {col_name} FROM {target_table} WHERE scan_id=?", (scan_id,))
                        else:
                            cur.execute(f"SELECT {col_name} FROM {target_table}")
                    else:
                        cur.execute(f"SELECT {col_name} FROM {target_table}")
                        
                    for row in cur.fetchall():
                        if row[0]: subdomains.add(row[0])
        except Exception as e:
            logger.error(f"[-] Database extraction error: {e}")

    subdomains = list(subdomains)

    if not subdomains:
        logger.warning("[-] No subdomains found in Database. Skipping Web stage.")
        return {"live_urls": []}

    logger.info(f"[+] Successfully loaded {len(subdomains)} subdomains from Database.")
    
    # 4. تشغيل httpx لمعرفة المواقع اللي عليها Web Server شغال
    live_urls = asyncio.run(run_httpx(subdomains))
    
    return {
        "live_urls": live_urls
    }
