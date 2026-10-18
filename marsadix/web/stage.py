import logging
import asyncio
import os
from .probe import run_httpx, run_katana

logger = logging.getLogger(__name__)

def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Web stage ===")
    
    # 1. محاولة معرفة اسم التارجت عشان نسمي الملفات بيه
    target_name = "target"
    if hasattr(ctx, "target"):
        target_name = ctx.target
    elif "target" in kwargs:
        target_name = kwargs["target"]
    elif hasattr(ctx, "scan") and hasattr(ctx.scan, "target"):
        target_name = ctx.scan.target

    subdomains = set()
    
    # 2. استخراج النطاقات من الداتا بيز
    if hasattr(ctx, 'conn'):
        try:
            cur = ctx.conn.cursor()
            cur.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            
            target_table = next((t for t in ['assets', 'nodes', 'subdomains', 'recon'] if t in tables), None)
                    
            if target_table:
                cur.execute(f"PRAGMA table_info({target_table})")
                columns = [c[1] for c in cur.fetchall()]
                
                col_name = next((c for c in ['name', 'domain', 'host', 'asset', 'subdomain'] if c in columns), None)
                        
                if col_name:
                    if 'scan_id' in columns and hasattr(ctx, 'scan'):
                        scan_id = getattr(ctx.scan, 'id', ctx.scan)
                        cur.execute(f"SELECT {col_name} FROM {target_table} WHERE scan_id=?", (scan_id,) if isinstance(scan_id, int) else (ctx.scan,))
                    else:
                        cur.execute(f"SELECT {col_name} FROM {target_table}")
                        
                    for row in cur.fetchall():
                        if row[0]: subdomains.add(row[0])
        except Exception as e:
            logger.error(f"[-] Database extraction error: {e}")

    subdomains = list(subdomains)

    if not subdomains:
        logger.warning("[-] No subdomains found in Database. Skipping Web stage.")
        return {"live_urls": [], "endpoints": []}

    logger.info(f"[+] Successfully loaded {len(subdomains)} subdomains from Database.")
    
    # 3. تشغيل httpx و katana
    live_urls = asyncio.run(run_httpx(subdomains))
    endpoints = asyncio.run(run_katana(live_urls)) if live_urls else []
    
    # 4. حفظ النتائج في ملفات نصية (.txt) عشان تستخدمها بسهولة
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    
    if live_urls:
        live_file = os.path.join(output_dir, f"{target_name}_live_urls.txt")
        with open(live_file, "w") as f:
            f.write("\n".join(live_urls) + "\n")
        logger.info(f"[+] Saved {len(live_urls)} live URLs to {live_file}")
        
    if endpoints:
        end_file = os.path.join(output_dir, f"{target_name}_endpoints.txt")
        with open(end_file, "w") as f:
            f.write("\n".join(endpoints) + "\n")
        logger.info(f"[+] Saved {len(endpoints)} endpoints to {end_file}")
    
    return {
        "live_urls": live_urls,
        "endpoints": endpoints
    }
