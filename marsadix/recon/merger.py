from typing import Dict, List, Set

def merge_and_track(tool_results: Dict[str, Set[str]]) -> Dict[str, List[str]]:
    """
    R3: دمج النتائج، إزالة التكرار، وتسجيل الأداة التي اكتشفت كل نطاق
    """
    master_list: Dict[str, List[str]] = {}
    
    for tool_name, subdomains in tool_results.items():
        for sub in subdomains:
            sub = sub.strip().lower()
            if not sub:
                continue
            
            if sub not in master_list:
                master_list[sub] = []
            
            # لو الأداة مش متسجلة للنطاق ده، ضيفها
            if tool_name not in master_list[sub]:
                master_list[sub].append(tool_name)
                
    return master_list
