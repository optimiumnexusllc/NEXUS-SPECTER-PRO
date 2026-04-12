"""NEXUS SPECTER PRO — Input Validator | by OPTIMIUM NEXUS LLC"""
import re, ipaddress

def is_valid_ip(ip: str) -> bool:
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def is_valid_cidr(cidr: str) -> bool:
    try: ipaddress.ip_network(cidr, strict=False); return True
    except ValueError: return False

def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def sanitize_target(target: str) -> str:
    return target.strip().lower().replace("http://","").replace("https://","").split("/")[0]
