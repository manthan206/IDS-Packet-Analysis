import requests
from typing import Dict, Any, Optional

# Cache to store resolved GeoIP details
GEO_DETAILS_CACHE: Dict[str, Dict[str, Any]] = {}

# Auto-detect local system public IP details on startup
LOCAL_PUBLIC_GEO: Optional[Dict[str, Any]] = None

def get_flag_emoji(country_code: str) -> str:
    """Converts 2-character ISO country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))
    except Exception:
        return "🌐"

def is_private_ip(ip: str) -> bool:
    if not ip or ip in ("Unknown", "localhost", "127.0.0.1", "0.0.0.0"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
    except ValueError:
        pass
    return False

def init_system_public_geo():
    """Resolves the operating system's active public IP and region location."""
    global LOCAL_PUBLIC_GEO
    if LOCAL_PUBLIC_GEO:
        return LOCAL_PUBLIC_GEO

    try:
        res = requests.get('http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,query', timeout=3.0)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                flag = get_flag_emoji(data.get("countryCode", ""))
                city = data.get("city", "")
                region = data.get("regionName", "")
                country = data.get("country", "")
                isp = data.get("isp", "")
                
                location_str = f"{city}, {region}, {country} {flag}" if city and region else f"{country} {flag}"
                if isp:
                    location_str += f" ({isp})"

                LOCAL_PUBLIC_GEO = {
                    "ip": data.get("query"),
                    "city": city,
                    "region": region,
                    "country": country,
                    "country_code": data.get("countryCode"),
                    "flag": flag,
                    "isp": isp,
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "location_string": location_str
                }
                return LOCAL_PUBLIC_GEO
    except Exception:
        pass

    LOCAL_PUBLIC_GEO = {
        "ip": "Local",
        "city": "Operating System",
        "region": "Local Network",
        "country": "Local Host",
        "country_code": "LOC",
        "flag": "🖥️",
        "isp": "Local LAN",
        "lat": 0.0,
        "lon": 0.0,
        "location_string": "Local Host (LAN) 🖥️"
    }
    return LOCAL_PUBLIC_GEO

def get_detailed_geo_for_ip(ip: str) -> Dict[str, Any]:
    """
    Returns precise region, city, country, ISP, and coordinates for an IP address.
    """
    if not ip or ip == "Unknown":
        return {
            "ip": ip,
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "flag": "🌐",
            "isp": "Unknown",
            "location_string": "Unknown Region 🌐"
        }

    if is_private_ip(ip):
        # Local system traffic — bind with active system public region
        sys_geo = init_system_public_geo()
        return {
            "ip": ip,
            "city": sys_geo["city"],
            "region": sys_geo["region"],
            "country": sys_geo["country"],
            "country_code": sys_geo.get("country_code", "LOC"),
            "flag": sys_geo["flag"],
            "isp": sys_geo["isp"],
            "lat": sys_geo.get("lat", 0.0),
            "lon": sys_geo.get("lon", 0.0),
            "location_string": f"Local Host [{sys_geo['city']}, {sys_geo['region']}] {sys_geo['flag']}"
        }

    if ip in GEO_DETAILS_CACHE:
        return GEO_DETAILS_CACHE[ip]

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,query", timeout=2.0)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                flag = get_flag_emoji(data.get("countryCode", ""))
                city = data.get("city", "Unknown")
                region = data.get("regionName", "")
                country = data.get("country", "Unknown")
                isp = data.get("isp", "")

                loc_str = f"{city}, {region}, {country} {flag}" if region else f"{city}, {country} {flag}"

                geo_info = {
                    "ip": ip,
                    "city": city,
                    "region": region,
                    "country": country,
                    "country_code": data.get("countryCode"),
                    "flag": flag,
                    "isp": isp,
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "location_string": loc_str
                }
                GEO_DETAILS_CACHE[ip] = geo_info
                return geo_info
    except Exception:
        pass

    fallback = {
        "ip": ip,
        "city": "External",
        "region": "Remote Host",
        "country": "External Net",
        "flag": "🌐",
        "isp": "Internet Provider",
        "location_string": f"{ip} 🌐"
    }
    GEO_DETAILS_CACHE[ip] = fallback
    return fallback

def get_country_for_ip(ip: str) -> str:
    """Backward compatibility helper for formatted location string."""
    details = get_detailed_geo_for_ip(ip)
    return details.get("location_string", "Unknown Region 🌐")
