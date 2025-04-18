import json
import glob
from collections import defaultdict
import requests
from ipwhois import IPWhois
import ipaddress
import shodan

LOG_DIR_PATTERN = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*"
SHODAN_API_KEY = "<Insert API Key>"

api = shodan.Shodan(SHODAN_API_KEY)

def is_valid_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        asn = res.get("asn", "N/A")
        org = res.get("network", {}).get("name", "N/A")
        net_name = res.get("asn_description", "N/A")
        return asn, org, net_name
    except Exception:
        return "Private IP", "N/A", "N/A"

def get_geoip(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if res.status_code == 200:
            data = res.json()
            loc = data.get("loc", ",").split(',')
            return {
                "country": data.get("country", "N/A"),
                "region": data.get("region", "N/A"),
                "city": data.get("city", "N/A"),
                "latitude": loc[0],
                "longitude": loc[1]
            }
    except Exception:
        pass
    return {"country": "N/A", "region": "N/A", "city": "N/A", "latitude": "N/A", "longitude": "N/A"}

def get_shodan_info(ip):
    try:
        result = api.host(ip)
        open_ports = result.get("ports", [])
        services = [str(service.get("product", "unknown")) for service in result.get("data", [])]
        return open_ports, services
    except shodan.APIError as e:
        print(f"    Shodan API error for IP {ip}: {e}")
        return "N/A", "N/A"
    except Exception:
        return "N/A", "N/A"

def main():
    ip_counts = defaultdict(int)
    log_files = sorted(glob.glob(LOG_DIR_PATTERN))

    for log_file in log_files:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line)
                    if log.get("eventid") == "cowrie.session.connect":
                        ip = log.get("src_ip")
                        if is_valid_ip(ip):
                            ip_counts[ip] += 1
                except json.JSONDecodeError:
                    continue

    print(f"\nTotal unique IPs: {len(ip_counts)}\n")

    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        asn, org, net_name = get_asn_info(ip)
        geo = get_geoip(ip)
        ports, services = get_shodan_info(ip)

        print(f"[+] IP: {ip} - {count} attempts")
        print(f"    ASN: {asn}")
        print(f"    Org: {org}")
        print(f"    Net Name: {net_name}")
        print(f"    Location: {geo['city']}, {geo['region']}, {geo['country']}")
        print(f"    Lat/Lon: {geo['latitude']}, {geo['longitude']}")
        print(f"    Open Ports: {ports}")
        print(f"    Services: {services}\n")

if __name__ == "__main__":
    main()
