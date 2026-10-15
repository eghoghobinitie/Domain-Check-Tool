
import socket
import urllib.request
import urllib.error
import ssl
import ipaddress
import re

print("=== Domain Check Tool ===")
print("Look up IP addresses. Compare DNS results. Tests if site is online.")
print()


# DNS servers used for comparison
DNS_SERVERS = {
    "System DNS": None,
    "Google DNS": "8.8.8.8",
    "Cloudflare DNS": "1.1.1.1",
}


def clean_domain(value):
    """Accept a domain or website URL and extract its hostname."""
    value = value.strip()

    if not value:
        return None

    # to allow example.com or https://example.com/
    if "://" not in value:
        value = "https://" + value

    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    domain = parsed.hostname

    if not domain:
        return None


    
    if domain.startswith("[") or domain.endswith("]"):
        return None

    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass

    if len(domain) > 253:
        return None

    labels = domain.rstrip(".").split(".")

    if len(labels) < 2:
        return None

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[A-Za-z0-9-]+", label)
        ):
            return None

    return domain.rstrip(".").lower()


def lookup_system_dns(domain):
    """Look up IPv4 and IPv6 addresses using the system DNS resolver."""
    ipv4 = set()
    ipv6 = set()

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        for result in results:
            address = result[4][0]

            if result[0] == socket.AF_INET:
                ipv4.add(address)
            elif result[0] == socket.AF_INET6:
                ipv6.add(address)

    except socket.gaierror:
        pass

    return sorted(ipv4), sorted(ipv6)


def lookup_specific_dns(domain, dns_server):
    """Query a selected DNS server for IPv4 and IPv6 records.

    Uses Google's or Cloudflare's DNS-over-HTTPS service.
    """
    from urllib.parse import urlencode

    addresses = {"A": set(), "AAAA": set()}

    for record_type in ("A", "AAAA"):
        query = urlencode({
            "name": domain,
            "type": record_type
        })

        url = f"https://{dns_server}/dns-query?{query}"

        request = urllib.request.Request(
            url,
            headers={"accept": "application/dns-json"}
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                import json
                data = json.loads(response.read().decode("utf-8"))

            for answer in data.get("Answer", []):
                if answer.get("type") == (1 if record_type == "A" else 28):
                    addresses[record_type].add(answer["data"])

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            ssl.SSLError,
            ValueError,
            OSError
        ):
            
            return None

    return (
        sorted(addresses["A"]),
        sorted(addresses["AAAA"])
    )


def check_website(domain, scheme):
    """Check whether an HTTP or HTTPS request can reach the website."""
    url = f"{scheme}://{domain}/"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DomainCheckTool/1.0"},
        method="GET"
    ) 
    
    try:
        with urllib.request.urlopen(request, timeout=7) as response:
            return f"Reachable (HTTP status {response.status})"

    except urllib.error.HTTPError as error:
        
        return f"Server responded (HTTP status {error.code})"

    except (
        urllib.error.URLError,
        TimeoutError,
        socket.timeout,
        ssl.SSLError,
        OSError,
        ValueError
    ):
        return "Not reachable from this connection"


def main():
    while True:
        entered = input("Enter a domain (or type 'q' to quit): ").strip()

        if entered.lower() == "q":
            
            return

        if not entered:
            print("Domain cannot be empty. Please enter a domain.")
            print()
            continue

        domain = clean_domain(entered)

        if not domain:
            print(
                "Invalid input. Enter a domain such as example.com "
                "or https://example.com."
            )
            print()
            continue

        print(f"\nDomain: {domain}")

        # DNS lookup
        ipv4, ipv6 = lookup_system_dns(domain)

        print("\n--- System DNS Results ---")
        print("IPv4 addresses:", ", ".join(ipv4) if ipv4 else "None found")
        print("IPv6 addresses:", ", ".join(ipv6) if ipv6 else "None found")

        # comparing DNS providers
        print("\n--- DNS Server Comparison ---")

        for name, server in DNS_SERVERS.items():
            if server is None:
                addresses = (ipv4, ipv6)
            else:
                addresses = lookup_specific_dns(domain, server)

            if addresses is None:
                print(f"{name}: Query failed or service unavailable")
                continue

            a_records, aaaa_records = addresses
            print(f"{name}:")
            print("  IPv4:", ", ".join(a_records) if a_records else "None found")
            print("  IPv6:", ", ".join(aaaa_records) if aaaa_records else "None found")

        # testing HTTP and HTTPS
        print("\n--- Site Availability ---")
        print("HTTP :", check_website(domain, "http"))
        print("HTTPS:", check_website(domain, "https"))

        print("\nNote: Results depend on your internet connection and the website.")
        print("A failed test does not necessarily mean the entire server is offline.")
        print("\n" + "-" * 45 + "\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nProgram stopped.")
