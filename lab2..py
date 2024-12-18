import re
import csv
import json
from collections import Counter
from bs4 import BeautifulSoup

# Nümunə jurnal məlumatları
data = """192.168.1.100 - - [05/Dec/2024:09:15:10 +0000] \"GET http://malicious-site.com/page1 HTTP/1.1\" 404 4321
192.168.1.101 - - [05/Dec/2024:09:16:20 +0000] \"GET http://example.com/page2 HTTP/1.1\" 200 5432
192.168.1.102 - - [05/Dec/2024:09:17:30 +0000] \"GET http://blacklisteddomain.com/page3 HTTP/1.1\" 404 1234
192.168.1.103 - - [05/Dec/2024:09:18:40 +0000] \"POST http://malicious-site.com/login HTTP/1.1\" 404 2345"""

# 1. access_log.txt oxumaq üçün jurnal məlumatlarını böl
logs = data.split("\n")

# 2. URL-ləri və HTTP status kodlarını çıxar
url_status_pattern = re.compile(r'\"[A-Z]+ (.*?) HTTP/[0-9\\.]+\" (\\d{3})')
url_status_list = url_status_pattern.findall("\n".join(logs))

# 3. URL-ləri və status kodlarını url_status_report.txt-də saxla
with open("url_status_report.txt", "w") as report_file:
    for url, status in url_status_list:
        report_file.write(f"{url} {status}\n")

# 4. 404 status koduna malik URL-ləri müəyyən et və onların sayını hesabla
url_404_list = [url for url, status in url_status_list if status == "404"]
url_404_counts = Counter(url_404_list)

# 5. 404 URL-ləri və saylarını malware_candidates.csv-də saxla
with open("malware_candidates.csv", "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["URL", "Say"])
    for url, count in url_404_counts.items():
        writer.writerow([url, count])

# 6. thread_feed.html faylını analiz edərək qara siyahıya alınmış domenləri çıxar
with open("thread_feed.html", "r") as html_file:
    soup = BeautifulSoup(html_file, "html.parser")

blacklisted_domains = {a.text.strip() for a in soup.find_all("a", class_="blacklisted")}

# 7. URL-ləri qara siyahıdakı domenlərlə müqayisə et
blacklisted_urls = {
    url: {"status": "qara siyahıda", "say": url_404_counts.get(url, 0)}
    for url in url_404_counts
    if any(domain in url for domain in blacklisted_domains)
}

# 8. Qara siyahıya düşmüş URL-ləri alert.json-da saxla
with open("alert.json", "w") as alert_file:
    json.dump(blacklisted_urls, alert_file, indent=4)

# 9. summary_report.json faylında ümumi hesabat yarat
summary_report = {
    "ümumi_url": len(url_status_list),
    "ümumi_404_url": len(url_404_list),
    "unikal_404_url": len(url_404_counts),
    "qara_siyahıdakı_url": len(blacklisted_urls),
}

with open("summary_report.json", "w") as summary_file:
    json.dump(summary_report, summary_file, indent=4)
