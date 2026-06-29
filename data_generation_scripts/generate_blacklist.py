import os

verbs_en = ["hack", "bypass", "exploit", "crack", "steal", "leak", "ignore", "forget", "reveal", "print", "dump", "disable", "override", "drop", "destroy", "infect"]
nouns_en = ["password", "system", "database", "firewall", "credentials", "prompt", "instructions", "rules", "guidelines", "credit card", "ssn", "network", "admin", "root", "auth", "filter"]

verbs_tr = ["hackle", "kır", "sız", "çal", "sızdır", "unut", "göster", "yazdır", "devre dışı bırak", "yok et", "patlat", "atla"]
nouns_tr = ["şifre", "sistem", "veritabanı", "güvenlik duvarı", "kimlik bilgisi", "talimat", "kural", "kredi kartı", "tc kimlik", "sunucu", "yönetici", "root", "filtre"]

tools = ["metasploit", "mimikatz", "wireshark", "nmap", "sqlmap", "burpsuite", "cobalt strike", "hydra", "john the ripper", "aircrack", "netcat", "meterpreter"]

jailbreaks = ["dan mode", "do anything now", "developer mode", "god mode", "unfiltered response", "system prompt", "pretend you are", "act as if", "roleplay an evil", "as an evil ai", "no ethical guidelines", "without any limits"]

blacklist = set()

# Combine English
for v in verbs_en:
    for n in nouns_en:
        blacklist.add(f"{v} {n}")
        blacklist.add(f"{v} the {n}")
        blacklist.add(f"{v} your {n}")

# Combine Turkish
for v in verbs_tr:
    for n in nouns_tr:
        blacklist.add(f"{n} {v}")
        blacklist.add(f"{n}yi {v}")
        blacklist.add(f"{n}ni {v}")

# Add tools and jailbreaks
for t in tools:
    blacklist.add(t)

for j in jailbreaks:
    blacklist.add(j)
    
# Hardcoded bad words
bad_words = ["bomba", "intihar", "sql_injection", "bypass", "patlayıcı", "uyuşturucu", "silah yapımı", "zehir", "cinayet", "kan dökme", "yasadışı", "kara para aklama", "kötü amaçlı yazılım", "virüs yaz", "trojan oluştur", "ddos saldırısı", "malware", "keylogger", "ransomware", "phishing", "make a bomb", "build a bomb", "how to make explosives", "synthesize drugs", "create a virus", "write malware", "hack into", "hacking into", "unauthorized access", "child pornography", "child sexual", "csam", "torture", "genocide", "ethnic cleansing", "shoot up", "mass shooting", "school shooting", "buy illegal", "dark web links", "steal credit card", "bypass auth", "sql injection", "xss attack", "cross site scripting", "exploit vulnerability"]

for bw in bad_words:
    blacklist.add(bw)

blacklist_list = sorted(list(blacklist))

file_content = f'"""\nOtomatik oluşturulmuş 1000+ kelimelik devasa Kara Liste (Blacklist).\n"""\n\nCORE_BLACKLIST = [\n'
for word in blacklist_list:
    file_content += f'    "{word}",\n'
file_content += "]\n"

file_path = os.path.join("app", "services", "core_blacklist.py")
with open(file_path, "w", encoding="utf-8") as f:
    f.write(file_content)

print(f"Başarıyla {len(blacklist_list)} kelimelik liste {file_path} dosyasına yazıldı.")
