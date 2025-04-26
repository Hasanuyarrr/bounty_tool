### Pentest Süreçlerinde Otomasyon: Varlık Keşfi ve Analizi 🔍

Siber güvenlik testlerinde kapsamlı bir varlık keşfi, başarılı bir Pentest veya Bug Bounty sürecinin temel taşlarından biri olarak öne çıkmaktadır. Bu bağlamda geliştirdiğim araç, süreci hızlandırarak daha verimli hale getirmekte ve aşağıdaki işlemleri tamamen otomatik olarak gerçekleştirmektedir:

---

### 🚀 Özellikler:

- **✅ Subdomain Keşfi:**  
  Bir domain'e ait tüm subdomain’leri tespit eder.

- **✅ Aktif Servis Analizi:**  
  Subdomain’lerin aktif olup olmadığını kontrol eder.

- **✅ Endpoint & Parametre Tespiti:**  
  Parametre içeren endpoint’leri hedef alarak test süreçlerini optimize eder.

- **✅ Yanıt Analizi:**  
  HTTP header’larından status code, title, content type gibi kritik bilgileri toplar.

- **✅ Hassas Bilgi Keşfi:**  
  API key, admin panel erişimi, HTTP metotları gibi kritik unsurları belirler.

- **✅ Teknoloji Tespiti:**  
  Kullanılan framework ve yazılım teknolojilerini analiz eder.

- **✅ Port Taramaları:**  
  Açık portları kategorize ederek sonuçları düzenli bir şekilde sunar.

- **✅ HTML Raporlama:**  
  Sonuçları düzenli bir HTML formatında raporlar.

---

### Kullanım:

Bu araç, verilen bir domain adresine ait tüm varlık keşfi işlemlerini otomatik olarak gerçekleştirir. Tek yapmanız gereken domain adresini vermek; tüm süreçleri kendisi halleder. 

---

💡 **Önemli Notlar:**
- Aracın çalışabilmesi için bazı bağımlılıklar gerekmektedir. Tüm bağımlılıkların doğru şekilde kurulduğundan emin olun. 
- Tarama süresi, hedef sistemin büyüklüğüne göre değişiklik gösterebilir. Örneğin, 10.000 varlık için tarama süresi yaklaşık **6 saat** sürebilir.
- Bu araç, otomatik varlık keşfi yaparak siber güvenlik testlerini bir adım öteye taşır ve Pentest ile Bug Bounty süreçlerinde büyük bir kolaylık sağlar.
- HackerOne’da dereceye giren siber güvenlik uzmanlarının metodolojileri takip edilerek oluşturulmuştur.

--- 

Bu araç sayesinde, siber güvenlik süreçlerinizi daha hızlı ve etkili bir şekilde yönetebilirsiniz.

### Araçların Kurulumu ve Yapılandırılması

Aşağıdaki araçları Go ile sisteminize kurabilirsiniz. Bu araçların kurulumu tamamlandıktan sonra, hepsini `/usr/local/bin` dizinine taşıyarak global olarak erişilebilir hale getirebilirsiniz.

#### Kurulması Gereken Araçlar:
- **subfinder**
- **httpx**
- **gau**
- **waybackurls**
- **anew**
- **nmap**
- **dig**
- **host**
- **jq**
- **masscan**

### Kurulum Adımları:

1. **Go ve Gerekli Araçların Yüklenmesi:**
   Go'nun sisteminizde kurulu olduğundan emin olun. Eğer kurulu değilse, aşağıdaki komutla kurabilirsiniz:
   ```bash
   sudo apt update && sudo apt install golang -y
   ```

2. **Araçların Go ile Kurulması:**
   Aşağıdaki komutları sırasıyla çalıştırarak araçları kurun:
   ```bash
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/lc/gau/v2/cmd/gau@latest
   go install github.com/tomnomnom/waybackurls@latest
   go install github.com/tomnomnom/anew@latest
   ```

3. **Diğer Araçların Yüklenmesi ve Yapılandırılması:**
   Aşağıdaki komutlarla diğer araçları kurabilirsiniz:
   ```bash
   sudo apt install -y nmap dnsutils jq
   sudo apt install -y masscan
   ```

4. **Araçların `/usr/local/bin` Dizinine Taşınması:**
   Go ile kurulan araçları `$GOPATH/bin` dizininden `/usr/local/bin` dizinine taşıyın:
   ```bash
   mv ~/go/bin/* /usr/local/bin/
   ```

5. **İzinlerin Kontrol Edilmesi:**
   Araçların doğru şekilde çalıştığından emin olmak için aşağıdaki komutlarla test edin:
   ```bash
   subfinder -h
   httpx -h
   gau -h
   waybackurls -h
   anew -h
   nmap -h
   dig -v
   host -v
   jq --version
   masscan --version
   ```

---

### `bounty.sh` Dosyasının Kullanımı

1. **`bounty.sh` Dosyasını `/usr/local/bin` Dizinine Kopyalayın:**
   ```bash
   sudo cp bounty.sh /usr/local/bin/
   ```

2. **Çalıştırılabilir İzin Verin:**
   ```bash
   sudo chmod +x /usr/local/bin/bounty.sh
   ```

3. **Herhangi Bir Dizinden Çalıştırma:**
   Artık `bounty.sh` dosyasını herhangi bir dizinden aşağıdaki komutla çalıştırabilirsiniz:
   ```bash
   bounty.sh
   ```

---

Tabii, aşağıda daha düzenli bir şekilde yapılandırılmış çıktı sonucu yer alıyor:

---

### Örnek Çıktı Yapısı

```
[domain_adı]/  
├── subdomains/                # Subdomain tarama sonuçları  
│   ├── subfinder.txt          # Subfinder tarafından bulunan subdomain'ler  
│   ├── wayback_subdomains.txt # Wayback Machine'den çekilen subdomain'ler  
│   └── all_subdomains.txt     # Tüm subdomain'lerin birleştirilmiş listesi  
│
├── live/                      # Aktif host'ların bilgileri  
│   ├── live_hosts.txt         # Aktif olarak yanıt veren host'lar  
│   └── httpx_results.json     # HTTPX tarafından alınan detaylı sonuçlar  
│
├── endpoints/                 # URL endpoint'leri  
│   ├── raw_endpoints.txt      # Tespit edilen ham endpoint'ler  
│   ├── unique_endpoints.txt   # Tekrarlanmayan endpoint'ler  
│   └── parameterized_urls.txt # Parametre içeren URL'ler  
│
├── status_codes/              # HTTP durum kodlarına göre ayrılmış URL'ler  
│
├── reports/                   # Tarama raporları  
│   └── master_report.html     # HTML formatındaki kapsamlı rapor  
│
├── screenshots/               # Alınan ekran görüntüleri henüz aktif değil. 
│
├── tech/                      # Teknoloji stack analizi sonuçları  
│   └── [domain]_tech.txt      # Tespit edilen teknolojiler  
│
├── responses/                 # HTTP yanıtları  
│
├── ports/                     # Port tarama sonuçları  
│   ├── masscan_results.json   # Masscan sonuçları  
│   └── [ip]_ports.json        # IP bazlı port tarama çıktıları  
```

---

Bu yapı, aracın çıktısını hem daha anlaşılır hem de kategorize edilmiş bir şekilde sunar. Her kategori altındaki dosyalar, ilgili tarama süreçlerini ve sonuçlarını detaylı bir şekilde organize eder.

Bu adımları takip ederek araçları sisteminize kurabilir, yapılandırabilir ve `bounty.sh` dosyasını kolaylıkla çalıştırabilirsiniz.