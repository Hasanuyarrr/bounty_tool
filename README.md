Tabii, aşağıda bu araçların nasıl kurulacağı ve `bounty.sh` dosyasının nasıl çalıştırılacağına dair daha açıklayıcı ve düzenli bir anlatım verilmiştir:

---

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

Bu adımları takip ederek araçları sisteminize kurabilir, yapılandırabilir ve `bounty.sh` dosyasını kolaylıkla çalıştırabilirsiniz.