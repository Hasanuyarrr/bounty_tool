#!/bin/bash

# Renk tanımlamaları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
print_banner() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║        Bug Bounty Otomasyon Aracı        ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Hassas bilgi pattern'leri
declare -a SENSITIVE_PATTERNS=(
    # Konfigürasyon ve Sistem
    "conf" "config" "cfg" "ini" "env" "environment"
    "root" "admin" "administrator" "sudo" "superuser"
    "path" "directory" "folder" "system" "server" "host"
    "docker" "container" "kubernetes" "k8s" "deployment"
    
    # Kimlik Doğrulama ve Güvenlik
    "password" "pass" "passwd" "pwd" "secret" "key"
    "api_key" "apikey" "token" "auth" "oauth" "jwt"
    "credentials" "login" "logout" "signin" "signup"
    "username" "user" "email" "mail" "account"
    "session" "cookie" "csrf" "xsrf" "cors"
    "certificate" "cert" "ssl" "tls" "https"
    "private" "public" "key" "rsa" "ssh"
    
    # Veritabanı ve Depolama
    "database" "db" "mysql" "postgresql" "mongo" "redis"
    "oracle" "mssql" "mariadb" "sqlite" "phpmyadmin"
    "query" "sql" "nosql" "schema" "table" "column"
    "backup" "dump" "export" "import" "sync" "replica"
    
    # API ve Servisler
    "api" "rest" "graphql" "soap" "wsdl" "swagger"
    "endpoint" "service" "microservice" "gateway"
    "webhook" "callback" "response" "request"
    
    # HTTP Metodları ve İşlemler
    "method" "post" "get" "put" "delete" "patch"
    "head" "options" "trace" "connect" "ajax"
    "fetch" "axios" "xhr" "upload" "download"
    
    # Hata ve Log
    "error" "exception" "debug" "log" "logger"
    "trace" "stack" "warning" "fatal" "critical"
    
    # Dosya İşlemleri
    "file" "upload" "download" "attachment" "document"
    "image" "video" "audio" "media" "stream"
    
    # Ödeme ve Finansal
    "payment" "credit" "card" "cvv" "expire"
    "bank" "account" "iban" "swift" "money"
    "transaction" "transfer" "balance" "invoice"
    
    # Kişisel Bilgiler
    "personal" "private" "name" "surname" "phone"
    "address" "location" "gps" "coordinate" "ip"
    "ssn" "social" "identity" "passport" "license"
)

# Gerekli araçların kontrolü
check_requirements() {
    tools=("subfinder" "httpx" "gau" "waybackurls" "anew" "nmap" "dig" "host" "jq" "masscan")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] $tool bulunamadı. Lütfen yükleyin.${NC}"
            exit 1
        fi
    done
}

# Dizin yapısı oluşturma
setup_workspace() {
    local domain="$1"
    echo -e "${BLUE}[*] Dizin yapısı oluşturuluyor...${NC}"
    
    mkdir -p "$domain"/{subdomains,live,endpoints,status_codes,reports,screenshots,tech,responses,ports}
    cd "$domain" || exit 1
}

# Subdomain taraması
perform_subdomain_scan() {
    local domain="$1"
    echo -e "${GREEN}[+] Subdomain taraması başlatılıyor...${NC}"
    
    # Subfinder taraması
    echo -e "${BLUE}[*] Subfinder çalıştırılıyor...${NC}"
    subfinder -d "$domain" -silent | anew "subdomains/subfinder.txt"
    
    # Waybackurls'den subdomain toplama
    echo -e "${BLUE}[*] Wayback Machine'den subdomain toplanıyor...${NC}"
    waybackurls "$domain" | unfurl -u domains | grep "$domain" | anew "subdomains/wayback_subdomains.txt"
    
    # Tüm subdomainleri birleştir
    cat subdomains/*.txt | sort -u | anew "subdomains/all_subdomains.txt"
    
    echo -e "${GREEN}[+] Toplam $(wc -l < subdomains/all_subdomains.txt) unique subdomain bulundu${NC}"
}

# Live host kontrolü
check_live_hosts() {
    echo -e "${GREEN}[+] Live host kontrolü yapılıyor...${NC}"
    
    if [ -f "subdomains/all_subdomains.txt" ]; then
        cat "subdomains/all_subdomains.txt" | \
        httpx -silent -mc 200,201,202,203,204,301,302,303,304,307,308,401,403,404,405,500 \
        -status-code -title -content-length -content-type -location -json -o "live/httpx_results.json"
        
        jq -r '.url' "live/httpx_results.json" | anew "live/live_hosts.txt"
        
        echo -e "${GREEN}[+] Toplam $(wc -l < live/live_hosts.txt) live host bulundu${NC}"
    else
        echo -e "${RED}[!] Subdomain listesi bulunamadı${NC}"
        return 1
    fi
}
# Endpoint toplama
gather_endpoints() {
    echo -e "${GREEN}[+] Endpoint ve parametreler toplanıyor...${NC}"
    
    if [ -f "live/live_hosts.txt" ]; then
        while IFS= read -r host; do
            echo -e "${BLUE}[*] $host için endpoint'ler toplanıyor...${NC}"
            
            # GAU ile endpoint toplama
            gau "$host" --threads 10 2>/dev/null | grep "^https\?://" | anew "endpoints/raw_endpoints.txt"
            
            # Waybackurls ile endpoint toplama
            waybackurls "$host" 2>/dev/null | anew "endpoints/raw_endpoints.txt"
        done < "live/live_hosts.txt"
        
        # URL'leri parametrelerine göre ayır
        cat "endpoints/raw_endpoints.txt" | sort -u | anew "endpoints/unique_endpoints.txt"
        grep "?" "endpoints/unique_endpoints.txt" | anew "endpoints/parameterized_urls.txt"
        
        echo -e "${GREEN}[+] Toplam $(wc -l < endpoints/unique_endpoints.txt) unique endpoint bulundu${NC}"
        echo -e "${GREEN}[+] Bunlardan $(wc -l < endpoints/parameterized_urls.txt) tanesi parametreli${NC}"
    else
        echo -e "${RED}[!] Live host listesi bulunamadı${NC}"
        return 1
    fi
}

# Port taraması ve servis tespiti
perform_port_scan() {
    local target="$1"
    local output_dir="ports"
    local masscan_output="$output_dir/masscan_results.json"
    local temp_ip_file="$output_dir/temp_ips.txt"
    
    echo -e "${BLUE}[*] IP adresleri çözümleniyor...${NC}"
    
    # URL'den domain kısmını çıkar (http:// veya https:// kısmını kaldır)
    local domain=$(echo "$target" | sed -E 's#^https?://##' | cut -d'/' -f1)
    
    # Host'un IP adresini al
    host "$domain" | grep "has address" | awk '{print $4}' >> "$temp_ip_file"
    
    if [ ! -s "$temp_ip_file" ]; then
        echo -e "${RED}[!] $domain için IP adresi bulunamadı${NC}"
        return 1
    fi
    
    echo -e "${BLUE}[*] Masscan ile port taraması yapılıyor...${NC}"
    
    # Tüm IP'ler için tek bir masscan taraması yap
    local ip_list=$(tr '\n' ',' < "$temp_ip_file" | sed 's/,$//')
    echo -e "${BLUE}[*] Taranan IP'ler: $ip_list${NC}"
    
    # Masscan taraması (1-65535 portları için)
    masscan -p1-65535 --rate=1000 $ip_list -oJ "$masscan_output" 2>/dev/null
    
    # Her IP için sonuçları JSON formatına dönüştür
    while IFS= read -r ip; do
        local json_file="$output_dir/${ip//[.:]/_}_ports.json"
        
        {
            echo "{"
            echo "  \"target\": \"$target\","
            echo "  \"domain\": \"$domain\","
            echo "  \"ip\": \"$ip\","
            echo "  \"scan_time\": \"$(date -u '+%Y-%m-%d %H:%M:%S UTC')\","
            echo "  \"ports\": ["
            
            # Masscan sonuçlarını parse et
            local first=true
            if [ -f "$masscan_output" ]; then
                while IFS= read -r line; do
                    if echo "$line" | grep -q "\"ip\": \"$ip\""; then
                        port=$(echo "$line" | jq -r '.ports[0].port')
                        proto=$(echo "$line" | jq -r '.ports[0].proto')
                        status="open"
                        
                        $first || echo ","
                        first=false
                        
                        echo "    {"
                        echo "      \"port\": \"$port\","
                        echo "      \"protocol\": \"$proto\","
                        echo "      \"state\": \"$status\""
                        echo "    }"
                    fi
                done < "$masscan_output"
            fi
            
            echo "  ]"
            echo "}"
        } > "$json_file"
        
    done < "$temp_ip_file"
    
    # Geçici dosyaları temizle
    rm -f "$temp_ip_file" "$masscan_output"
}

# URL analizi ve hassas bilgi tespiti
analyze_url() {
    local url="$1"
    local output_dir="status_codes"
    
    echo -e "${BLUE}[*] Analiz ediliyor: $url${NC}"
    
    # Response'u al
    local response_file="responses/$(echo "$url" | md5sum | cut -d' ' -f1).html"
    local response=$(curl -sk -L -A "Mozilla/5.0" \
        -w "STATUS_CODE:%{http_code}\nCONTENT_LENGTH:%{size_download}\nCONTENT_TYPE:%{content_type}\nREDIRECT_URL:%{redirect_url}\n" \
        "$url" -o "$response_file")
    
    local status_code=$(echo "$response" | grep "STATUS_CODE:" | cut -d':' -f2)
    local content_length=$(echo "$response" | grep "CONTENT_LENGTH:" | cut -d':' -f2)
    local content_type=$(echo "$response" | grep "CONTENT_TYPE:" | cut -d':' -f2)
    local redirect_url=$(echo "$response" | grep "REDIRECT_URL:" | cut -d':' -f2-)
    
    # Title'ı çek
    local title=$(grep -i "<title>" "$response_file" 2>/dev/null | head -n1 | sed 's/<[^>]*>//g' | tr -d '\n')
    
    # Hassas bilgi kontrolü
    local sensitive_findings=""
    local found_patterns=()
    
    # HTML içeriğini temizle ve analiz et
    local cleaned_content=$(cat "$response_file" | tr '\n' ' ')
    local raw_content=$(cat "$response_file")
    
    # HTTP metodlarını HTML içeriğinde kontrol et
    local http_methods=("GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS" "TRACE" "CONNECT")
    for method in "${http_methods[@]}"; do
        # Form metodlarını kontrol et
        local form_matches=$(echo "$cleaned_content" | grep -ioP "method\s*=\s*['\"]?\b${method}\b['\"]?" | head -n 3)
        if [ ! -z "$form_matches" ]; then
            sensitive_findings+="<span class='sensitive-tag'>http_method</span>: Found $method method in form<br>"
            found_patterns+=("http_method")
        fi
        
        # JavaScript/Ajax metodlarını kontrol et
        local js_matches=$(echo "$cleaned_content" | grep -ioP "(?:type|method)\s*:\s*['\"]?\b${method}\b['\"]?" | head -n 3)
        if [ ! -z "$js_matches" ]; then
            sensitive_findings+="<span class='sensitive-tag'>http_method</span>: Found $method method in JavaScript/Ajax call<br>"
            found_patterns+=("http_method")
        fi
        
        # Fetch/Axios metodlarını kontrol et
        local fetch_matches=$(echo "$cleaned_content" | grep -ioP "(?:fetch|axios)\s*\([^)]*['\"]?\b${method}\b['\"]?" | head -n 3)
        if [ ! -z "$fetch_matches" ]; then
            sensitive_findings+="<span class='sensitive-tag'>http_method</span>: Found $method method in Fetch/Axios call<br>"
            found_patterns+=("http_method")
        fi
        
        # Genel HTTP metod kullanımlarını kontrol et
        local general_matches=$(echo "$cleaned_content" | grep -ioP "\b${method}\b\s+(?:/[^\s'\"]+|https?://[^\s'\"]+)" | head -n 3)
        if [ ! -z "$general_matches" ]; then
            sensitive_findings+="<span class='sensitive-tag'>http_method</span>: Found $method method in general usage<br>"
            found_patterns+=("http_method")
        fi
    done
    
    # Input alanlarını kontrol et
    local input_fields=$(echo "$cleaned_content" | grep -oiP 'input[^>]+type\s*=\s*["\x27]?(password|hidden|file)["\x27]?[^>]+' | sort -u)
    if [ ! -z "$input_fields" ]; then
        while IFS= read -r field; do
            local field_type=$(echo "$field" | grep -oiP 'type\s*=\s*["\x27]?([^"\x27]+)' | cut -d'=' -f2- | tr -d '"'\')
            local field_name=$(echo "$field" | grep -oiP 'name\s*=\s*["\x27]?([^"\x27]+)' | cut -d'=' -f2- | tr -d '"'\')
            sensitive_findings+="<span class='sensitive-tag'>sensitive_field</span>: Found $field_type field named $field_name<br>"
            found_patterns+=("sensitive_field")
        done <<< "$input_fields"
    fi
    
    # JavaScript değişkenlerini ve objeleri kontrol et
    local js_patterns=(
        'var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\x27][^"\x27]*token[^"\x27]*["\x27]'
        'var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\x27][^"\x27]*key[^"\x27]*["\x27]'
        'var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\x27][^"\x27]*secret[^"\x27]*["\x27]'
        'var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\x27][^"\x27]*password[^"\x27]*["\x27]'
        'apiKey\s*[:=]\s*["\x27][^"\x27]+["\x27]'
        'secret\s*[:=]\s*["\x27][^"\x27]+["\x27]'
    )
    
    for pattern in "${js_patterns[@]}"; do
        local js_matches=$(echo "$cleaned_content" | grep -oiP "$pattern" | head -n 3)
        if [ ! -z "$js_matches" ]; then
            while IFS= read -r match; do
                sensitive_findings+="<span class='sensitive-tag'>js_sensitive</span>: Found sensitive JS variable: $match<br>"
                found_patterns+=("js_sensitive")
            done <<< "$js_matches"
        fi
    done
    
    # Yorum satırlarını kontrol et
    local comments=$(echo "$raw_content" | grep -oiP '<!--[\s\S]*?-->' | grep -iP '(password|key|token|secret|config)')
    if [ ! -z "$comments" ]; then
        while IFS= read -r comment; do
            sensitive_findings+="<span class='sensitive-tag'>sensitive_comment</span>: Found sensitive comment: ${comment:0:100}...<br>"
            found_patterns+=("sensitive_comment")
        done <<< "$comments"
    fi
    
    # Veritabanı bağlantı stringlerini kontrol et
    local db_patterns=(
        'mysqli?:\/\/[^:]+:[^@]+@[^\/]+'
        'mongodb:\/\/[^:]+:[^@]+@[^\/]+'
        'postgresql:\/\/[^:]+:[^@]+@[^\/]+'
        'redis:\/\/[^:]+:[^@]+@[^\/]+'
    )
    
    for pattern in "${db_patterns[@]}"; do
        local db_matches=$(echo "$cleaned_content" | grep -oiP "$pattern" | head -n 3)
        if [ ! -z "$db_matches" ]; then
            while IFS= read -r match; do
                sensitive_findings+="<span class='sensitive-tag'>db_connection</span>: Found database connection string<br>"
                found_patterns+=("db_connection")
            done <<< "$db_matches"
        fi
    done
    
    # Diğer hassas bilgileri kontrol et
    for pattern in "${SENSITIVE_PATTERNS[@]}"; do
        # Regex ile hassas bilgi ara (büyük/küçük harf duyarlı olmasın)
        local matches=$(echo "$cleaned_content" | grep -ioP "(?:\b$pattern\b[:\s=]+)[^\s<>&\"']{3,50}" | head -n 3)
        if [ ! -z "$matches" ]; then
            while IFS= read -r match; do
                if [ ! -z "$match" ]; then
                    found_patterns+=("$pattern")
                    match=$(echo "$match" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
                    sensitive_findings+="<span class='sensitive-tag'>$pattern</span>: $match<br>"
                fi
            done <<< "$matches"
        fi
    done
    
    # Sonuçları dosyaya yaz
    {
        echo "URL: $url"
        echo "Status Code: $status_code"
        echo "Content Length: $content_length"
        echo "Content Type: $content_type"
        echo "Title: $title"
        echo "Found Patterns: ${found_patterns[*]}"
        echo "Sensitive Info: $sensitive_findings"
        echo "-------------------"
    } >> "$output_dir/${status_code}.txt"
}

# Tech stack analizi
analyze_tech_stack() {
    local url="$1"
    local domain=$(echo "$url" | sed -E 's#^https?://##' | cut -d'/' -f1)
    local output_file="tech/${domain//[\/:]/_}_tech.txt"
    
    echo -e "${BLUE}[*] Tech stack analizi yapılıyor: $url${NC}"
    
    # Geçici dosyalar
    local headers_file="tech/temp_headers.txt"
    local body_file="tech/temp_body.html"
    
    # Response'u al
    curl -sk -L -A "Mozilla/5.0" -D "$headers_file" "$url" > "$body_file"
    
    # Teknoloji tespiti için pattern'ler
    declare -A TECH_PATTERNS=(
        # Web Sunucular
        ["nginx"]='(nginx|NGINX)'
        ["apache"]='(Apache|APACHE)'
        ["iis"]='(IIS|Microsoft-IIS)'
        
        # Backend Teknolojiler
        ["php"]='(PHP|X-Powered-By: PHP|\.php)'
        ["python"]='(Python|\.py|wsgi|django|flask)'
        ["nodejs"]='(Node\.js|Express)'
        ["java"]='(Java|JSP|Servlet|Spring)'
        ["ruby"]='(Ruby|Rails|Sinatra)'
        
        # Frontend Frameworks
        ["react"]='(react|reactjs|React|__REACT_ROOT__|_reactRootContainer)'
        ["angular"]='(ng-|angular|Angular|\[\[|{{)'
        ["vue"]='(vue|Vue|__vue__|v-bind|v-if|v-for)'
        ["jquery"]='(jQuery|jquery|\$\(document\))'
        
        # CMS Sistemler
        ["wordpress"]='(WordPress|wp-content|wp-includes)'
        ["drupal"]='(Drupal|drupal|sites/all|sites/default)'
        ["joomla"]='(Joomla|com_content|com_users)'
        
        # JavaScript Frameworks
        ["next"]='(__NEXT_DATA__|next-page|NextJS)'
        ["nuxt"]='(__NUXT__|nuxt-link|Nuxt)'
        ["svelte"]='(svelte-|Svelte)'
        
        # CSS Frameworks
        ["bootstrap"]='(bootstrap|Bootstrap|navbar-|container-fluid)'
        ["tailwind"]='(tailwind|tw-)'
        ["materialize"]='(materialize|material-icons)'
        
        # Veritabanları
        ["mysql"]='(MySQL|mysqli)'
        ["postgresql"]='(PostgreSQL|psql)'
        ["mongodb"]='(MongoDB|mongoose)'
        
        # Cache & Performance
        ["redis"]='(Redis)'
        ["memcached"]='(Memcached)'
        ["varnish"]='(Varnish|X-Varnish)'
        
        # Security
        ["cloudflare"]='(cloudflare|CF-RAY)'
        ["waf"]='(WAF|X-WAF)'
        ["ssl"]='(SSL|TLS|https)'
    )
    
    # Sonuçları topla
    local detected_tech=()
    local headers_content=$(<"$headers_file")
    local body_content=$(<"$body_file")
    
    # Her pattern için kontrol
    for tech in "${!TECH_PATTERNS[@]}"; do
        pattern="${TECH_PATTERNS[$tech]}"
        if grep -qiP "$pattern" "$headers_file" || grep -qiP "$pattern" "$body_file"; then
            detected_tech+=("$tech")
        fi
    done
    
    # Sonuçları düz metin olarak kaydet
    {
        echo "URL: $url"
        echo "Server: $(grep -i "Server:" "$headers_file" | cut -d' ' -f2- | tr -d '\r')"
        echo "Powered-By: $(grep -i "X-Powered-By:" "$headers_file" | cut -d' ' -f2- | tr -d '\r')"
        echo "Backend: $(printf '%s\n' "${detected_tech[@]}" | grep -E 'php|python|nodejs|java|ruby|mysql|postgresql|mongodb' | paste -sd ',' -)"
        echo "Frontend: $(printf '%s\n' "${detected_tech[@]}" | grep -E 'react|angular|vue|jquery|bootstrap|tailwind|materialize' | paste -sd ',' -)"
        echo "CMS: $(printf '%s\n' "${detected_tech[@]}" | grep -E 'wordpress|drupal|joomla' | paste -sd ',' -)"
        echo "Frameworks: $(printf '%s\n' "${detected_tech[@]}" | grep -E 'next|nuxt|svelte|express|django|flask|spring|rails' | paste -sd ',' -)"
        echo "Security: $(printf '%s\n' "${detected_tech[@]}" | grep -E 'cloudflare|waf|ssl' | paste -sd ',' -)"
        echo "-------------------"
    } > "$output_file"
    
    # Geçici dosyaları temizle
    rm -f "$headers_file" "$body_file"
    
    echo -e "${GREEN}[+] Tespit edilen teknolojiler: ${detected_tech[*]}${NC}"
}

# HTML rapor oluşturma
create_html_report() {
    local domain="$1"
    echo -e "${GREEN}[+] HTML raporu oluşturuluyor...${NC}"
    
    cat > "reports/master_report.html" <<EOF
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Raporu - $domain</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/buttons/2.2.2/css/buttons.bootstrap5.min.css" rel="stylesheet">
    <style>
        body { 
            background-color: #1e2227; 
            color: #fff; 
        }
        .card { 
            background: #282c34; 
            border-color: #373d48; 
        }
        .table { 
            color: #fff; 
        }
        .status-2xx { color: #0dee00 !important; }
        .status-3xx { color: #d0b200 !important; }
        .status-4xx { color: #00a0fc !important; }
        .status-5xx { color: #DD4A68 !important; }
        .sensitive-tag {
            display: inline-block;
            padding: 2px 6px;
            margin: 2px;
            border-radius: 3px;
            background: rgba(255,0,0,0.1);
            color: #ff4444;
            font-weight: bold;
        }
        .badge { 
            font-size: 0.9em; 
        }
        pre { 
            background: #282c34; 
            color: #fff; 
            padding: 15px; 
            border-radius: 5px; 
        }
        .dataTables_wrapper { 
            color: #fff; 
        }
        .page-link { 
            background-color: #282c34; 
            border-color: #373d48; 
            color: #fff; 
        }
        .page-link:hover { 
            background-color: #373d48; 
            border-color: #444; 
            color: #fff; 
        }
        .url-link {
            color: #00a0fc;
            text-decoration: none;
        }
        .url-link:hover {
            color: #0056b3;
            text-decoration: underline;
        }
        .port-details {
            background: #2c3038;
            border-radius: 5px;
            padding: 10px;
            margin: 5px 0;
        }
        .port-number {
            font-weight: bold;
            color: #00a0fc;
        }
        .port-service {
            color: #0dee00;
        }
        .port-version {
            color: #d0b200;
        }
        .tech-badge {
            display: inline-block;
            padding: 3px 8px;
            margin: 2px;
            border-radius: 3px;
            background: #373d48;
            color: #fff;
        }
        .nav-tabs .nav-link {
            color: #fff;
        }
        .nav-tabs .nav-link.active {
            background-color: #373d48;
            color: #fff;
            border-color: #444;
        }
    </style>
</head>
<body>
    <div class="container-fluid p-4">
        <h1 class="mb-4">Bug Bounty Raporu - $domain</h1>

        <!-- İstatistikler -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Subdomain Sayısı</h5>
                        <p class="card-text">$(wc -l < subdomains/all_subdomains.txt 2>/dev/null || echo "0")</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Live Host Sayısı</h5>
                        <p class="card-text">$(wc -l < live/live_hosts.txt 2>/dev/null || echo "0")</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Unique Endpoint Sayısı</h5>
                        <p class="card-text">$(wc -l < endpoints/unique_endpoints.txt 2>/dev/null || echo "0")</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Hassas Bilgi Bulunan URL</h5>
                        <p class="card-text" id="sensitiveCount">0</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab Menüsü -->
        <ul class="nav nav-tabs mb-3" role="tablist">
            <li class="nav-item">
                <a class="nav-link active" data-bs-toggle="tab" href="#subdomains">Subdomains</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#endpoints">Endpoints</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#tech">Tech Stack</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#ports">Port Scan</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#sensitive">Hassas Bilgiler</a>
            </li>
        </ul>

        <div class="tab-content">
            <!-- Subdomains Tab -->
            <div class="tab-pane fade show active" id="subdomains">
                <table id="subdomainsTable" class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
EOF

    # Subdomain listesini ekle
    if [ -f "subdomains/all_subdomains.txt" ]; then
        while IFS= read -r subdomain; do
            if grep -q "$subdomain" "live/live_hosts.txt" 2>/dev/null; then
                echo "<tr>
                    <td>$subdomain</td>
                    <td><span class='badge bg-success'>Live</span></td>
                    <td>
                        <a href='http://$subdomain' target='_blank' class='btn btn-sm btn-outline-primary'>HTTP</a>
                        <a href='https://$subdomain' target='_blank' class='btn btn-sm btn-outline-primary'>HTTPS</a>
                    </td>
                </tr>" >> "reports/master_report.html"
            else
                echo "<tr>
                    <td>$subdomain</td>
                    <td><span class='badge bg-secondary'>Not Live</span></td>
                    <td>-</td>
                </tr>" >> "reports/master_report.html"
            fi
        done < "subdomains/all_subdomains.txt"
    fi

    cat >> "reports/master_report.html" <<EOF
                    </tbody>
                </table>
            </div>

            <!-- Endpoints Tab -->
            <div class="tab-pane fade" id="endpoints">
                <table id="endpointsTable" class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status Code</th>
                            <th>Content Length</th>
                            <th>Content Type</th>
                            <th>Title</th>
                        </tr>
                    </thead>
                    <tbody>
EOF

    # Status code dosyalarından endpoint verilerini ekle
    for status_file in status_codes/*.txt; do
        if [ -f "$status_file" ]; then
            status_code=$(basename "$status_file" .txt)
            awk -v sc="$status_code" '
            /^URL:/ { url=$2 }
            /^Content Length:/ { len=$3 }
            /^Content Type:/ { type=$3 }
            /^Title:/ { title=substr($0, index($0,":")+2) }
            /^-------------------/ {
                printf "<tr class=\"status-%sxx\">", substr(sc,1,1)
                printf "<td><a href=\"%s\" target=\"_blank\" class=\"url-link\">%s</a></td>", url, url
                printf "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
                sc, len, type, title
            }' "$status_file" >> "reports/master_report.html"
        fi
    done

    cat >> "reports/master_report.html" <<EOF
                    </tbody>
                </table>
            </div>

            <!-- Tech Stack Tab -->
            <div class="tab-pane fade" id="tech">
                <table id="techTable" class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Web Server</th>
                            <th>Backend</th>
                            <th>Frontend</th>
                            <th>CMS</th>
                            <th>Frameworks</th>
                            <th>Security</th>
                        </tr>
                    </thead>
                    <tbody>
EOF

    # Tech stack dosyalarını işle
    for tech_file in tech/*_tech.txt; do
        if [ -f "$tech_file" ]; then
            url=$(grep "^URL:" "$tech_file" | cut -d' ' -f2-)
            server=$(grep "^Server:" "$tech_file" | cut -d' ' -f2-)
            backend=$(grep "^Backend:" "$tech_file" | cut -d' ' -f2-)
            frontend=$(grep "^Frontend:" "$tech_file" | cut -d' ' -f2-)
            cms=$(grep "^CMS:" "$tech_file" | cut -d' ' -f2-)
            frameworks=$(grep "^Frameworks:" "$tech_file" | cut -d' ' -f2-)
            security=$(grep "^Security:" "$tech_file" | cut -d' ' -f2-)
            
            cat >> "reports/master_report.html" <<EOF
            <tr>
                <td><a href="$url" target="_blank" class="url-link">$url</a></td>
                <td>$server</td>
                <td>$backend</td>
                <td>$frontend</td>
                <td>$cms</td>
                <td>$frameworks</td>
                <td>$security</td>
            </tr>
EOF
        fi
    done

    cat >> "reports/master_report.html" <<EOF
                    </tbody>
                </table>
            </div>

            <!-- Port Scan Tab -->
            <div class="tab-pane fade" id="ports">
                <table id="portsTable" class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>Target</th>
                            <th>Open Ports</th>
                        </tr>
                    </thead>
                    <tbody>
EOF

    # Port tarama sonuçlarını ekle
    for port_file in ports/*.json; do
        if [ -f "$port_file" ]; then
            jq -r '. | "<tr><td>\(.target)</td><td>" + (.ports | map("<div class=\"port-details\"><span class=\"port-number\">\(.port)</span> - <span class=\"port-service\">\(.service)</span> <span class=\"port-version\">\(.version)</span></div>") | join("")) + "</td></tr>"' "$port_file" >> "reports/master_report.html"
        fi
    done

    cat >> "reports/master_report.html" <<EOF
                    </tbody>
                </table>
            </div>

            <!-- Hassas Bilgiler Tab -->
            <div class="tab-pane fade" id="sensitive">
                <table id="sensitiveTable" class="table table-dark table-striped">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Bulunan Hassas Bilgiler</th>
                        </tr>
                    </thead>
                    <tbody>
EOF

    # Hassas bilgileri ekle
    for status_file in status_codes/*.txt; do
        if [ -f "$status_file" ]; then
            awk '
            /^URL:/ { url=$2 }
            /^Sensitive Info:/ {
                if($3 != "") {
                    printf "<tr><td><a href=\"%s\" target=\"_blank\" class=\"url-link\">%s</a></td><td>%s</td></tr>\n",
                    url, url, substr($0, index($0,":")+2)
                }
            }' "$status_file" >> "reports/master_report.html"
        fi
    done

    cat >> "reports/master_report.html" <<EOF
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.2.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.2.2/js/buttons.bootstrap5.min.js"></script>
    <script>
        \$(document).ready(function() {
            // Tüm tablolar için DataTables initialization
            ['#subdomainsTable', '#endpointsTable', '#techTable', '#portsTable', '#sensitiveTable'].forEach(function(tableId) {
                \$(tableId).DataTable({
                    pageLength: 25,
                    order: [[0, 'asc']],
                    dom: 'Bfrtip',
                    buttons: ['copy', 'csv', 'excel', 'pdf', 'print']
                });
            });

            // Hassas bilgi sayısını güncelle
            var sensitiveCount = \$('#sensitiveTable tbody tr').length;
            \$('#sensitiveCount').text(sensitiveCount);
        });
    </script>
</body>
</html>
EOF

    echo -e "${GREEN}[+] HTML rapor oluşturuldu: $PWD/reports/master_report.html${NC}"
}

# Ana fonksiyon
main() {
    print_banner
    check_requirements
    
    # Hedef domain
    read -p "Hedef domaini girin (örnek: example.com): " domain
    
    # Çalışma alanını hazırla
    setup_workspace "$domain"
    
    # Taramaları başlat
    echo -e "\n${YELLOW}[*] Tarama başlatılıyor...${NC}"
    
    perform_subdomain_scan "$domain"
    check_live_hosts
    gather_endpoints
    
    echo -e "\n${YELLOW}[*] URL'ler analiz ediliyor...${NC}"
    if [ -f "endpoints/unique_endpoints.txt" ]; then
        total_urls=$(wc -l < endpoints/unique_endpoints.txt)
        current_url=0
        
        while IFS= read -r url; do
            current_url=$((current_url + 1))
            echo -ne "\r${BLUE}[*] İşlenen URL: $current_url/$total_urls${NC}"
            analyze_url "$url"
        done < "endpoints/unique_endpoints.txt"
        echo
    fi
    
    echo -e "\n${YELLOW}[*] Tech stack analizi yapılıyor...${NC}"
    if [ -f "live/live_hosts.txt" ]; then
        while IFS= read -r host; do
            analyze_tech_stack "$host"
        done < "live/live_hosts.txt"
    fi
    
    echo -e "\n${YELLOW}[*] Port taraması başlatılıyor...${NC}"
    if [ -f "live/live_hosts.txt" ]; then
        while IFS= read -r host; do
            perform_port_scan "$host"
        done < "live/live_hosts.txt"
    fi
    
    create_html_report "$domain"
    
    echo -e "\n${GREEN}[+] Tarama tamamlandı! Özet:${NC}"
    echo -e "${YELLOW}Subdomain sayısı:${NC} $(wc -l < subdomains/all_subdomains.txt 2>/dev/null || echo "0")"
    echo -e "${YELLOW}Live host sayısı:${NC} $(wc -l < live/live_hosts.txt 2>/dev/null || echo "0")"
    echo -e "${YELLOW}Unique endpoint sayısı:${NC} $(wc -l < endpoints/unique_endpoints.txt 2>/dev/null || echo "0")"
    
    if command -v xdg-open &> /dev/null; then
        read -p "Raporu tarayıcıda açmak ister misiniz? (E/h): " open_browser
        if [[ $open_browser != "h" && $open_browser != "H" ]]; then
            xdg-open "reports/master_report.html"
        fi
    fi
}

# Scripti çalıştır
main "$@"
