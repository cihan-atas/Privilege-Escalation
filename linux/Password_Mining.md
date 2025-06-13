
### **Password Mining**

Bu rehber, bir sisteme sızdıktan sonra (post-exploitation), daha yüksek yetkilere erişmek amacıyla unutulmuş veya güvensiz bir şekilde saklanmış kimlik bilgilerini bulma tekniğini derinlemesine açıklar. Bu, bir saldırganın en sık başvurduğu ve en etkili yetki yükseltme yöntemlerinden biridir.

#### **1. Şifre Madenciliği Nedir?**

Şifre Madenciliği, bir saldırganın zaten erişimi olan bir sistemde, kullanıcıların, geliştiricilerin veya sistem yöneticilerinin bıraktığı dijital "kırıntıları" tarayarak açık metin (plaintext) şifreleri, API anahtarlarını, veritabanı bağlantı bilgilerini, özel anahtarları veya diğer hassas kimlik bilgilerini bulma sürecidir.

**Temel Prensip:** Bir sisteme ilk erişim genellikle düşük yetkili bir kullanıcı (örneğin, bir web sunucusu kullanıcısı olan `www-data` veya standart bir çalışan hesabı) ile sağlanır. Amacımız, bu kısıtlı hesabı bir sıçrama tahtası olarak kullanarak, sistemdeki diğer daha yetkili hesapların (`admin`, `root`, veritabanı yöneticisi, servis hesabı vb.) kimlik bilgilerini ortaya çıkarmaktır.

**Neden Bu Kadar Etkili?**
Bu teknik, teknolojiden çok insan faktörüne dayanır:
*   **Unutkanlık:** Şifreler geçici olarak not dosyalarına yazılır ve sonra unutulur.
*   **Kolaycılık:** Geliştiriciler, test aşamasında şifreleri doğrudan kodun veya yapılandırma dosyalarının içine yazar ve üretim ortamına bu şekilde taşır.
*   **Bilgisizlik:** Hassas bilgilerin nasıl güvenli bir şekilde saklanacağı bilinmediği için komut geçmişi veya betik dosyaları gibi güvensiz yerlerde bırakılır.

---

#### **2. Metodoloji: Adım Adım Şifre Madenciliği**

Başarılı bir şifre madenciliği operasyonu, aceleci davranmak yerine metodik ve sabırlı bir yaklaşım gerektirir.

##### **Adım A: Keşif ve Durum Değerlendirmesi (Enumeration)**

Sisteme ilk erişimi sağladıktan sonra, "Ben kimim ve neredeyim?" sorularını cevaplayın. Bu, arama alanınızı belirlemenize yardımcı olur.

*   **Kullanıcı ve Yetki Tespiti:**
    *   `whoami`: Mevcut kullanıcı adınız.
    *   `id`: Kullanıcı ve grup bilgileriniz (Linux).
    *   `whoami /groups`: Grup bilgileriniz (Windows).
    *   `hostname`: Üzerinde çalıştığınız makinenin adı.
*   **Ev Dizinini İnceleme:**
    *   `ls -la ~`: Kullanıcının ev dizinindeki gizli dosyalar dahil her şeyi listeleyin. Burası madenciliğe başlamak için en zengin yerdir.

##### **Adım B: Sistematik Tarama ve Madencilik (The "Mining")**

Bu, sürecin en kritik ve zaman alıcı kısmıdır. Aşağıda listelenen ortak hedefleri, belirtilen anahtar kelimelerle sistematik olarak tarayın.

**Anahtar Kelime Listeniz (Genişletilmiş):**
`pass`, `pwd`, `secret`, `key`, `token`, `login`, `user`, `admin`, `credential`, `auth`, `access_key`, `secret_key`, `api_key`, `connection_string`, `DSN`

##### **Adım C: Doğrulama ve Kullanım (Exploitation)**

Bir kimlik bilgisi bulduğunuzda, hemen çalışıp çalışmadığını ve ne işe yaradığını doğrulayın.

*   **Kullanıcı Adı/Şifre:**
    *   `su <bulunan_kullanici>`: Mevcut terminalde kullanıcı değiştirmeyi deneyin (Linux).
    *   `ssh <kullanici>@localhost`: Sisteme başka bir kullanıcı olarak SSH ile bağlanmayı deneyin. Bu, daha temiz bir oturum sağlar.
    *   Windows'ta `runas /user:<kullanici> cmd.exe` komutuyla yeni bir komut istemi açmayı deneyin.
*   **Veritabanı Kimlik Bilgileri:**
    *   `mysql -u <user> -p'<password>' -h 127.0.0.1`: Yerel MySQL veritabanına bağlanın.
    *   `psql -U <user> -d <database> -h 127.0.0.1`: Yerel PostgreSQL veritabanına bağlanın. Bu veritabanları, başka kullanıcıların hash'lenmiş şifrelerini içerebilir.

**Dikkat:** Yanlış parola denemeleriyle bir hesabı kilitlememeye özen gösterin. Mümkünse, sistemdeki parola politikalarını öğrenmeye çalışın.

##### **Adım D: Yetki Yükseltme ve Kalıcılık (Privilege Escalation & Persistence)**

Elde ettiğiniz yeni hesapla oturum açtıktan sonra, bu hesabın `sudo` veya `Administrators` grubunda olup olmadığını kontrol edin (`sudo -l`). Eğer yetkili bir hesap ise, son hedef olan `root` veya `NT AUTHORITY\SYSTEM` seviyesine erişin. Ardından, sisteme erişiminizi kaybetmemek için kalıcılık mekanizmaları (örneğin, yeni bir SSH anahtarı eklemek veya bir arka kapı oluşturmak) kurun.

---

#### **3. Şifrelerin Bulunabileceği Yaygın Yerler ve Komutlar**

##### **A. Komut Geçmişi Dosyaları**
*   **Linux:**
    *   `~/.bash_history`, `~/.zsh_history`, `~/.ash_history`: Shell komut geçmişleri.
    *   `~/.mysql_history`, `~/.psql_history`: Veritabanı istemci geçmişleri.
    *   `~/.python_history`: Python REPL geçmişi.
*   **Windows:**
    *   PowerShell geçmişi: `(Get-PSReadlineOption).HistorySavePath`
    *   `doskey /history`: CMD geçmişi (mevcut oturum için).

**Arama Komutları (Linux):**
```bash
# Genişletilmiş ve daha kapsamlı bir arama
grep -EaRin "password|pass|pwd|secret|key|token|login|user|admin|cred|auth" ~/.bash_history

# Birden fazla geçmiş dosyasını tek seferde arama
cat ~/.bash_history ~/.zsh_history ~/.mysql_history 2>/dev/null | grep -i "pass"
```

##### **B. Konfigürasyon Dosyaları (.conf, .ini, .xml, .yml, .env)**
*   **Web Uygulamaları:** `wp-config.php`, `web.config`, `settings.py`, `database.yml`, `config.inc.php`, `.env` (çok yaygın!), `settings.local.php`.
*   **Sistem Servisleri:** `/etc/` altındaki `.conf` dosyaları (ör: `/etc/fstab` içindeki ağ sürücüsü bağlantıları).
*   **Docker/Konteyner:** `docker-compose.yml` dosyaları genellikle veritabanı şifreleri içerir.
*   **Windows Registry:** `reg query HKLM /f password /t REG_SZ /s`

**Arama Komutları (Linux):**
```bash
# Tüm sistemdeki .conf, .ini, .yml ve .env dosyalarında şifre arama
find / -type f \( -name "*.conf" -o -name "*.ini" -o -name "*.yml" -o -name "*.env" \) 2>/dev/null -exec grep -HionE "pass|secret|token" {} \;

# Özellikle /var/www veya /srv/http gibi web kök dizinlerinde arama yapma
grep -ria "db_password|db_user" /var/www
```

##### **C. Betikler, Kaynak Kodları ve Git Depoları**
*   **Dosyalar:** `.sh`, `.py`, `.pl`, `.php`, `.rb`, `.java`. Yedekleme (`backup.sh`), dağıtım (`deploy.py`) veya otomasyon betikleri altın madenidir.
*   **Git:** Geliştiriciler bazen `.git` klasörünü sunucuya yükler. `git log`, `git stash` veya `git config` komutları hassas veri içerebilir.

**Arama Komutları (Linux):**
```bash
# Ev dizinindeki tüm betiklerde veritabanı veya SSH bağlantısı arama
find /home -name "*.sh" -o -name "*.py" 2>/dev/null | xargs grep -ionE "mysql|ssh|ftp|passwd"

# Yorum satırlarına gizlenmiş şifreleri arama
grep -rin "password" --include=*.{py,sh,php} /opt
```

##### **D. Kullanıcı Notları ve Ofis Belgeleri**
*   `passwords.txt`, `creds.txt`, `notlar.md`, `bilgiler.docx`, `hesaplar.xlsx`, `secrets.kdbx` (KeePass veritabanı, ana şifresini bulabilirseniz jackpot!).

**Arama Komutları (Linux):**
```bash
# "pass", "cred", "hesap", "şifre" kelimelerini içeren dosyaları bulma
find /home /tmp -type f -name "*pass*" 2>/dev/null
find /home /tmp -type f -name "*cred*" 2>/dev/null
find /home /tmp -type f -name "*hesap*" -o -name "*sifre*" 2>/dev/null
```

##### **E. SSH Anahtarları ve Yapılandırmaları**
*   `~/.ssh/id_rsa`: Parola koruması olmayan özel anahtarlar, başka sunuculara parolasız erişim sağlar.
*   `~/.ssh/config`: Hangi anahtarın hangi sunucu için ve hangi kullanıcıyla kullanılacağını belirtir.
*   `~/.ssh/authorized_keys`: Bu sunucuya hangi anahtarların erişebildiğini gösterir. Diğer kullanıcıların (`/home/<diger_kullanici>/.ssh/`) dosyalarını okuyabilirseniz, sistemdeki güven ilişkilerini haritalayabilirsiniz.
*   `~/.ssh/known_hosts`: Kullanıcının daha önce hangi sunuculara bağlandığını gösterir.

**Pro-Tip:** Bir `id_rsa` bulduğunuzda, parola korumalı olup olmadığını `ssh-keygen -y -f id_rsa` komutuyla kontrol edin. Eğer parola sormadan genel anahtarı ekrana basarsa, anahtar parolasızdır!

##### **F. Otomatik Bilgi Toplama Araçları (En Hızlı Yöntem)**
Bu araçlar, yukarıdaki tüm kontrolleri ve çok daha fazlasını saniyeler içinde yapar.
*   **Linux:** `LinPEAS.sh`, `LinEnum.sh`, `pspy` (Çalışan prosesleri dinleyerek komut satırına yazılan şifreleri yakalar).
*   **Windows:** `WinPEAS.exe`, `PowerUp.ps1`, `Seatbelt.exe`.

---

#### **4. İleri Seviye Teknikler**

*   **Bellek Dökümlerini Analiz Etme (Memory Analysis):**
    *   **Windows:** `mimikatz` aracı, LSASS prosesinin belleğinden açık metin Windows şifrelerini, hash'leri ve Kerberos biletlerini çıkarabilir. Bu, en güçlü yetki yükseltme tekniklerinden biridir.
    *   **Linux:** `gcore` ile bir prosesin bellek dökümünü alıp `strings` ile içinde şifre arayabilirsiniz.
*   **Grup Politikaları (GPO) ve Oturum Açma Betikleri (Windows):**
    *   Active Directory ortamlarında, yöneticiler bazen GPO kullanarak şifreleri dağıtırlar. Domain Controller'daki `SYSVOL` paylaşımında bulunan betik ve XML dosyaları (`Groups.xml`) şifrelenmiş (ama kolayca çözülebilen) parolalar içerebilir.
*   **Tarayıcı Veritabanları (Browser Databases):**
    *   Kullanıcıların tarayıcılarında (`Chrome`, `Firefox`) kayıtlı şifreler, SQLite veritabanlarında saklanır. `LaZagne` gibi araçlar bu veritabanlarını otomatik olarak bulup şifreleri çözer.

---

#### **5. Korunma Yöntemleri (Savunma Tarafı)**

Bu saldırıların hedefi olmamak için aşağıdaki en iyi uygulamaları benimseyin:

1.  **ASLA Şifreleri Hardcode Etmeyin:** Şifreleri, API anahtarlarını veya token'ları doğrudan koda veya yapılandırma dosyalarına yazmayın.
2.  **Ortam Değişkenleri (.env) ve Secrets Management Kullanın:** Hassas verileri ortam değişkenlerinden (environment variables) okuyun. Geliştirme ortamında `.env` dosyaları kullanın ve bu dosyaları `.gitignore` ile versiyon kontrolüne eklemeyi **unutmayın**. Üretim ortamında **HashiCorp Vault**, **AWS Secrets Manager**, **Azure Key Vault** gibi merkezi sır yönetimi araçları kullanın.
3.  **Komut Geçmişini Kontrol Edin:** Hassas bir komut çalıştıracaksanız, `export HISTCONTROL=ignorespace` ayarı aktifken komutun başına bir boşluk koyarak geçmişe kaydedilmesini engelleyin. Veya `set +o history` ile geçmişi geçici olarak kapatın.
4.  **En Düşük Yetki Prensibi (Principle of Least Privilege):** Bir kullanıcı veya servise, işini yapması için gereken minimum yetkileri verin. `www-data` kullanıcısının `/home/` dizinini okuyamaması gerekir.
5.  **Sıkı Dosya İzinleri:** Yapılandırma dosyaları gibi hassas dosyaların izinlerini sıkılaştırın. `chmod 600 config.ini` komutu, dosyayı sadece sahibi tarafından okunabilir ve yazılabilir hale getirir.
6.  **Kod Gözden Geçirme (Code Review):** Kodları üretim ortamına göndermeden önce, içinde unutulmuş şifre veya hassas veri olup olmadığını kontrol etmek için gözden geçirme süreçleri oluşturun.
7.  **Sistemleri Düzenli Olarak Denetleyin:** Yukarıda bahsedilen otomatik araçları (`LinPEAS`, `WinPEAS`) savunma amacıyla kullanarak kendi sistemlerinizde unutulmuş "dijital kırıntıları" proaktif olarak bulun ve temizleyin.

---

#### **Etik ve Yasal Uyarı**

Bu rehberde açıklanan teknikler, yalnızca **yasal izin ve yetkiyle** siber güvenlik tatbikatları (penetration testing), CTF (Capture The Flag) yarışmaları ve eğitim amacıyla kullanılmalıdır. Bu bilgilerin izinsiz sistemlere sızmak için kullanılması yasa dışıdır ve ciddi hukuki sonuçları vardır. Bilgi, savunmayı güçlendirmek için bir araçtır.
