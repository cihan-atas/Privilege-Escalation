# Yetki Yükseltme Teknikleri Rehberi (Awesome Privilege Escalation)

Bu repo, siber güvenlik meraklıları, CTF oyuncuları ve sızma testi uzmanları için bir kaynak olarak tasarlanmıştır. Amacı, Linux ve Windows sistemlerinde kullanılan yetki yükseltme (Privilege Escalation) tekniklerini derlemek ve adım adım açıklamaktır.

## 📂 İçindekiler

Aşağıdaki listeden incelemek istediğiniz tekniği seçebilirsiniz.

### 🐧 Linux Teknikleri

*   **[LD_PRELOAD Hijacking](./linux/LD_PRELOAD-Hijacking.md)** - `LD_PRELOAD` ortam değişkenini kötüye kullanarak paylaşılan kütüphaneler aracılığıyla yetki yükseltme tekniği.
*   **[PATH Değişkeni Manipülasyonu (PATH Hijacking)](./linux/PATH-Hijacking.md)** - Yüksek yetkili bir programı kandırarak, `PATH` ortam değişkeni üzerinden zararlı script'ler çalıştırma tekniği.
*   **[Parola Madenciliği (Password Mining)](./linux/Password_Mining.md)** - Sistemdeki yapılandırma dosyalarından, geçmiş kayıtlardan veya betiklerden parola ve hassas bilgileri arama.
*   **[SUID Zafiyetleri](./linux/SUID.md)** - SUID biti ayarlanmış çalıştırılabilir dosyaları kullanarak yetki yükseltme yöntemleri.
*   **[SU Kaba Kuvvet Saldırısı (SU Brute-force)](./linux/su-bruteforce.md)** - `su` komutu aracılığıyla kullanıcı parolalarına yönelik kaba kuvvet saldırısı gerçekleştirme.
