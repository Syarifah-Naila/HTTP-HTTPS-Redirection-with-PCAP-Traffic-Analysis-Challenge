# HTTP-HTTPS-Redirection-with-PCAP-Traffic-Analysis-Challenge

| Nama | NRP |
|------------|-------------|
| Syarifah Naila | 5027251109 |
| Irsa Fairuza | 5027251115 |
| Razana Aulia | 5027251127 |

## 1. Informasi Awal

| | |
|---|---|
| **Nama File** | `2015-05-08-traffic-analysis-exercise.pcap` |
| **Jumlah Paket** | 761 paket (745 TCP, 16 UDP) |
| **Host Korban** | `192.168.138.158` (Windows 7 64-bit, IE7/IE8) |

---

### Langkah 1 — Identifikasi IP yang paling banyak bertukar data
Membuka **Statistics > Conversations** di tab IPv4 untuk melihat pasangan IP yang paling banyak berkomunikasir. IP dengan traffic tertinggi jadi kandidat awal yang dicurigai.

<img width="1500" height="200" alt="top-talker" src="https://github.com/user-attachments/assets/412f90cd-1371-4a8e-8d16-3166df77bab4" />

### Langkah 2 — Melihat request awal korban
**Filter:** `http.request`

<img width="734" height="307" alt="request-korban" src="https://github.com/user-attachments/assets/c7dda7de-c72d-4b36-a0dc-9676f8207bb6" />

- Ditemukan path yang sangat panjang, ini paket pertama jadi bisajadi pas baru buka web korban dialihin kesini dan bisa micu request setelahnya diarahin kesini juga (paket #6): `GET /?285a4d4e4e5a4d4d4649584c5d43064b4745`
- Host tujuan punya subdomain berlapis dan acak: `va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in`

### Langkah 3 — Lihat seluruh request GET korban
**Filter:** `http.request.method == "GET"`

<img width="742" height="290" alt="filter-get" src="https://github.com/user-attachments/assets/0241b971-3a1f-4426-9225-bcfd1f1e54f6" />


- Ditemukan file `bitcoin.png` dan `button_pay.png` yang diambil dari server `95.163.121.204` (host: `7oqnsnzwwnm6zb7y.gigapaysun.com`)
- Pada temuan ini korban diarahin buat ke halaman pembayaran ransomware untuk instruksi bayar tebusan pake bitcoin

### Langkah 4 — Lihat seluruh request POST korban ke server
**Filter:** `http.request.method == "POST"`

<img width="749" height="117" alt="image" src="https://github.com/user-attachments/assets/4dc2d247-8824-425b-a03d-9b07d7b4780c" />

- Ditemukan pengiriman data berukuran besar (Length: 783 bytes) ke IP `95.163.121.204`, ini pengiriman data penting ke yang sama dengan halaman pembayaran
- Ditemukan juga pola POST berulang ke path `/wp-content/themes/twentyfifteen/img5.php` dan `/wp-content/themes/grizzly/img5.php`, dikirim ke dua IP berbeda (`72.34.49.86` dan `204.152.254.221`) dan parameter nya berubah-ubah (`t`, `c`, `l`, `u`, `f`)

### Langkah 5 — Export HTTP Objects
Dilakukan **File > Export Objects > HTTP** untuk melihat seluruh objek yang ditransfer melalui HTTP dalam satu daftar.

| Paket | Hostname | Content-Type |
|---|---|---|
| 8 | va872g...groupprograms.in | text/html |
| 49 | ubb67...groupprograms.in | **application/x-shockwave-flash** |
| 176–508 | 62.75.195.236 | text/html (beberapa berisi payload biner tersamar) |
| 482 | ip-addr.es | text/plain |
| 496, 534, 561, 632 | runlove.us | application/x-www-form-urlencoded |
| 522, 544, 573, 621 | comarksecurity.com | application/x-www-form-urlencoded |

> Objek yang Content-Type nya `application/x-shockwave-flash` di paket 49 jadi fokus utama karena gak wajar kalau file flash berukuran kecil, dan muncul tepat setelah landing page pertama.


### Langkah 6 — Menyimpan file mencurigakan
File pada paket 49 (Content-Type: `application/x-shockwave-flash`) disimpan  dengan **Save** di Export Objects, dengan nama file `curiga`.

### Langkah 7 — Menghitung hash SHA256 lewat terminal
```
PS> certutil -hashfile curiga SHA256
```
Hash yang didapat:
```
81523163b298f2543d5f56a4c44ef8b07c6c9b3844b629b04fb870ca356c1437
```

---

## 2. Verifikasi Reputasi di web VirusTotal

Hash file dicek pada `virustotal.com/gui/file/81523163b298f2543d5f56a4c44ef8b07c6c9b3844b629b04fb870ca356c1437` dengan hasil berikut:

| Vendor | Nama Deteksi |
|---|---|
| AliCloud | Exploit.Win/CVE-2015-0311.I |
| ESET-NOD32 | SWF/Exploit.CVE-2015-0311.I Trojan |
| Varist | SWF/CVE150311 |
| AVG | SWF:Malware-gen [Trj] |
| Avast | SWF:Malware-gen [Trj] |
| CTX | Swf.trojan.generic |
| Kaspersky | HEUR:Trojan.SWF.Agent.gen |
| Tencent | Win32.Trojan.Agent.Fajl |
| Skyhigh (SWG) | BehavesLike.Flash.Exploit.zb |

**Kesimpulan :** file ini adalah exploit aktif untuk kerentanan **CVE-2015-0311** pada Adobe Flash Player, yang merupakan celah zero-day yang tereksploitasi luas oleh berbagai exploit kit. Temuan ini sesuai dengan konteks pcap dan mengonfirmasi bahwa file `.swf` yang dikirim otomatis di awal traffic memang merupakan senjata eksploitasi, bukan konten Flash biasa.

---

## 3. Daftar Indicator

### 6.1 Alamat IP

| IP | Peran |
|---|---|
| 62.75.195.236 | Server exploit kit (landing page, Flash exploit, download malware EXE) |
| 95.163.121.204 | Halaman pembayaran ransomware (gigapaysun.com) |
| 72.34.49.86 | Server C2 (comarksecurity.com) |
| 204.152.254.221 | Server C2 (runlove.us) |
| 188.165.164.184 | Layanan cek IP publik (ip-addr.es) |

### 6.2 Domain

- `*.groupprograms.in` (subdomain acak/berlapis — exploit kit gate)
- `gigapaysun.com` (halaman pembayaran ransomware)
- `runlove.us` (C2)
- `comarksecurity.com` (C2)
- `ip-addr.es` (cek IP publik korban)

### 6.3 Hash File

| Jenis | Nilai |
|---|---|
| SHA256 (exploit .swf) | `81523163b298f2543d5f56a4c44ef8b07c6c9b3844b629b04fb870ca356c1437` |

### 6.4 User-Agent

```
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)
```

Digunakan secara konsisten di hampir seluruh request, termasuk pada fase C2 dan halaman pembayaran, jadi menjadi penanda perilaku otomatis (bukan browsing manusia biasa) dan dapat digunakan jadi salah satu penanda deteksi tambahan.

---

## 7. Kesimpulan

Traffic ini terbukti berisi rangkaian serangan siber. Awalnya, korban kena exploit kit yang manfaatin celah keamanan di Adobe Flash Player (CVE-2015-0311, sudah dikonfirmasi lewat pengecekan di VirusTotal). Setelah itu, malware berhasil diunduh dan dijalankan di komputer korban. Malware ini juga terus-terusan ada ke beberapa server milik penyerang secara bergantian, sampai korban diarahkan ke halaman pembayaran ransomware untuk membayar tebusan. Semua ini adalah ciri khas yang biasa ditemukan pada serangan exploit kit dan ransomware.

---
