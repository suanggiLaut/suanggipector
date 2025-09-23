<div align="center">
  <h1 align="center">suanggipector 🕵️‍♂️</h1>
  <p align="center">
    <strong>Tools recon untuk memburu endpoint, secret, dan informasi sensitif di dalam file JavaScript.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python Version">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/Status-Aktif-brightgreen" alt="Status">
  </p>
</div>

<p align="center">
  <img src="https://user-images.githubusercontent.com/YOUR_USER_ID/YOUR_REPO_ID/....gif" alt="suanggipector-demo">
</p>

`suanggipector` adalah tools recon sederhana berbasis Python yang secara otomatis merayapi situs web target untuk menemukan semua file JavaScript (eksternal & inline). Setelah itu, ia akan memindai isinya untuk mencari informasi menarik yang sering kali tersembunyi, seperti endpoint API, potensi secret, API key, dan subdomain.

## ✨ Fitur Utama

- **Crawling Cerdas**: Menemukan semua tag `<script>` dari URL target.
- **Ekstraksi Komprehensif**: Menganalisis file `.js` eksternal dan juga script *inline*.
- **Pemindaian Berbasis Regex**: Menggunakan pola-pola cerdas untuk mendeteksi:
    - Path URL & Endpoint API (`/api/v1/users`)
    - API Key (Google, AWS, dll.)
    - URL Pihak Ketiga (misalnya, Firebase)
    - Kata Kunci Sensitif (`secret`, `token`, `password`, `auth_key`)
- **Tampilan Interaktif**: Output berwarna yang bersih untuk memudahkan analisis.
- **Simpan Hasil**: Opsi untuk menyimpan semua temuan ke dalam file teks.

---

## 🚀 Instalasi & Persiapan

Anda bisa menjalankan `suanggipector` hanya dengan beberapa langkah mudah.

```bash
# 1. Clone repositori ini
git clone [https://github.com/suanggiLaut/suanggipector.git](https://github.com/suanggiLaut/suanggipector.git)

# 2. Masuk ke direktori
cd suanggipector

# 3. (Sangat disarankan) Buat dan aktifkan virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install semua dependensi yang dibutuhkan
pip install -r requirements.txt
