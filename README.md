# suanggipector 🕵️‍♂️

suanggipector (JavaScript Inspector) adalah tools recon sederhana berbasis Python. Tools ini merayapi situs web target, mengekstrak semua file JavaScript eksternal dan inline, lalu memindainya untuk mencari informasi menarik seperti endpoint API, potensi secret, API key, dan subdomain.

## Fitur
- **Merayapi Target**: Secara otomatis menemukan tag `<script>` pada URL yang diberikan.
- **Mengekstrak JS**: Menangani file JS eksternal (`src`) dan script inline.
- **Pemindaian Regex**: Menggunakan pola regex untuk menemukan:
    - Path URL & Endpoint API
    - API Key (Google, AWS)
    - URL Firebase
    - Secret/Token Generik
- **Output Berwarna**: Tampilan CLI yang bersih dan mudah dibaca.
- **Simpan ke File**: Opsi untuk menyimpan hasil pemindaian ke file teks.

## Instalasi
1.  **Clone repositori ini:**
    ```bash
    git clone [https://github.com/suanggiLaut/suanggipector.git](https://github.com/suanggipector/suanggipector.git)
    cd suanggipector
    ```

2.  **Install dependensi:**
    Sangat disarankan untuk menggunakan virtual environment.
    ```bash
    pip install -r requirements.txt
    ```

## Penggunaan
Cukup berikan URL target untuk memulai pemindaian.

```bash
python jspector.py -u [https://example.com](https://example.com)
