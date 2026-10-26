# YumzExe — Paket Deploy

## Isi paket
| File | Fungsi |
|---|---|
| index.html | Aplikasi utama (HTML + CSS + JS, satu file) |
| security.js | Lapisan keamanan sisi klien (wajib satu folder dengan index.html) |
| vercel.json | Rewrite URL: `/pp` dan `/t-o-u` |
| pp.html | Kebijakan Privasi (`yumz-exe.vercel.app/pp`) |
| t-o-u.html | Syarat Penggunaan (`yumz-exe.vercel.app/t-o-u`) |
| supabase.sql | Setup database Supabase (tabel, policy, trigger, data awal) |

## Cara deploy
1. Jalankan `supabase.sql` di Supabase > SQL Editor.
2. Upload semua file di zip ini ke root project Vercel (satu folder).
3. Deploy. Login Google jalan lewat Firebase, data lewat Supabase.

## Yang perlu diperhatikan
- Policy database di `supabase.sql` masih terbuka karena auth-nya Firebase. Kunci lewat Edge Function sebelum dipakai produksi.
- Isi `pp.html` dan `t-o-u.html` adalah draft umum. Sesuaikan dengan kondisi kamu.
- Setelah deploy, tes: login Google, kirim chat, ScriptBlox, tombol CS, Akun, dan Admin Panel.
