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

## Update v3 (yang baru)
- **Urutan deploy ulang**: jalankan `supabase.sql` lagi dulu (ada kolom & tabel baru: `username_set`, `global_chat.role`, `global_chat.avatar_url`, tabel `notifications`), baru upload file.
- **Username**: setelah login Google pertama kali, user wajib pilih username (3-20 karakter, unik). Username ini yang tampil di chat, dropdown, dan leaderboard.
- **Chat**: tiap pesan menampilkan foto profil + nama + badge role. Username, avatar, dan role dipaksa diambil dari server lewat trigger `chat_guard`, jadi tidak bisa dipalsukan dari client.
- **Role & badge**: Owner = centang emas berkilau (berbentuk lencana bulat), Admin = centang biru, Member = tanpa badge.
- **Tamu**: bisa masuk tanpa login dan melihat konten, tapi tidak bisa kirim chat.
- **Tips & Tutorial**: tombol Tips di nav bawah membuka panduan lengkap.
- **Routing**: halaman bisa dibuka lewat URL (`/script`, `/chat`, `/leaderboard`, `/akun`, `/tools`, `/executor`). URL yang tidak ada menampilkan halaman 404. `/admin` menampilkan halaman khusus.
- **Kirim pesan (owner)**: tombol kirim di samping leaderboard. Bisa kirim ke semua user atau ke user tertentu (lewat username).
- **Inbox**: tombol lonceng dengan titik merah jika ada pesan belum dibaca.
- **Font Awesome**: semua ikon sudah memakai Font Awesome (emoji di UI sudah diganti).

### Catatan keamanan
- Policy `notifications` insert masih terbuka seperti tabel lain di proyek ini. Owner bisa dipalsukan dari client sampai policy dikunci lewat Edge Function.
- Pesan pribadi (`to_email` terisi) tetap ikut terkirim ke semua client lewat realtime, karena filter-nya hanya di sisi client. Untuk privasi beneran, pakai RLS berdasarkan email.
