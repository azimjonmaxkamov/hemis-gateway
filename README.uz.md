# HEMIS API Gateway

> 🇬🇧 [English version](README.md) · © 2026 Azimjon Makhkamov · [Apache-2.0](LICENSE)

OTM (oliy ta'lim muassasasi) HEMIS tizimining API'siga tashqi tizimlar **to'g'ridan-to'g'ri emas**, faqat shu gateway orqali,
har bir mijozga alohida sozlangan ruxsat doirasida ulanadi. HEMIS admin tokeni faqat gateway serverida
(shifrlangan holda) saqlanadi va hech qachon tashqariga chiqmaydi.

```
Tashqi tizim ──(hg_ kalit)──▶ hemis-api.otm.uz ──(admin token)──▶ student.otm.uz/rest
                              │ endpoint ruxsati
                              │ filtr ruxsati / qulflangan qiymatlar
                              │ ma'lumot doirasi (fakultet, guruh…)
                              │ limit, IP, CORS, muddat
                              │ shaxsiy ma'lumotlarni yashirish
                              └ audit jurnali, kesh, HEMIS 10 rps himoyasi
```

## Imkoniyatlar

**Gateway (proxy)**
- HEMIS API hujjatidagi barcha **346 ta endpoint** (Backend, Public, Student, Tutor, Vazirlik, Fast API) katalogga avtomatik import qilinadi.
- **Default deny**: mijozga yoqilmagan endpoint, hujjatda yo'q parametr, ruxsat berilmagan filtr — `403`.
- **Filtr darajasidagi nazorat**: har bir endpoint uchun ruxsat etilgan filtrlar ro'yxati; **qulflangan filtrlar** (masalan `_education_year=2024` — mijoz boshqa qiymat yubora olmaydi, bitta qiymat bo'lsa gateway o'zi qo'yadi); `max_limit`.
- **Ma'lumot doirasi (scope)**: mijozga "fakultet = 7" bersangiz, gateway barcha endpointlarda `_department` / `faculty_id` / `_faculty` filtrini majburan qo'yadi va boshqa qiymatni rad etadi. Doira bilan cheklab bo'lmaydigan endpointlar (masalan `student-info`) qat'iy rejimda bloklanadi.
- **Parameter pollution himoyasi**: `?_department=7&_department=9`, `_department[]=…` kabi aldash usullari rad etiladi.
- **Shaxsiy ma'lumotlar** (PINFL, pasport, telefon, manzil, tug'ilgan sana, rasm) javobdan olib tashlanadi — faqat mijoz va endpoint darajasida ikkalasida ham ruxsat bo'lsa ko'rinadi. Qo'shimcha yashiriladigan maydonlar (`salary`, `data.items.address`) sozlanadi.
- Avtorizatsiya turlari: **admin** (gateway HEMIS tokenini qo'shadi, mijoz yuborgan `Authorization` almashtiriladi), **passthrough** (talaba/tutor o'z JWT tokeni bilan), **public**, **fast**.
- Kalitlar `hg_<prefix>_<secret>` formatida, bazada faqat HMAC-SHA256 xeshi saqlanadi; muddat, IP oq ro'yxati (CIDR), CORS domenlari.
- **So'rovlar limiti** (har bir mijozga alohida): soniyalik (standart 10, HEMIS dagi kabi), daqiqalik va kunlik kvota; oshsa `429` + `Retry-After`. Qo'shimcha: nginx da IP bo'yicha 50 so'rov/soniya, noto'g'ri kalit bilan 10 daqiqada 30 urinishdan keyin IP bloki, admin va docs login urinishlari cheklangan.
- HEMIS Backend API ning **10 so'rov/soniya** cheklovidan oshmaslik uchun barcha workerlar uchun umumiy navbat; Redis keshi (spravochniklar 1 soat, statistika 5 daqiqa).
- HEMIS token xatolari mijozga oshkor qilinmaydi (`502 upstream_auth`), brute-force himoyasi.

**Xavfsizlik va botlardan himoya**
- **IP qora / oq ro'yxati** panelda: IP yoki CIDR, muddat (1 soat … doimiy), qayerga (hammasi / API / admin / docs). Ishonchli IP lar bloklardan ustun va avtomatik ban qilinmaydi. O'z IP ingizni bloklab qo'yishdan himoya bor.
- **Excel eksport / import** (oq va qora ro'yxat uchun alohida): eksport (faol / hammasi), shablon (yo'riqnoma varag'i bilan), import — avval **Tekshirish** (qaysi qatorlar qo'shiladi, yangilanadi, qaysilari xato), so'ng **Qo'shish** yoki **Almashtirish** rejimida yozish. Tugash vaqti sana (31.12.2026 18:00) yoki nisbiy («7 kun», «12 soat») ko'rinishida. Tanlab ommaviy o'chirish ham bor.
- **Bosqichma-bosqich avtomatik ban**: 5 daqiqada 50 ta rad etilgan so'rov (401/403/404, noto'g'ri kalit, xato login ×3) → 15 daqiqa, takrorlansa 1 soat, keyin 24 soat. Barcha chegaralar panelda sozlanadi.
- **Kalit o'g'irlanishini aniqlash**: kalit 10 daqiqada 20 tadan ko'p turli IP dan ishlatilsa mijoz avtomatik vaqtincha to'xtatiladi (mijozga alohida chegara ham berish mumkin). Admin qo'lda to'xtatishi / qayta yoqishi mumkin.
- **Captcha**: admin va docs sahifalarida 3 ta xato logindan keyin server tomonda yaratiladigan rasmli captcha (tashqi servissiz, bir martalik).
- **Telegram ogohlantirishlari**: IP ban, mijoz to'xtatilishi, admin akkaunt bloki, admin yangi IP dan kirishi, HEMIS token xatosi, 5xx xatolar ko'payishi, login brute-force. Takroriy xabarlar 10 daqiqaga jamlanadi.
- **fail2ban**: har bir ban `data/security.log` ga yoziladi; `deploy/fail2ban/` dagi konfiguratsiya bilan IP server firewall darajasida ham yopiladi.
- Barcha hodisalar **Xavfsizlik → Hodisalar** bo'limida saqlanadi.

**Boshqaruv paneli** (`/admin`)
- **Nazorat**: so'rovlar dinamikasi, rad etish sabablari, eng faol mijozlar va endpointlar, shubhali IP'lar, tizim holati.
- **Statistika**: talabalar va xodimlar (turli kesimlarda), qarzdorlar, akademik qarzdorlik / dars qoldirish, davomat, bugungi dars qoldirish, ochiq statistika.
- **Mijozlar**: yaratish, kalitni almashtirish, doira, limitlar; **ruxsatlar muharriri** (guruhlar, qidiruv, har endpoint uchun filtrlar, qulflar, maydonlar), boshqa mijozdan nusxalash; **Sinov** — so'rov o'tadimi va HEMIS ga qanday ketishini HEMIS ga yubormasdan tekshirish.
- **Endpointlar katalogi**: global yoqish/o'chirish, avtorizatsiya turi, xavf darajasi, kesh, parametr ↔ doira bog'lanishi, yangi OpenAPI faylni yuklash.
- **Jurnallar**: barcha so'rovlar (filtrlar bilan) va admin amallari audit jurnali.
- **Xavfsizlik**: rollar (superadmin / admin / auditor), 2FA (TOTP), bloklash, httpOnly+SameSite cookie, CSRF, CSP, admin panelni IP bo'yicha cheklash.

**API hujjatlari — Swagger** (`/docs`) — HEMIS ning o'z swagger sahifasiga o'xshash, lekin har bir mijoz
admin bergan **docs login/parol** bilan kiradi va faqat **o'ziga ruxsat berilgan** endpointlarni ko'radi:
ruxsatsiz filtrlar ko'rinmaydi, qulflangan va doira qiymatlari ro'yxat (enum) bo'lib chiqadi, `limit` maksimumi,
yashiriladigan maydonlar va limitlar yozib qo'yiladi. "Authorize" ga kalitni kiritib, shu yerning o'zida so'rov
yuborib sinash mumkin (kalit brauzerda saqlanmaydi). Login/parol mijoz yaratilganda beriladi, panelda
"Docs paroli" tugmasi bilan yangilanadi (eski sessiyalar darhol bekor bo'ladi).

**Dasturchilar portali** (`/portal`) — mijoz o'z kaliti bilan qaysi endpoint va filtrlarga ruxsati borligini ko'radi (`GET /gateway/me`).

## O'rnatish (Ubuntu server, Docker)

```bash
# 1. Kodni serverga ko'chiring
cd /opt && sudo mkdir hemis-gateway && sudo chown $USER hemis-gateway
# (arxivni shu papkaga oching)

# 2. Sozlamalar
cp .env.example .env
docker compose run --rm app python -m app.cli gen-secrets   # chiqqan qiymatlarni .env ga yozing
nano .env      # HEMIS_ADMIN_TOKEN, ADMIN_ALLOWED_IPS, INIT_ADMIN_PASSWORD

# 3. Ishga tushirish
sudo chown -R 10001 data            # konteyner security.log va katalogni yoza olishi uchun
docker compose up -d --build
docker compose logs app | grep -i superadmin   # birinchi parol (agar INIT_ADMIN_PASSWORD bermagan bo'lsangiz)

# 4. Nginx + SSL
sudo cp deploy/nginx-hemis-api.conf /etc/nginx/sites-available/hemis-api.otm.uz
sudo ln -s /etc/nginx/sites-available/hemis-api.otm.uz /etc/nginx/sites-enabled/
sudo certbot --nginx -d hemis-api.otm.uz && sudo nginx -t && sudo systemctl reload nginx
```

So'ng `https://hemis-api.otm.uz/admin` ga kiring → parolni o'zgartiring → 2FA yoqing → **Sozlamalar**da HEMIS tokenini kiriting va "Ulanishni tekshirish".
Keyin **Xavfsizlik** bo'limida: OTM tarmog'i va server IP sini "Ishonchli IP" ga qo'shing, **Telegram** yorlig'ida bot token va chat ID ni kiritib "Test xabar" yuboring.
fail2ban: `deploy/fail2ban/README.md`.

**HEMIS token olish**: HEMIS admin panelida gateway uchun alohida foydalanuvchi yarating va unga `API User` rolini bering ([qo'llanma](https://t.me/hemis_university/525)).

## Mijoz qo'shish (tartib)

1. **Mijozlar → Yangi mijoz**: nomi, mas'ul shaxs, IP manzillari, limit, kerak bo'lsa doira (fakultet ID).
2. Chiqqan **API kaliti** va **docs login/parolini** mijozga xavfsiz kanal orqali bering (ikkalasi ham faqat bir marta ko'rsatiladi). Docs login/parol — `/docs` sahifasiga kirish uchun, API kaliti — so'rovlar uchun.
3. **Ruxsatlar** bo'limida faqat kerakli endpointlarni yoqing → "Sozlash" orqali filtrlarni cheklang → Saqlash.
4. **Sinov** bo'limida mijoz URL'larini tekshiring.

## Mijoz uchun ishlatish

```bash
# Backend API — HEMIS bilan bir xil yo'llar, faqat manzil va kalit boshqa
curl -H "X-Gateway-Key: hg_xxxxxxxxxx_xxxx" \
  "https://hemis-api.otm.uz/rest/v1/data/student-list?limit=50&_group=45"

# HEMIS dagi kabi Bearer ham ishlaydi (Backend/Public endpointlar uchun)
curl -H "Authorization: Bearer hg_xxxxxxxxxx_xxxx" https://hemis-api.otm.uz/rest/v1/data/student-stats

# Student API — Authorization da talaba tokeni, kalit alohida headerda
curl -X POST -H "X-Gateway-Key: hg_…" -H "Content-Type: application/json" \
  -d '{"login":"...","password":"..."}' https://hemis-api.otm.uz/rest/v1/auth/login
curl -H "X-Gateway-Key: hg_…" -H "Authorization: Bearer <talaba_jwt>" \
  https://hemis-api.otm.uz/rest/v1/account/me
```

Xato javoblari HEMIS formatida, qo'shimcha `gateway_code` bilan:
`{"success": false, "error": "'search' filtridan foydalanish sizga ruxsat etilmagan", "code": 403, "gateway_code": "param_not_allowed"}`

## Xizmat ko'rsatish

```bash
docker compose exec app python -m app.cli reset-password admin   # admin parolini tiklash (2FA ham o'chadi)
docker compose exec app python -m app.cli sync-catalog            # HEMIS dan hujjatni qayta sinxronlash
docker compose exec db pg_dump -U gateway gateway > backup.sql    # zaxira nusxa
```

### HEMIS API hujjati (docs.json) yangilanganda

Kod relizi **kerak emas** — tuzilma panel orqali yangilanadi: **Endpointlar → HEMIS docs yangilash**.

1. Yangi docs.json ni fayl, URL yoki arxivdan tanlang → **Farqni ko'rish**: qo'shiladigan, olib tashlanadigan,
   filtrlari o'zgargan endpointlar va **qaysi mijozlarga qanday ta'sir qilishi** ko'rsatiladi.
2. **Qo'llash** — katalog, ruxsatlar muharriri va mijozlarning Swagger (`/docs`) sahifalari darhol yangilanadi.

Qoidalar:
- Mavjud ruxsatlar, kesh/xavf sozlamalari va doira bog'lanishlari saqlanadi.
- Yangi endpointlar hech bir mijozga yoqilmagan holda qo'shiladi (doira filtrlari avtomatik aniqlanadi).
- Hujjatdan olib tashlangan endpointlar o'chirilmaydi, «hujjatda yo'q» deb belgilanadi va `410 endpoint_removed`
  qaytaradi; keyingi versiyada qaytsa — avtomatik tiklanadi.
- Qulf qo'yilgan filtr hujjatdan yo'qolsa, endpoint shu mijoz uchun **rad etiladi** (`locked_param_missing`) —
  filtrsiz, kengroq ma'lumot berib yubormaslik uchun. Administrator ruxsatni qayta sozlaydi.
- Endpointlarning 30% dan ko'pini olib tashlaydigan fayl (ehtimol noto'g'ri fayl) alohida tasdiqsiz qo'llanmaydi.
- Har bir qo'llangan docs.json arxivlanadi (`data/specs/`) — istalgan eski versiyaga farqni ko'rib **qaytish** mumkin.
- **Avtomatik sinxronlash** (Endpointlar → Avto-sinxronlash) — docs.json ni qo'lda yuklash shart emas:
  tizim HEMIS docs ni o'zi yuklab oladi (manzilni HEMIS REST manzilidan **o'zi topadi** yoki qo'lda beriladi),
  har 1/3/6/12/24 soatda tekshiradi va rejimga qarab ishlaydi:
  - *Faqat xabar berish* — Hodisalar + Telegram, qo'llashni admin bajaradi;
  - *Xavfsiz o'zgarishlarni avtomatik qo'llash* (standart) — yangi endpoint/filtr, tavsif o'zgarishi, hech kim
    ishlatmayotgan endpointning olib tashlanishi avtomatik qo'llanadi; ishlatilayotgan endpoint yo'qolsa yoki
    qulflangan filtr o'chsa — to'xtab, tasdiq so'raydi (panelda «Ko'rib chiqish» tugmasi);
  - *Hammasini avtomatik qo'llash* — hammasi qo'llanadi va xabar beriladi (30% dan ko'p endpoint yo'qolsa baribir to'xtaydi);
  - *O'chirilgan*.
- **Qoidalar ham moslanadi**: HEMIS da o'chirilgan filtrlar mijozlarning ruxsat ro'yxatidan tozalanadi;
  «barcha filtrlar» yoqilgan mijozlarga yangi filtrlar standart bo'yicha **berilmaydi** (ro'yxat eski filtrlar
  bilan qotiriladi, sozlamadan o'zgartirish mumkin); yangi endpointlarning doira filtrlari o'zi aniqlanadi.

GitHub relizi faqat gateway **kodining** o'zi o'zgarganda (yangi funksiya, tuzatish) kerak bo'ladi.

## Muhim eslatmalar

- POST so'rovlarning **tanasi** (body) filtrlanmaydi — POST endpointlarni faqat ishonchli mijozlarga bering.
- Fayl yuklab olish endpointlari (`*-download`) binar javob qaytaradi, ularda maydon yashirish ishlamaydi — ular "yuqori xavf" deb belgilangan.
- Doira filtrining to'g'riligi HEMIS filtrni to'g'ri qo'llashiga bog'liq. Yangi endpointni doirali mijozga berishdan oldin **Sinov** va jurnal orqali tekshiring; kerak bo'lsa katalogda parametr ↔ doira bog'lanishini tuzating (masalan, ba'zi endpointlarda `_department` kafedrani bildiradi).
- `HEMIS_MAX_RPS` — barcha mijozlar uchun umumiy. Ko'p so'rovli mijozlarga kesh va kichik limit bering.

## Testlar

```bash
pip install -r requirements.txt pytest pytest-asyncio
pytest -q tests
```

## Tuzilma

```
app/
  main.py         ilova, xavfsizlik headerlari
  proxy.py        gateway: autentifikatsiya, limit, ruxsat, HEMIS ga yo'naltirish, kesh, maskalash
  policy.py       ruxsat dvigateli (endpoint, filtr, doira, maydonlar)
  catalog.py      OpenAPI → endpoint katalogi, xavf/kesh/doira tasnifi
  admin_api.py    panel API: mijozlar, ruxsatlar, katalog, jurnal, monitoring, sozlamalar
  admin_auth.py   admin kirish, 2FA, rollar, CSRF
  stats_api.py    statistika hisobotlari
  docs_portal.py  /docs: mijoz login, mijozga filtrlangan OpenAPI (Swagger UI)
  guard.py        IP qoidalari, avtomatik ban, kalit o'g'irlanishi, Telegram, security.log
  security_api.py panel API: xavfsizlik bo'limi
  captcha.py      rasmli captcha
  iplists.py      oq/qora ro'yxat: Excel eksport, shablon, import, ommaviy o'chirish
  spec_update.py  docs.json yangilash: farq, qo'llash, versiyalar arxivi, rollback, avtomatik tekshiruv
  state.py        xotiradagi konfiguratsiya (workerlar orasida sinxron)
  kv.py           Redis: limitlar, kesh, HEMIS rps navbati
  static/         boshqaruv paneli va portal (tashqi kutubxonasiz)
data/                     ish vaqtidagi fayllar (HEMIS hujjati, logo, arxiv) — repoga qo'shilmaydi
deploy/                   nginx konfiguratsiyasi
tests/                    testlar + soxta HEMIS server
```

## Mualliflik va litsenziya

**HEMIS API Gateway** — muallif: **Azimjon Makhkamov** (raqamlivodiy@gmail.com).
Copyright © 2026 Azimjon Makhkamov.

Loyiha [Apache License 2.0](LICENSE) asosida tarqatiladi: har qanday OTM bepul foydalanishi, o'zgartirishi va
tarqatishi mumkin. Shart — [LICENSE](LICENSE) va [NOTICE](NOTICE) fayllari hamda mualliflik ma'lumotlari
saqlanib qolishi, o'zgartirilgan fayllarda o'zgartirish qilingani ko'rsatilishi kerak.

«HEMIS» nomi va HEMIS API si o'z egalariga tegishli. Ushbu loyiha mustaqil bo'lib, HEMIS ning rasmiy API
hujjatiga asoslangan integratsiya vositasidir va HEMIS ishlab chiquvchilari tomonidan rasmiy tasdiqlanmagan.
