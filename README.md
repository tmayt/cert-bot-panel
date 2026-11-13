# Certbot Panel

پنل وب ساده برای صدور گواهی SSL Wildcard با Let's Encrypt و DNS Challenge دستی.

## ویژگی‌ها

- صدور گواهی Wildcard (`*.example.com` + `example.com`)
- نمایش رکورد TXT برای تنظیم دستی DNS
- بررسی خودکار DNS قبل از صدور گواهی
- نگهداری لیست دامنه‌ها و تمدید از پنل
- دانلود فایل‌های گواهی (ZIP)

## راه‌اندازی

```bash
cp .env.example .env
# ایمیل Let's Encrypt و یوزرنیم/پسورد ادمین را در .env تنظیم کنید

docker compose up -d --build
```

پنل روی `http://localhost:4234` در دسترس است. قبل از استفاده باید با حساب ادمین وارد شوید.

## ساخت خودکار ایمیج

با هر push، گردش‌کار `.gitea/workflows/build-image.yml` یک بار ایمیج را می‌سازد و به این آدرس پوش می‌کند:

`gitea.tmayt.ir/thaiostream/certbot-panel`

تگ `latest` همان آدرسی است که `docker-compose.yml` استفاده می‌کند. هر بیلد هم با تگ SHA همان commit هم پوش می‌شود.

اطلاعات ورود Gitea را در مخزن بگذارید: Settings → Actions → Secrets. این مقادیر داخل مخزن نمی‌آیند.

| سکرت | مقدار |
|------|-------|
| `GITEA_USERNAME` | نام کاربری Gitea |
| `GITEA_PASSWORD` | رمز عبور، یا personal access token با دسترسی نوشتن پکیج |

رانر Actions باید برچسب `ubuntu-latest` داشته باشد و دستور `docker` روی همان رانر قابل اجرا باشد. بعد از پوش موفق ایمیج:

```bash
docker compose pull
docker compose up -d
```

## نحوه استفاده

1. دامنه را وارد کنید (مثلاً `example.com`)
2. رکورد TXT نمایش داده شده را در DNS اضافه کنید
3. چند دقیقه صبر کنید تا propagate شود
4. دکمه «بررسی DNS و صدور گواهی» را بزنید
5. اگر Let's Encrypt رکورد را رد کرد، «تلاش مجدد همین مرحله» را بزنید. صدور از اول شروع نمی‌شود
6. گواهی را دانلود کنید

## متغیرهای محیطی

| متغیر | پیش‌فرض | توضیح |
|-------|---------|-------|
| `LETSENCRYPT_EMAIL` | `admin@example.com` | ایمیل ثبت در Let's Encrypt |
| `CERTBOT_STAGING` | `false` | استفاده از سرور staging برای تست |
| `CERTBOT_API_TOKEN` | خالی | اگر تنظیم شود، همه مسیرهای `/api` به هدر `X-API-Key` نیاز دارند |
| `ADMIN_USERNAME` | `admin` | نام کاربری ورود به پنل |
| `ADMIN_PASSWORD` | خالی | رمز عبور ورود به پنل (الزامی) |
| `SESSION_SECRET` | خالی | کلید امضای کوکی نشست؛ در ری‌استارت ثابت بماند |
| `LOGIN_MAX_ATTEMPTS` | `5` | سقف تلاش ناموفق ورود از یک آدرس؛ `0` یعنی بدون محدودیت |
| `LOGIN_WINDOW_SECONDS` | `900` | مدت به‌خاطر سپردن تلاش‌های ناموفق، به ثانیه |

## API

همه عملیات پنل از مسیر `/api` هم در دسترس است. اگر `CERTBOT_API_TOKEN` تنظیم شده باشد هدر `X-API-Key` یا `Authorization: Bearer <token>` لازم است.

| روش | مسیر | توضیح |
|-----|------|--------|
| `GET` | `/api/health` | وضعیت سرویس |
| `GET` | `/api/domains` | لیست دامنه‌ها (`?name=example.com` برای فیلتر) |
| `POST` | `/api/domains` | شروع صدور گواهی `{ "domain": "example.com" }` |
| `GET` | `/api/domains/{id}` | جزئیات و رکوردهای TXT |
| `POST` | `/api/domains/{id}/verify` | بررسی DNS و ادامه صدور |
| `POST` | `/api/domains/{id}/renew` | تمدید |
| `POST` | `/api/domains/{id}/retry` | تلاش مجدد؛ اگر DNS رد شده باشد همان مرحله ادامه پیدا می‌کند |
| `DELETE` | `/api/domains/{id}` | حذف دامنه از پنل |
| `GET` | `/api/domains/{id}/certificate` | محتوای PEM فایل‌های گواهی |
| `GET` | `/api/domains/{id}/download` | دانلود ZIP |

## ساختار داده

گواهی‌ها و دیتابیس در volume داکر (`certbot-data`) ذخیره می‌شوند.
