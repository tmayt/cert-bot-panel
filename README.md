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
# تنظیم ایمیل Let's Encrypt
export LETSENCRYPT_EMAIL=your@email.com

# (اختیاری) استفاده از staging برای تست
export CERTBOT_STAGING=true

docker compose up -d --build
```

پنل روی `http://localhost:8000` در دسترس است.

## نحوه استفاده

1. دامنه را وارد کنید (مثلاً `example.com`)
2. رکورد TXT نمایش داده شده را در DNS اضافه کنید
3. چند دقیقه صبر کنید تا propagate شود
4. دکمه «بررسی DNS و صدور گواهی» را بزنید
5. گواهی را دانلود کنید

## متغیرهای محیطی

| متغیر | پیش‌فرض | توضیح |
|-------|---------|-------|
| `LETSENCRYPT_EMAIL` | `admin@example.com` | ایمیل ثبت در Let's Encrypt |
| `CERTBOT_STAGING` | `false` | استفاده از سرور staging برای تست |

## ساختار داده

گواهی‌ها و دیتابیس در volume داکر (`certbot-data`) ذخیره می‌شوند.
