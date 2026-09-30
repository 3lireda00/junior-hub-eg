# Junior Hub Authentication API

جزء الـAuthentication لمنصة Junior Hub باستخدام ASP.NET Core 9 وSQL Server وASP.NET Core Identity وJWT.

## التشغيل

1. ثبّت .NET 9 وSQL Server LocalDB (أو غيّر `ConnectionStrings:DefaultConnection` في `appsettings.json`).
2. من مجلد المشروع شغّل:

```powershell
dotnet restore
dotnet run
```

ينشئ التطبيق قاعدة البيانات تلقائيًا عند أول تشغيل. غيّر `Jwt:Key` إلى قيمة سرية عشوائية طويلة قبل النشر، ولا ترفع المفتاح الحقيقي إلى Git. يمكن ضبط القيم عبر متغيرات البيئة مثل `Jwt__Key` و`ConnectionStrings__DefaultConnection`.

في بيئة التطوير افتح `http://localhost:5124/swagger` لتجربة الطلبات من Swagger UI.

## المسارات

### `POST /api/auth/register`

Guardian:

```json
{
  "role": "Guardian",
  "fullName": "Parent Name",
  "email": "parent@example.com",
  "password": "StrongPass123",
  "confirmPassword": "StrongPass123",
  "learnerName": "Learner Name",
  "learnerDateOfBirth": "2012-05-01",
  "acceptTerms": true,
  "accuracyConfirmed": true
}
```

Learner:

```json
{
  "role": "Learner",
  "fullName": "Learner Name",
  "email": "learner@example.com",
  "password": "StrongPass123",
  "confirmPassword": "StrongPass123",
  "dateOfBirth": "2012-05-01",
  "learningInterest": "Programming",
  "guardianName": "Parent Name",
  "guardianEmail": "parent@example.com",
  "acceptTerms": true,
  "accuracyConfirmed": true
}
```

الدور يقبل `Learner` أو `Guardian` في التسجيل. بيانات ولي الأمر للمتعلم وبيانات المتعلم لولي الأمر تحفظ كجزء من الملف الشخصي. `Mentor` متاح لتسجيل الدخول فقط، والحسابات الإدارية/المرشدين تُنشأ يدويًا من قاعدة البيانات حاليًا.

### `POST /api/auth/login`

```json
{ "email": "parent@example.com", "password": "StrongPass123", "role": "Guardian" }
```

عند النجاح يرجع JWT صالحًا لمدة 60 دقيقة. أرسله في الطلبات المحمية بصيغة `Authorization: Bearer <accessToken>`.

### `GET /api/auth/me`

مسار محمي يعيد بيانات المستخدم من الـJWT. لإكمال ربط الحسابات وولي الأمر، أضف `Authorization: Bearer <token>`.

## ما تم بناؤه

- تخزين الحسابات في SQL Server باستخدام ASP.NET Core Identity، وكلمات المرور مجزأة ومملحة بواسطة Identity.
- أدوار Learner وGuardian وMentor، والتحقق من الدور المختار عند تسجيل الدخول.
- JWT بتوقيع HMAC، تحقق من المصدر والجمهور والصلاحية، ومدة انتهاء قابلة للضبط.
- قفل مؤقت بعد خمس محاولات دخول فاشلة، والتحقق من البريد وكلمة المرور ومدخلات التسجيل.
- ربط بيانات ولي الأمر الأولية بحساب المتعلم وانتظار موافقته.

قاعدة البيانات تُنشأ بـ`EnsureCreated` لسهولة تشغيل نموذج التخرج. عند اعتماد مخطط قاعدة البيانات النهائي، يُفضّل الانتقال إلى EF Core Migrations وإضافة تأكيد البريد واستعادة كلمة المرور بالبريد. موافقة ولي الأمر الفعلية يمكن إضافتها كميزة لاحقة.
