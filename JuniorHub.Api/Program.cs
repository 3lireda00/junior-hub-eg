using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using JuniorHub.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AuthDbContext>(o => o.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddIdentityCore<AppUser>(o =>
{
    o.User.RequireUniqueEmail = true;
    o.Password.RequiredLength = 10;
    o.Password.RequireDigit = true;
    o.Password.RequireUppercase = true;
    o.Password.RequireLowercase = true;
    o.Password.RequireNonAlphanumeric = false;
    o.Lockout.MaxFailedAccessAttempts = 5;
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
})
.AddRoles<IdentityRole<Guid>>()
.AddEntityFrameworkStores<AuthDbContext>()
.AddSignInManager();

var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key is missing.");
if (Encoding.UTF8.GetByteCount(jwtKey) < 32) throw new InvalidOperationException("Jwt:Key must contain at least 32 UTF-8 bytes.");
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true, ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateIssuerSigningKey = true, IssuerSigningKey = signingKey,
        ValidateLifetime = true, ClockSkew = TimeSpan.FromSeconds(30),
        RoleClaimType = ClaimTypes.Role, NameClaimType = ClaimTypes.NameIdentifier
    };
});
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Junior Hub Auth API", Version = "v1", Description = "تسجيل حساب وتسجيل دخول Junior Hub" });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization", Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT",
        In = ParameterLocation.Header, Description = "أدخل رمز الدخول فقط بدون كتابة كلمة Bearer."
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" } }] = Array.Empty<string>()
    });
});
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins(builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? ["http://localhost:3000", "http://localhost:5173"]).AllowAnyHeader().AllowAnyMethod()));
var app = builder.Build();
await using (var scope = app.Services.CreateAsyncScope())
    await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureCreatedAsync();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new { name = "Junior Hub Auth API", version = "1.0", routes = new[] { "POST /api/auth/register", "POST /api/auth/login", "GET /api/auth/me" } }));

app.MapPost("/api/auth/register", async (RegisterRequest req, UserManager<AppUser> users, RoleManager<IdentityRole<Guid>> roles) =>
{
    var validation = Validate(req);
    if (validation.Count != 0) return Results.ValidationProblem(validation);
    var email = req.Email!.Trim().ToLowerInvariant();
    if (await users.FindByEmailAsync(email) is not null) return Results.Conflict(new { message = "البريد الإلكتروني مسجل بالفعل." });
    var roleName = req.Role!;
    if (!await roles.RoleExistsAsync(roleName)) await roles.CreateAsync(new IdentityRole<Guid>(roleName));
    var isLearner = roleName == "Learner";
    var user = new AppUser
    {
        Id = Guid.NewGuid(), UserName = email, Email = email, FullName = req.FullName!.Trim(), Role = roleName,
        DateOfBirth = isLearner ? req.DateOfBirth : req.LearnerDateOfBirth,
        LearningInterest = isLearner ? req.LearningInterest?.Trim() : null,
        GuardianName = isLearner ? req.GuardianName?.Trim() : req.FullName!.Trim(),
        GuardianEmail = isLearner ? req.GuardianEmail!.Trim().ToLowerInvariant() : email,
        LearnerName = isLearner ? null : req.LearnerName!.Trim(),
        TermsAcceptedAt = DateTimeOffset.UtcNow
    };
    var created = await users.CreateAsync(user, req.Password!);
    if (!created.Succeeded) return IdentityErrorResult(created);
    var assigned = await users.AddToRoleAsync(user, roleName);
    if (!assigned.Succeeded) { await users.DeleteAsync(user); return IdentityErrorResult(assigned); }
    return Results.Created("/api/auth/me", new { message = isLearner ? "تم إنشاء الحساب. يلزم اعتماد ولي الأمر قبل تسجيل الدخول." : "تم إنشاء الحساب بنجاح.", user = Public(user) });
});

app.MapPost("/api/auth/login", async (LoginRequest req, UserManager<AppUser> users, SignInManager<AppUser> signIn, IConfiguration config) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password) || !IsKnownRole(req.Role))
        return Results.BadRequest(new { message = "البريد وكلمة المرور ودور صالح مطلوبة." });
    var user = await users.FindByEmailAsync(req.Email.Trim());
    if (user is null || user.Role != req.Role) return Results.Json(new { message = "البريد أو كلمة المرور غير صحيحة." }, statusCode: 401);
    var check = await signIn.CheckPasswordSignInAsync(user, req.Password, lockoutOnFailure: true);
    if (check.IsLockedOut) return Results.Json(new { message = "تم إيقاف المحاولات مؤقتًا. حاول بعد 10 دقائق." }, statusCode: 423);
    if (!check.Succeeded) return Results.Json(new { message = "البريد أو كلمة المرور غير صحيحة." }, statusCode: 401);
    var claims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, user.Id.ToString()), new(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new(JwtRegisteredClaimNames.Email, user.Email!), new(ClaimTypes.Name, user.FullName),
        new(ClaimTypes.Role, user.Role), new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };
    var expires = DateTime.UtcNow.AddMinutes(config.GetValue<int>("Jwt:ExpiryMinutes", 60));
    var token = new JwtSecurityToken(config["Jwt:Issuer"], config["Jwt:Audience"], claims, expires: expires,
        signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!)), SecurityAlgorithms.HmacSha256));
    return Results.Ok(new { accessToken = new JwtSecurityTokenHandler().WriteToken(token), tokenType = "Bearer", expiresAt = expires, user = Public(user) });
});

app.MapGet("/api/auth/me", (ClaimsPrincipal principal) => Results.Ok(new
{
    id = principal.FindFirstValue(ClaimTypes.NameIdentifier), email = principal.FindFirstValue(JwtRegisteredClaimNames.Email),
    fullName = principal.FindFirstValue(ClaimTypes.Name), role = principal.FindFirstValue(ClaimTypes.Role)
})).RequireAuthorization();

app.Run();

static IResult IdentityErrorResult(IdentityResult result) => Results.BadRequest(new { message = "تعذر إنشاء الحساب.", errors = result.Errors.Select(e => new { e.Code, e.Description }) });
static object Public(AppUser u) => new { u.Id, u.FullName, u.Email, u.Role, u.DateOfBirth, u.LearningInterest, u.GuardianName, u.GuardianEmail, u.LearnerName, u.TermsAcceptedAt };
static bool IsKnownRole(string? role) => role is "Learner" or "Guardian" or "Mentor";
static Dictionary<string, string[]> Validate(RegisterRequest r)
{
    var e = new Dictionary<string, string[]>(); void Add(string k, string v) => e[k] = [v];
    if (r.Role is not ("Learner" or "Guardian")) Add("role", "الدور يجب أن يكون Learner أو Guardian.");
    if (string.IsNullOrWhiteSpace(r.FullName) || r.FullName.Trim().Length > 120) Add("fullName", "الاسم مطلوب وبحد أقصى 120 حرفًا.");
    if (string.IsNullOrWhiteSpace(r.Email) || r.Email.Length > 254 || !Regex.IsMatch(r.Email, @"^[^\s@]+@[^\s@]+\.[^\s@]+$")) Add("email", "أدخل بريدًا إلكترونيًا صحيحًا.");
    if (string.IsNullOrEmpty(r.Password) || r.Password.Length < 10 || !r.Password.Any(char.IsUpper) || !r.Password.Any(char.IsLower) || !r.Password.Any(char.IsDigit)) Add("password", "كلمة المرور 10 أحرف على الأقل وتحتوي حرفًا كبيرًا وصغيرًا ورقمًا.");
    if (r.Password != r.ConfirmPassword) Add("confirmPassword", "كلمتا المرور غير متطابقتين.");
    if (!r.AcceptTerms) Add("acceptTerms", "يجب الموافقة على الشروط وسياسة الخصوصية.");
    if (r.Role == "Learner")
    {
        if (r.DateOfBirth is null || r.DateOfBirth >= DateOnly.FromDateTime(DateTime.UtcNow)) Add("dateOfBirth", "تاريخ ميلاد المتعلم غير صحيح.");
        if (string.IsNullOrWhiteSpace(r.LearningInterest)) Add("learningInterest", "مجال التعلم مطلوب.");
        if (string.IsNullOrWhiteSpace(r.GuardianName)) Add("guardianName", "اسم ولي الأمر مطلوب.");
        if (string.IsNullOrWhiteSpace(r.GuardianEmail) || !Regex.IsMatch(r.GuardianEmail, @"^[^\s@]+@[^\s@]+\.[^\s@]+$")) Add("guardianEmail", "بريد ولي الأمر غير صحيح.");
        if (!r.AccuracyConfirmed) Add("accuracyConfirmed", "يجب تأكيد دقة البيانات.");
    }
    if (r.Role == "Guardian" && (r.LearnerDateOfBirth is null || string.IsNullOrWhiteSpace(r.LearnerName))) Add("learner", "اسم المتعلم وتاريخ ميلاده مطلوبان.");
    return e;
}

record RegisterRequest(string? Role, string? FullName, string? Email, string? Password, string? ConfirmPassword,
    DateOnly? DateOfBirth, string? LearningInterest, string? GuardianName, string? GuardianEmail,
    string? LearnerName, DateOnly? LearnerDateOfBirth, bool AcceptTerms, bool AccuracyConfirmed);
record LoginRequest(string? Email, string? Password, string? Role);
