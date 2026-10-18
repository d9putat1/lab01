using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
       
app.MapPost("/api/auth/register", async (
    RegistrationInput input,
    UserManager<ApplicationUser> users) =>
{
    var errors = new Dictionary<string, string[]>();

    if (string.IsNullOrWhiteSpace(input.UserName))
        errors["userName"] = ["Ім'я користувача обов'язкове."];
    else if (input.UserName.Length > 256)
        errors["userName"] = ["Ім'я користувача не довше за 256 символів."];

    if (string.IsNullOrWhiteSpace(input.Email))
        errors["email"] = ["Email обов'язковий."];
    else if (input.Email.Length > 256)
        errors["email"] = ["Email не довший за 256 символів."];

    if (string.IsNullOrWhiteSpace(input.DisplayName))
        errors["displayName"] = ["Ім'я для показу обов'язкове."];
    else if (input.DisplayName.Length > 120)
        errors["displayName"] = ["Ім'я для показу не довше за 120 символів."];

    if (string.IsNullOrEmpty(input.Password))
        errors["password"] = ["Пароль обов'язковий."];

    if (errors.Count > 0)
        return Results.ValidationProblem(errors);

    // Після перевірки явно отримуємо ненульові значення.
    var userName = input.UserName!.Trim();
    var email = input.Email!.Trim();
    var displayName = input.DisplayName!.Trim();
    var password = input.Password!;

    // Не дозволяємо полям стати порожніми після Trim().
    if (string.IsNullOrWhiteSpace(userName) ||
        string.IsNullOrWhiteSpace(email) ||
        string.IsNullOrWhiteSpace(displayName))
    {
        return Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
                ["input"] = ["Поля не можуть бути порожніми."]
            });
    }

    var user = new ApplicationUser
    {
        Id = Guid.NewGuid(),
        UserName = userName,
        Email = email,
        DisplayName = displayName
    };

    var result = await users.CreateAsync(user, password);

    if (!result.Succeeded)
    {
        var codes = result.Errors.Select(e => e.Code).ToArray();

        if (codes.Contains("DuplicateUserName") ||
            codes.Contains("DuplicateEmail"))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Обліковий запис уже існує",
                detail: "Користувача з таким іменем або email вже зареєстровано.");
        }

        return Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
                ["password"] =
                [
                    "Пароль не відповідає вимогам Identity."
                ]
            });
    }

    var role = await users.AddToRoleAsync(
        user,
        DbSeeder.ReporterRole);

    if (!role.Succeeded)
        throw new InvalidOperationException(
            "Default role assignment failed.");

    return Results.Created(
        "/api/me",
        new RegisteredUserResponse(
            user.Id,
            user.UserName!,
            user.DisplayName));
});
               app.MapPost("/api/auth/login", async (
            LoginInput input,
            SignInManager<ApplicationUser> signIn,
            ILogger<Program> logger,
            HttpContext httpContext) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                    "login", "rejected-input", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                "login", result.Succeeded ? "success" : "failure", httpContext.TraceIdentifier);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting("login");
         app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        }).RequireAuthorization();
               app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
        private static IResult GetCurrentUser(HttpContext httpContext)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

        return Results.Ok(new { UserId = verifiedUserId, UserName = userName, Role = role });
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);

public sealed record RegisteredUserResponse(Guid Id, string UserName, string DisplayName);