namespace SecureLab.Api.Tests;

// Один login на користувача на тестовий клас (ліміт login — 10/хв на host).
// Кожен клієнт має власне сховище cookie: «один користувач — один клієнт».
public sealed class LoggedInUsersFixture : IAsyncLifetime
{
    public SecureLabApiFactory Factory { get; } = new();

    public HttpClient Alice { get; private set; } = null!;
    public HttpClient Bob { get; private set; } = null!;
    public HttpClient Morgan { get; private set; } = null!;
    public HttpClient Admin { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

        Alice = await Factory.LoginAsync("alice", password);
        Bob = await Factory.LoginAsync("bob", password);
        Morgan = await Factory.LoginAsync("morgan", password);
        Admin = await Factory.LoginAsync("admin", password);
    }

    public async Task DisposeAsync()
    {
        Alice.Dispose();
        Bob.Dispose();
        Morgan.Dispose();
        Admin.Dispose();
        await Factory.DisposeAsync();
    }
}