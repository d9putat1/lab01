using System.Net;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(LoggedInUsersFixture users)
    : IClassFixture<LoggedInUsersFixture>
{
    [Fact]
    public async Task Search_ReturnsJson()
    {
        using var response = await users.Alice.GetAsync("/api/incidents/search?q=навчальн");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}