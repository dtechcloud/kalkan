using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddHttpClient<VulnApp.Controllers.StoreController>();
builder.Services.AddSingleton<IMongoDatabase>(_ =>
    new MongoClient(builder.Configuration["Mongo:Url"]).GetDatabase("vulnapp"));

builder.Services.AddCors(options =>
{
    options.AddPolicy("partner", policy =>
        policy.SetIsOriginAllowed(origin => true)
            .AllowAnyHeader()
            .AllowCredentials());

    options.AddPolicy("store", policy =>
        policy.WithOrigins("https://shop.vulnapp.internal")
            .AllowAnyHeader()
            .AllowCredentials());
});

builder.Services.AddAuthentication()
    .AddJwtBearer("partner", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            RequireSignedTokens = false,
            SignatureValidator = (token, parameters) => new JsonWebToken(token),
        };
    })
    .AddJwtBearer("store", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "https://login.vulnapp.internal",
            ValidAudience = "store",
            RequireSignedTokens = true,
            IssuerSigningKey = new SymmetricSecurityKey(Convert.FromHexString(builder.Configuration["Jwt:Key"] ?? "")),
        };
    });

var app = builder.Build();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
