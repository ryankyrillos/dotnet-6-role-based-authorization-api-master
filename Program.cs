using BCryptNet = BCrypt.Net.BCrypt;
using System.Text.Json.Serialization;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Services;

var builder = WebApplication.CreateBuilder(args);

// add services to DI container
{
    var services = builder.Services;
    var env = builder.Environment;

    services.AddDbContext<DataContext>();
    services.AddCors();
    services.AddControllers().AddJsonOptions(x =>
    {
        // serialize enums as strings in api responses (e.g. Role)
        x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        
        // ignore omitted parameters on models to enable optional params (e.g. User update)
        x.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });
    services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    // configure strongly typed settings object
    services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

    // configure DI for application services
    services.AddScoped<IJwtUtils, JwtUtils>();
    services.AddScoped<IUserService, UserService>();
}

var app = builder.Build();

// configure HTTP request pipeline
{
    // global cors policy
    app.UseCors(x => x
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader());

    // global error handler
    app.UseMiddleware<ErrorHandlerMiddleware>();

    // custom jwt auth middleware
    app.UseMiddleware<JwtMiddleware>();

    app.MapControllers();
}

// create hardcoded test users in db on startup
{
    var testUsers = new List<User>
    {
        new User { Id = 1,Title = "Mr",FirstName = "Admin", LastName = "User", Email = "admin@gmail.com", PasswordHash = BCryptNet.HashPassword("admin"), Role = Role.Admin },
        new User { Id = 2,Title = "Mr", FirstName = "Normal", LastName = "User", Email = "user@gmail.com", PasswordHash = BCryptNet.HashPassword("user"), Role = Role.User },
        new User { Id = 3,Title = "Mr", FirstName = "Super", LastName = "User", Email = "GOD@gmail.com", PasswordHash = BCryptNet.HashPassword("GOD"), Role = Role.User }
    };

    using var scope = app.Services.CreateScope();
    var dataContext = scope.ServiceProvider.GetRequiredService<DataContext>();
    dataContext.Users.AddRange(testUsers);
    dataContext.SaveChanges();
}

app.Run("http://localhost:4000");