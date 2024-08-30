// <copyright file="Program.cs" company="Beniamin Jitca">
// Copyright (c) Beniamin Jitca. All rights reserved.
// </copyright>

// The configurations for the Core Web API.
using BlazorShop.WebApi.Services;
using FluentValidation;

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.File(builder.Configuration["Serilog:Json:Path"], LogEventLevel.Warning));

    var allowedOrigins = builder.Configuration["AllowedOrigins"];
    var corsPolicy = "EnableCORS";

    builder.Services.AddCors(options =>
    {
        options.AddPolicy(corsPolicy, builder =>
        {
            builder.WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });

    // Inject Architecture Layers
    builder.Services.AddApplicationLayer();
    builder.Services.AddInfrastructureLayer(builder.Configuration);

    builder.Services.AddHttpContextAccessor();
    builder.Services.AddFluentValidationAutoValidation();
    builder.Services.AddValidatorsFromAssemblyContaining<ApiExceptionFilterAttribute>();

    builder.Services.AddControllers(options =>
        options.Filters.Add<ApiExceptionFilterAttribute>());

    // .AddFluentValidation(x => x.AutomaticValidationEnabled = false);
    builder.Services.AddFluentValidationAutoValidation().AddFluentValidationClientsideAdapters();

    // Add JWT TOKEN Settings
    builder.Services.AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
        .AddJwtBearer(options =>
        {
            options.Audience = builder.Configuration["JwtToken:Audience"];
            options.RequireHttpsMetadata = true;
            options.SaveToken = true;

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.FromSeconds(1),
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.Unicode.GetBytes(builder.Configuration["JwtToken:SecretKey"])),
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidAudience = builder.Configuration["JwtToken:Audience"],
                ValidIssuer = builder.Configuration["JwtToken:Issuer"],
            };
        });

    builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();

    builder.Services.AddHealthChecks();
    builder.Services.AddAuthorization();
    builder.Services.AddControllers();

    // Stripe Configuration - Secret Key
    StripeConfiguration.ApiKey = builder.Configuration["StripeSettings:SecretKey"];

    var app = builder.Build();

    using (var scope = app.Services.CreateScope())
    {
        try
        {
            var runSeeding = Convert.ToBoolean(builder.Configuration["RunSeedingOnStartup"]);

            if (runSeeding)
            {
                var services = scope.ServiceProvider;
                var context = services.GetRequiredService<ApplicationDbContext>();
                if (context.Database.IsSqlServer())
                {
                    context.Database.Migrate();
                }

                var userManager = services.GetRequiredService<UserManager<User>>();
                var roleManager = services.GetRequiredService<RoleManager<Role>>();

                var rolesSeed = new RolesSeedModel
                {
                    AdminRoleName = builder.Configuration["RolesSeedModel:AdminRoleName"],
                    AdminRoleNormalizedName = builder.Configuration["RolesSeedModel:AdminRoleNormalizedName"],
                    UserRoleName = builder.Configuration["RolesSeedModel:UserRoleName"],
                    UserRoleNormalizedName = builder.Configuration["RolesSeedModel:UserRoleNormalizedName"],
                    DefaultRoleName = builder.Configuration["RolesSeedModel:DefaultRoleName"],
                    DefaultRoleNormalizedName = builder.Configuration["RolesSeedModel:DefaultRoleNormalizedName"],
                };
                var adminSeed = new AdminSeedModel
                {
                    FirstName = builder.Configuration["AdminSeedModel:FirstName"],
                    LastName = builder.Configuration["AdminSeedModel:LastName"],
                    Email = builder.Configuration["AdminSeedModel:Email"],
                    Password = builder.Configuration["AdminSeedModel:Password"],
                    RoleName = builder.Configuration["AdminSeedModel:RoleName"],
                };

                await ApplicationDbContextSeed.SeedRolesAsync(roleManager, rolesSeed);
                await ApplicationDbContextSeed.SeedAdminUserAsync(userManager, roleManager, adminSeed);
                await ApplicationDbContextSeed.SeedClothesDataAsync(context);
                await ApplicationDbContextSeed.SeedMusicsDataAsync(context);
                await ApplicationDbContextSeed.SeedSubscriptionsDataAsync(context);
                await ApplicationDbContextSeed.SeedTodosDataAsync(context);
            }
        }
        catch (Exception ex)
        {
            Log.Logger.Error(ex, "An error occurred while migrating or seeding the database.");
            throw;
        }
    }

    if (app.Environment.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
        app.UseMigrationsEndPoint();
    }
    else
    {
        app.UseExceptionHandler("/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseRouting();

    // this must be places after 'useRouting' and before 'UseAuthorization'
    app.UseCors(corsPolicy);

    app.UseMiddleware<JwtTokenMiddleware>();

    app.UseSerilogRequestLogging();

    app.UseAuthentication();
    app.UseAuthorization();

    // Security Headers for Website
    app.Use(async (context, next) =>
    {
        context.Response.Headers.TryAdd("X-Frame-Options", "SAMEORIGIN");
        context.Response.Headers.TryAdd("Access-Control-Allow-Origin", allowedOrigins);
        context.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
        context.Response.Headers.TryAdd("Referrer-Policy", "same-origin");
        context.Response.Headers.TryAdd("Permissions-Policy", "geolocation=(), camera=()");
        context.Response.Headers.TryAdd(builder.Configuration["ContentPolicy"], "default-src "
            + "self  "
            + "https://maxcdn.bootstrapcdn.com  "
            + "https://login.microsoftonline.com "
            + "https://sshmantest.azurewebsites.net "
            + "https://code.jquery.com https://dc.services.visualstudio.com "
            + " 'unsafe-inline' 'unsafe-eval'");
        context.Response.Headers.TryAdd("SameSite", "Strict");
        context.Response.Headers.TryAdd("X-XSS-Protection", "1; mode=block");
        await next();
    });

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller}/{action=Index}/{id?}");

    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}
