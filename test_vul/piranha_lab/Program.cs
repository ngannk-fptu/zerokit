using Microsoft.EntityFrameworkCore;
using Piranha;
using Piranha.AspNetCore.Identity.SQLite;
using Piranha.AttributeBuilder;
using Piranha.Data.EF.SQLite;
using Piranha.Manager.Editor;

var builder = WebApplication.CreateBuilder(args);

builder.AddPiranha(options =>
{
    options.AddRazorRuntimeCompilation = true;
    options.UseCms();
    options.UseManager();

    // Use local file storage - files go into wwwroot/uploads/
    // This is the vulnerable setting for CWE-434 test
    options.UseFileStorage(naming: Piranha.Local.FileStorageNaming.UniqueFileNames);
    options.UseImageSharp();
    options.UseTinyMCE();
    options.UseMemoryCache();

    var connectionString = builder.Configuration.GetConnectionString("piranha");
    options.UseEF<SQLiteDb>(db => db.UseSqlite(connectionString));

    // Seed with a default admin user: admin / password
    options.UseIdentityWithSeed<IdentitySQLiteDb>(db => db.UseSqlite(connectionString));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UsePiranha(options =>
{
    App.Init(options.Api);

    new ContentTypeBuilder(options.Api)
        .AddAssembly(typeof(Program).Assembly)
        .Build()
        .DeleteOrphans();

    EditorConfig.FromFile("editorconfig.json");
    options.UseManager();
    options.UseTinyMCE();
    options.UseIdentity();
});

app.Run();
