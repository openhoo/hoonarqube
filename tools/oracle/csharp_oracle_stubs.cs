// Generated C# oracle compilation support. Excluded from SonarQube analysis.
#nullable enable

global using static OracleStubs;

public static class OracleStubs
{
    public static readonly OracleItems items = new();
    public static readonly OracleItems otherItems = new();
    public static readonly OracleItems set = new();
    public static readonly OracleItems sample = new();
    public static readonly OracleItems queue = new();
    public static readonly OracleOptions options = new();
    public static readonly Microsoft.Extensions.Logging.ILogger _logger = null!;
    public static readonly System.IO.StreamWriter writer = new(System.IO.Stream.Null);
    public static readonly string name = "oracle";
    public static readonly int number = 1;

    public static bool IsReady { get; set; }
    public static bool HasItems { get; set; }
    public static bool ShouldRetry { get; set; }
    public static bool CanFail { get; set; }
    public static bool ValidateAntiforgeryToken { get; set; }
    public static int Width { get; set; }
    public static int Height { get; set; }
    public static OracleModelState ModelState { get; set; } = new();

    public static void Load() { }
    public static void Save() { }
    public static void Archive() { }
    public static void Purge() { }
    public static void Prepare() { }
    public static void Dispatch() { }
    public static void Hold() { }
    public static void Open() { }
    public static void Close() { }
    public static void Apply() { }
    public static void Drain() { }
    public static void Greet() { }
    public static string BuildCaption() => "oracle";
    public static void Log<T>(T value) { }
    public static int CoInitializeSecurity(params object?[] values) => 0;
    public static int CoSetProxyBlanket(params object?[] values) => 0;
    public static string HashPassword(string password, string salt) => password + salt;
    public static string PBKDF2(string password, string salt, int iterations, int size) => password;
    public static System.Collections.Generic.IEnumerable<int> LoadIds() => [];
}

public sealed class OracleItems
{
    public OracleItems Items => this;
    public void AddRange(OracleItems other) { }
    public void Union(OracleItems other) { }
    public void Except(OracleItems other) { }
}

public sealed class OracleOptions
{
    public OracleItems Items { get; } = new();
}

public sealed class OracleModelState
{
    public bool IsValid { get; set; }
}

public class ApplicationExceptionWrapper : System.Exception { }
public readonly struct CustomId
{
    public static explicit operator CustomId(int value) => new();
}
public sealed class ResultEventArgs : System.EventArgs { }
public sealed class StatusEventArgs : System.EventArgs { }
public interface IUserService { }
public interface IAuditService { }
public interface IReportService { }
public class OracleLogger { }
public class Window
{
    public string? Title { get; set; }
    public string? ToolTip { get; set; }
    public string? Header { get; set; }
    public int Width { get; set; }
}

public sealed class ConstructorArgumentAttribute : System.Attribute
{
    public ConstructorArgumentAttribute(string name) { }
}

[System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class FactAttribute : System.Attribute { }
[System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class TestClassAttribute : System.Attribute { }
[System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class TestMethodAttribute : System.Attribute { }
[System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class TestFixtureAttribute : System.Attribute { }
[System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class TestAttribute : System.Attribute { }
[System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class IgnoreAttribute : System.Attribute
{
    public IgnoreAttribute() { }
    public IgnoreAttribute(string reason) { }
}
[System.AttributeUsage(System.AttributeTargets.Method, AllowMultiple = true)]
public sealed class ExpectedExceptionAttribute : System.Attribute
{
    public ExpectedExceptionAttribute(System.Type exceptionType) { }
}

public static class Assert
{
    public static void IsTrue(bool value) { }
    public static void IsFalse(bool value) { }
    public static void IsFalse(bool value, string message) { }
    public static void False(bool value) { }
    public static void Equal<T>(T expected, T actual) { }
    public static void AreEqual<T>(T expected, T actual) { }
    public static void AreNotEqual<T>(T notExpected, T actual) { }
    public static void AreSame<T>(T expected, T actual) { }
    public static void That<T>(T actual) { }
    public static void That<T>(T actual, object? constraint) { }
}

public static class CollectionAssert
{
    public static void AreNotEqual<T>(T notExpected, object? actual) { }
}

public static class Is
{
    public static object True { get; } = new();
    public static NotConstraint Not { get; } = new();

    public sealed class NotConstraint
    {
        public object Empty { get; } = new();
    }
}

public static class Check
{
    public static void That(bool value) { }
}

public static class OracleAssertionExtensions
{
    public static OracleFluentAssertion Should(this int value) => new();
}

public sealed class OracleFluentAssertion
{
    public void Be(int expected) { }
}

public sealed class FunctionNameAttribute : System.Attribute
{
    public FunctionNameAttribute(string name) { }
}

public sealed class SupplyParameterFromQueryAttribute : System.Attribute { }
public sealed class ParameterAttribute : System.Attribute { }

public static class XmlConfigurator
{
    public static void Configure(System.IO.FileInfo file) { }
}

public static class LogManager
{
    public static object Configuration { get; } = new();
}

namespace System
{
    public sealed class SuppressMessageAttribute : Attribute
    {
        public SuppressMessageAttribute(string category, string checkId) { }
        public string? Justification { get; set; }
    }
}

namespace System.Configuration
{
    public static class ConfigurationManager
    {
        public static System.Collections.Generic.Dictionary<string, string> AppSettings { get; } = new();
    }
}

namespace System.Data.SqlClient
{
    public sealed class SqlCommand
    {
        public SqlCommand() { }
        public SqlCommand(string query) { }
        public object ExecuteReader(string query) => new();
        public object? ExecuteScalar() => null;
        public object? ExecuteScalar(string query) => null;
    }

    public sealed class SqlConnection : System.IDisposable
    {
        public void Dispose() { }
    }
}

namespace System.Web
{
    public sealed class HttpContext
    {
        public HttpResponse Response { get; } = new();
    }

    public sealed class HttpResponseHeaders
    {
        public string ContentSecurityPolicy { get; set; } = "";
    }

    public sealed class HttpCookie
    {
        public HttpCookie(string name, string value) { }
        public bool HttpOnly { get; set; }
        public bool Secure { get; set; }
    }

    public sealed class HttpCookieCollection
    {
        public void Add(HttpCookie cookie) { }
    }

    public sealed class HttpResponse
    {
        public HttpCookieCollection Cookies { get; } = new();
        public HttpResponseHeaders Headers { get; } = new();
    }
}

namespace System.Windows.Forms
{
    public class Form { }
    public static class Application
    {
        public static void Run(Form form) { }
        public static void EnableVisualStyles() { }
        public static void Exit() { }
    }
}

namespace System.ServiceModel
{
    public sealed class ServiceContractAttribute : System.Attribute { }
    public sealed class OperationContractAttribute : System.Attribute
    {
        public bool IsOneWay { get; set; }
        public bool IsTerminating { get; set; }
    }
}

namespace System.ComponentModel.Composition
{
    public enum CreationPolicy { Any, Shared, NonShared }
    public sealed class ExportAttribute : System.Attribute
    {
        public ExportAttribute() { }
        public ExportAttribute(string contractName) { }
        public ExportAttribute(System.Type contractType) { }
    }
    public sealed class PartCreationPolicyAttribute : System.Attribute
    {
        public PartCreationPolicyAttribute(CreationPolicy policy) { }
    }
    public sealed class SharedAttribute : System.Attribute { }
}

namespace System.ComponentModel.Composition.Hosting
{
    public sealed class CompositionContainer
    {
        public T GetExportedValue<T>() where T : new() => new();
    }
}

namespace System.DirectoryServices
{
    public enum AuthenticationTypes
    {
        None = 0,
        Secure = 1,
        Anonymous = 16,
    }
    public sealed class DirectoryEntry
    {
        public DirectoryEntry(string path) => Path = path;
        public DirectoryEntry(string path, string? user, string? password) => Path = path;
        public DirectoryEntry(string path, string? user, string? password, AuthenticationTypes authenticationType) => Path = path;
        public string Path { get; }
    }
}

namespace System.IdentityModel.Tokens.Jwt
{
    public sealed class JwtSecurityToken
    {
        public JwtSecurityToken(string? issuer = null, string? audience = null,
            Microsoft.IdentityModel.Tokens.SigningCredentials? signingCredentials = null) { }
    }
}

namespace Microsoft.IdentityModel.Tokens
{
    public class SecurityKey { }
    public sealed class SymmetricSecurityKey : SecurityKey
    {
        public SymmetricSecurityKey(byte[] key) { }
    }
    public sealed class RsaSecurityKey : SecurityKey
    {
        public RsaSecurityKey(System.Security.Cryptography.RSA key) { }
    }
    public sealed class SigningCredentials
    {
        public SigningCredentials(SecurityKey key, string algorithm) { }
    }
    public sealed class TokenValidationParameters
    {
        public string[]? ValidAlgorithms { get; set; }
    }
}

namespace Microsoft.EntityFrameworkCore
{
    public sealed class DbContextOptionsBuilder { }
    public static class SqlServerDbContextOptionsExtensions
    {
        public static DbContextOptionsBuilder UseSqlServer(
            this DbContextOptionsBuilder builder,
            string connectionString) => builder;
    }
}

namespace Org.BouncyCastle.Security
{
    public sealed class SecureRandom
    {
        public SecureRandom() { }
        public static SecureRandom GetInstance(string algorithm, bool autoSeed) => new();
        public void NextBytes(byte[] output) { }
    }
}

namespace TimeZoneConverter
{
    public static class TZConvert
    {
        public static string IanaToWindows(string timeZone) => timeZone;
    }
}

namespace JWT
{
    public interface IJwtDecoder
    {
        string Decode(string token, string secret, bool verify);
    }

    public sealed class JwtBuilder
    {
        public JwtBuilder WithSecret(string secret) => this;
        public JwtBuilder MustVerifySignature() => this;
        public string Decode(string token) => token;
    }
}

namespace System.Web.Script.Serialization
{
    public class JavaScriptTypeResolver { }
    public sealed class SimpleTypeResolver : JavaScriptTypeResolver { }
    public sealed class JavaScriptSerializer
    {
        public JavaScriptSerializer() { }
        public JavaScriptSerializer(JavaScriptTypeResolver resolver) { }
        public T? Deserialize<T>(string json) => default;
    }
}

namespace System.Security.Permissions
{
    [System.AttributeUsage(System.AttributeTargets.All, AllowMultiple = true)]
    public sealed class FileIOPermissionAttribute : System.Attribute
    {
        public FileIOPermissionAttribute(SecurityAction action) { }
        public bool Unrestricted { get; set; }
    }
}

namespace Newtonsoft.Json
{
    public enum TypeNameHandling { None, Objects, Arrays, Auto }
    public sealed class JsonSerializerSettings
    {
        public TypeNameHandling TypeNameHandling { get; set; }
    }
    public static class JsonConvert
    {
        public static object? DeserializeObject(string json, System.Type type, JsonSerializerSettings settings) => null;
    }
}

namespace Azure.Storage.Queues
{
    public sealed class QueueClient
    {
        public QueueClient(string connectionString) { }
        public string Name { get; } = "queue";
    }
}

namespace Azure.Messaging.ServiceBus
{
    public sealed class ServiceBusClient
    {
        public ServiceBusClient(string connectionString) { }
    }
}
