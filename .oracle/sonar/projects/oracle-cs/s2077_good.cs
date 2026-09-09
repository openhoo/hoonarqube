using System.Data.Common;
public static class SqlSafe { public static void Run(DbCommand command) { command.CommandText = "SELECT * FROM records WHERE name = @name"; } }

public sealed class CustomCommand { public string CommandText { get; set; } = ""; }
public static class SqlNearMiss { public static void Run(CustomCommand command, string input) { command.CommandText = "SELECT * FROM records WHERE name = '" + input + "'"; } }
