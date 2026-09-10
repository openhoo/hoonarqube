using System.Data.Common;
public static class SqlAttack { public static void Run(DbCommand command, string input) { command.CommandText = "SELECT * FROM records WHERE name = '" + input + "'"; } }
