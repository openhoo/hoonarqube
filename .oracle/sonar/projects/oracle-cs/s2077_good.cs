public class Sample
{
    public void Count(System.Data.SqlClient.SqlCommand command)
    {
        var sql = "SELECT COUNT(*) FROM users";
        command.ExecuteScalar(sql);
    }
}
