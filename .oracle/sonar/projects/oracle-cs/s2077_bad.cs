public class Sample
{
    public void Query(System.Data.SqlClient.SqlCommand command, string user)
    {
        var sql = "SELECT * FROM users WHERE name = '" + user + "'";
        command.ExecuteReader(sql);
    }
}
