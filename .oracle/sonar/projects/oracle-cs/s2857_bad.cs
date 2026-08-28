using System.Data.SqlClient;

namespace Oracle.SqlClient;

class S2857Bad
{
    SqlCommand Query()
    {
        string select = "SELECT p.FirstName, p.LastName, p.PhoneNumber" +
            "FROM Person as p" + // S2857
            "WHERE p.Id = @Id"; // S2857
        return new SqlCommand(select);
    }
}
