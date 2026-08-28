using System.Data.SqlClient;

namespace Oracle.SqlClient;

class S2857Good
{
    SqlCommand Query() { return new SqlCommand("SELECT * FROM Users WHERE id = 1"); }

    SqlCommand Count() { return new SqlCommand("SELECT COUNT(id) FROM Orders");
    }
}
