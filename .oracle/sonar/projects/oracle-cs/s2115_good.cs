using Microsoft.EntityFrameworkCore;

public class S2115Good
{
    protected void OnConfiguring(DbContextOptionsBuilder optionsBuilder, string password)
    {
        optionsBuilder.UseSqlServer(
            "Server=myServerAddress;Database=myDataBase;Integrated Security=true;");
    }
}
