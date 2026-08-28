using Microsoft.EntityFrameworkCore;

public class S2115Bad
{
    protected void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlServer(
            "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password="); // S2115
    }
}
