public class Parser
{
    public System.Data.DataTable CreateTable()
    {
        var table = new System.Data.DataTable("Customers");
        table.Columns.Add("ID", typeof(int));
        return table;
    }
}
