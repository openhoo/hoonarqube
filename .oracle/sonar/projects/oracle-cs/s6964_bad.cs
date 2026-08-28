using Microsoft.AspNetCore.Mvc;

public class Product
{
    public int Id { get; set; } // S6964
    public string Name { get; set; } = "";
    public int NumberOfItems { get; set; } // S6964
    public decimal Price { get; set; } // S6964
}

[ApiController]
public class ProductsController : ControllerBase
{
    [HttpPost]
    public void Create(Product product)
    {
    }
}
