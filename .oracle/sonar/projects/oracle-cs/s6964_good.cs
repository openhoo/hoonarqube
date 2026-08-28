using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

public class Product
{
    public int? Id { get; set; }
    public string Name { get; set; } = "";
    public required int NumberOfItems { get; set; }
    public decimal? Price { get; set; }
}

[ApiController]
public class ProductsController : ControllerBase
{
    [HttpPost]
    public void Create(Product product)
    {
    }
}
