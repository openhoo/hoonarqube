public class Fruit { }
public class Orange : Fruit { }
public class Apple : Fruit { }

public class S3217Bad
{
    public void Inspect(System.Collections.Generic.List<Fruit> basket)
    {
        foreach (Orange orange in basket)
        {
            System.Console.WriteLine(orange);
        }
    }
}
