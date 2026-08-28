using System.Security.Cryptography;

class Shuffler
{
    int Roll()
    {
        return RandomNumberGenerator.GetInt32(6);
    }
}
