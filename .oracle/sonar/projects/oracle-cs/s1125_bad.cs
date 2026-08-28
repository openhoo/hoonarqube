public class Sample
{
    public int Gate(bool flag, bool gate)
    {
        int score = 0;
        if (flag == true)
        {
            score += 1;
        }

        if (true == gate)
        {
            score += 2;
        }

        return score;
    }
}
