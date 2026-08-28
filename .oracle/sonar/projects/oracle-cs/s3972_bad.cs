using System;
using System.IO;

class OrderProcessor
{
    void Process(bool ready)
    {
        if (ready) {
            Dispatch();
        } if (!ready) {
            Hold();
        }
    }
}
