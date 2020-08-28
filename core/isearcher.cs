using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace APSoft_Web_Scanner_v2
{
    public interface isearcher : IDisposable
    {
        void Dispose();

        core helper { get; set; }
        string name { get; set; }

        List<Task> initialize(int threads, List<string> source, CancellationToken stoptoken);

        List<string> getsearch(string dork);

        void saver(ref List<string> sourcefiles, bool finished = false);
    }
}