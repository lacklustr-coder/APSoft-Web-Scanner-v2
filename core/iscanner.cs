using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace APSoft_Web_Scanner_v2
{
    public interface iscanner
    {
        core helper { get; set; }
        string name { get; set; }

        List<Task> initialize(int threads, bool realtimeupdate, CancellationToken stoptoken);

        bool isvulnerable(string url, ref string payload);

        void saver(ref List<string> sourcefiles, bool finished = false, bool itsbad = false);

        bool sourcevalidator(string basesource, string source);
    }
}