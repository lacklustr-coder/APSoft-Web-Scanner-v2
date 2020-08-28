using Leaf.xNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace APSoft_Web_Scanner_v2
{
    public class googlesearcher : isearcher, IDisposable
    {
        public core helper { get; set; }
        public string name { get; set; }
        public object searcherlock { get; set; }

        public void Dispose()
        {
            GC.Collect();
            GC.SuppressFinalize(this);
        }

        public googlesearcher()
        {
            name = "Google";
            searcherlock = new object();
        }

        public List<Task> initialize(int threads, List<string> source, CancellationToken stoptoken)
        {
            List<Task> res = new List<Task>();
            List<List<string>> chunkeddorkslist = new List<List<string>>();
            for (int i = 0; i < threads; i++)
            {
                chunkeddorkslist.Add(new List<string>());
            }
            int currentlistindex = 0;
            for (int i = 0; i < source.Count; i++)
            {
                if (currentlistindex >= chunkeddorkslist.Count)
                {
                    currentlistindex = 0;
                }
                chunkeddorkslist[currentlistindex].Add(source[i]);
                currentlistindex++;
            }
            foreach (var func in chunkeddorkslist)
            {
                res.Add(Task.Run(() =>
               {
                   List<string> me = new List<string>();
                   foreach (var item in func)
                   {
                       if (stoptoken.IsCancellationRequested)
                       {
                           break;
                       }
                       var itemres = getsearch(item);
                       if (itemres.Count > 0)
                       {
                           me.AddRange(itemres);
                           saver(ref me);
                       }
                   }
                   saver(ref me, true);
               }));
            }
            return res;
        }

        public List<string> getsearch(string dork)
        {
            List<string> res = new List<string>();
            try
            {
                HttpRequest req = new HttpRequest()
                {
                    IgnoreProtocolErrors = true,
                    IgnoreInvalidCookie = true,
                    KeepAlive = true,
                    ConnectTimeout = helper.connectiontimeout * 1000,
                    ReadWriteTimeout = (helper.connectiontimeout - 2) * 1000,
                    Cookies = new CookieStorage(false),
                    UserAgent = helper.getuseragent(),
                    AllowAutoRedirect = true
                };
                helper.setproxy(ref req);
                req.Get("https://www.google.com/ncr", null);
                string url = $"https://www.google.com/search?q={dork}&num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search&start=0";
                again:
                req.ClearAllHeaders();
                req.Cookies = req.Response.Cookies;
                string source = req.Get(url).ToString();
                string nextpageurl = Regex.Match(source, @"href=""(\S{1,1000})"" aria-label=""Next page""").Groups[1].Value.ToString();
                source = WebUtility.UrlDecode(source);
                if (Regex.IsMatch(source, "Please click <a href=\"(.*?)\">"))
                {
                    url = "https://www.google.com" + Regex.Match(source, "Please click <a href=\"(.*?)\">").Groups[1].Value.ToString();
                    goto again;
                }
                List<Match> urls = Regex.Matches(source, @"<a href=""/url[?]q=(\S{1,100})[&amp]")
                    .Cast<Match>()
                    .ToList();
                urls.AddRange(Regex.Matches(source, @"<a href=""([Hh][Tt][Tt][Pp][Ss]\S{1,1000})""")
                    .Cast<Match>()
                    .ToList());
                for (int i = 0; i < urls.Count; i++)
                {
                    string item = urls[i].Groups[1].Value.ToString();
                    item = WebUtility.UrlDecode(item);
                    if (Regex.IsMatch(item, @"&amp;a=[a-z-A-Z-0-9-\/-:-$-@-&-^-_-]{1,10000}"))
                    {
                        item = Regex.Match(item, @"&amp;a=[a-z-A-Z-0-9-\/-:-$-@-&-^-_-]{1,10000}").Groups[1].Value.ToString();
                    }
                    item = Regex.Replace(item, @"&amp\S{1,10000}", "");
                    if (helper.urlfilter(item) && res.Contains(item))
                    {
                        res.Add(item);
                        Interlocked.Increment(ref helper.stats.google);
                    }
                }
                if (nextpageurl.Length >= 5)
                {
                    url = "https://www.google.com" + nextpageurl;
                    goto again;
                }
            }
            catch
            {
                Interlocked.Increment(ref helper.stats.searchererror);
            }

            return res;
        }

        public void saver(ref List<string> sourcefiles, bool finished = false)
        {
            try
            {
                if (finished)
                {
                    if (sourcefiles.Count > 0)
                    {
                        using (StreamWriter st = File.AppendText(name + ".txt"))
                        {
                            foreach (var item in sourcefiles)
                            {
                                st.WriteLine(item);
                            }
                        }
                    }

                    again:
                    try
                    {
                        helper.urlslist.AddRange(sourcefiles);
                    }
                    catch
                    {
                        Thread.Sleep(100);
                        goto again;
                    }
                    sourcefiles = new List<string>();
                }
                else
                {
                    lock (searcherlock)
                    {
                        if (sourcefiles.Count > 0)
                        {
                            string filepath = helper.logpath + "\\" + $"searcher [{name}].txt";
                            using (StreamWriter st = File.AppendText(filepath))
                            {
                                foreach (var item in sourcefiles)
                                {
                                    st.WriteLine(item);
                                }
                            }
                        }
                        again:
                        try
                        {
                            helper.urlslist.AddRange(sourcefiles);
                        }
                        catch
                        {
                            Thread.Sleep(100);
                            goto again;
                        }
                        sourcefiles = new List<string>();
                    }
                }
            }
            catch
            {
                Thread.Sleep(150);
                saver(ref sourcefiles, finished);
            }
        }
    }
}