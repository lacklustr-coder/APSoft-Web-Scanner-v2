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
    public class yahoosearcher : isearcher, IDisposable
    {
        public void Dispose()
        {
            GC.Collect();
            GC.SuppressFinalize(this);
        }

        public core helper { get; set; }
        public string name { get; set; }
        public object searcherlock { get; set; }

        public yahoosearcher()
        {
            name = "Yahoo";
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
            int currentinheritance = 0;
            int nourl = 0;
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
                again:
                string url = "https://search.yahoo.com/search?p=" + dork + "&b=" + currentinheritance;
                string source = req.Get(url, null).ToString();
                if (!source.Contains("We did not find results"))
                {
                    List<Match> urls = Regex.Matches(source, "a class=\" ac-algo fz-l ac-21th lh-24\" href=\"(.*?)\"")
                 .Cast<Match>()
                 .ToList();
                    urls.AddRange(Regex.Matches(source, @"<a href=""([Hh][Tt][Tt][Pp][Ss]\S{1,1000})""")
                        .Cast<Match>()
                        .ToList());
                    if (urls.Count >= 1)
                    {
                        for (int i = 0; i < urls.Count; i++)
                        {
                            string item = urls[i].Groups[1].Value.ToString();
                            item = WebUtility.UrlDecode(item);
                            if (Regex.IsMatch(item, @"&amp;a=[a-z-A-Z-0-9-\/-:-$-@-&-^-_-]{1,10000}"))
                            {
                                item = Regex.Match(item, @"&amp;a=[a-z-A-Z-0-9-\/-:-$-@-&-^-_-]{1,10000}").Groups[1].Value.ToString();
                            }
                            if (item.Contains("RK") && item.Contains("RU"))
                            {
                                item = Regex.Match(item, "RU=(.*?)/RK").Groups[1].Value.ToString();
                                item = System.Web.HttpUtility.UrlDecode(item);
                            }
                            item = Regex.Replace(item, @"&amp\S{1,10000}", "");
                            if (helper.urlfilter(item) && !res.Contains(item))
                            {
                                res.Add(item);
                                Interlocked.Increment(ref helper.stats.yahoo);
                            }
                        }
                        currentinheritance += urls.Count + 20;
                        if (helper.grabbermaxsearchdepth * 1000 <= currentinheritance)
                        {
                            goto exit;
                        }
                        else
                        {
                            goto again;
                        }
                    }
                    else
                    {
                        nourl++;
                        if (nourl >= 5)
                        {
                            goto exit;
                        }
                        else
                        {
                            currentinheritance += urls.Count + 20;
                            if (helper.grabbermaxsearchdepth * 1000 <= currentinheritance)
                            {
                                goto exit;
                            }
                            else
                            {
                                goto again;
                            }
                        }
                    }
                }
                else
                {
                    Interlocked.Increment(ref helper.stats.searchererror);
                    goto exit;
                }
            }
            catch
            {
                Interlocked.Increment(ref helper.stats.searchererror);
            }
            exit:

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