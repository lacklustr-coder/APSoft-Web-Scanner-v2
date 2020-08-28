using Leaf.xNet;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace APSoft_Web_Scanner_v2
{
    public class sqlscanner : iscanner
    {
        public object scannerlock { get; set; }
        public string name { get; set; }
        public core helper { get; set; }

        public sqlscanner()
        {
            name = "SQL";
            scannerlock = new object();
        }

        public List<Task> initialize(int threads, bool realtimeupdate, CancellationToken stoptoken)
        {
            List<Task> res = new List<Task>();
            if (realtimeupdate)
            {
                for (int i = 0; i < threads; i++)
                {
                    res.Add(Task.Run(() =>
                    {
                        List<string> me = new List<string>();
                        List<string> mebad = new List<string>();

                        while (true)
                        {
                            if (!helper.scannerbothisactive && helper.urlslist.Count <= 0)
                            {
                                break;
                            }
                            if (stoptoken.IsCancellationRequested)
                            {
                                break;
                            }
                            if (helper.urlslist.Count > 0)
                            {
                                string url = "";
                                lock (scannerlock)
                                {
                                    url = helper.urlslist[0];
                                    helper.urlslist.RemoveAt(0);
                                }
                                if (helper.continueifwafdetected)
                                {
                                    if (helper.scannerwafdetection(url))
                                    {
                                        Interlocked.Increment(ref helper.stats.scannerscanned);
                                        Interlocked.Increment(ref helper.stats.scannerwafdetected);
                                        mebad.Add(url);
                                        saver(ref mebad, false);
                                        continue;
                                    }
                                }
                                string foundpayload = "";
                                bool vulnerable = isvulnerable(url, ref foundpayload);
                                Interlocked.Increment(ref helper.stats.scannerscanned);
                                if (vulnerable)
                                {
                                    bool haswaf = helper.scannerwafdetection(url);
                                    if (haswaf)
                                    {
                                        Interlocked.Increment(ref helper.stats.scannerwafdetected);
                                    }
                                    helper.main.listView2.Items.Add(new ListViewItem(new string[]
                                    {
                                    url.ToString(),
                                    name,
                                    haswaf.ToString(),
                                    foundpayload
                                    }));
                                    Interlocked.Increment(ref helper.stats.sqlvulnerable);
                                    me.Add(url);
                                    saver(ref me, false);
                                }
                            }
                            else
                            {
                                Thread.Sleep(150);
                                continue;
                            }
                        }
                        saver(ref mebad, true);
                        saver(ref me, true);
                    }));
                }
            }
            else
            {
                List<List<string>> chunkedurls = new List<List<string>>();
                for (int i = 0; i < threads; i++)
                {
                    chunkedurls.Add(new List<string>());
                }
                int currentindex = 0;
                for (int i = 0; i < helper.urlslist.Count; i++)
                {
                    if (currentindex >= threads)
                    {
                        currentindex = 0;
                    }
                    chunkedurls[currentindex].Add(helper.urlslist[i]);
                    currentindex++;
                }
                foreach (var item in chunkedurls)
                {
                    res.Add(Task.Run(() =>
                    {
                        List<string> me = new List<string>();
                        List<string> mebad = new List<string>();
                        foreach (string url in item)
                        {
                            if (stoptoken.IsCancellationRequested)
                            {
                                break;
                            }
                            if (helper.continueifwafdetected)
                            {
                                if (helper.scannerwafdetection(url))
                                {
                                    Interlocked.Increment(ref helper.stats.scannerscanned);
                                    Interlocked.Increment(ref helper.stats.scannerwafdetected);
                                    mebad.Add(url);
                                    saver(ref mebad, false);
                                    continue;
                                }
                            }
                            string foundpayload = "";
                            bool vulnerable = isvulnerable(url, ref foundpayload);
                            Interlocked.Increment(ref helper.stats.scannerscanned);
                            if (vulnerable)
                            {
                                bool haswaf = helper.scannerwafdetection(url);
                                if (haswaf)
                                {
                                    Interlocked.Increment(ref helper.stats.scannerwafdetected);
                                }
                                helper.main.listView2.Items.Add(new ListViewItem(new string[]
                                {
                                    url.ToString(),
                                    name,
                                    haswaf.ToString(),
                                    foundpayload
                                }));
                                Interlocked.Increment(ref helper.stats.sqlvulnerable);
                                me.Add(url);
                                saver(ref me, false);
                            }
                        }
                        saver(ref mebad, true);
                        saver(ref me, true);
                    }));
                }
            }
            return res;
        }

        public bool isvulnerable(string url, ref string payload)
        {
            bool res = false;
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
                if (!helper.urlfilter(url)) goto exit;
                helper.setproxy(ref req);
                string basesource = req.Get(url, null).ToString();
                for (int i = 0; i < helper.paylodasinstance.sql.Count; i++)
                {
                    if (i >= helper.scannermaxpayloadchecking)
                    {
                        continue;
                    }
                    string currentpayload = helper.paylodasinstance.sql[i];
                    List<string> generatedurls = helper.injectpayload(url, currentpayload, false);
                    for (int x = 0; x < generatedurls.Count; x++)
                    {
                        req.ClearAllHeaders();
                        req.Cookies = req.Response.Cookies;
                        string currentgeneratedurl = generatedurls[x];
                        string source = req.Get(currentgeneratedurl, null).ToString().ToLower();
                        if (sourcevalidator(basesource, source))
                        {
                            res = true;
                            payload = currentpayload;
                            goto exit;
                        }
                    }
                }
            }
            catch
            {
                Interlocked.Increment(ref helper.stats.scannererror);
                goto exit;
            }

            exit:
            return res;
        }

        public bool sourcevalidator(string basesource, string source)
        {
            bool res = false;
            for (int i = 0; i < helper.payloadserrorsinstance.sql.Count; i++)
            {
                string currenterror = helper.payloadserrorsinstance.sql[i];
                if (currenterror.Contains("REIT"))
                {
                    currenterror = currenterror.Replace("REIT|", "");
                    Regex rxerror = new Regex(currenterror, RegexOptions.IgnoreCase);
                    if (rxerror.IsMatch(source) && !rxerror.IsMatch(basesource))
                    {
                        res = true;
                        goto exit;
                    }
                }
                else
                {
                    currenterror = currenterror.ToLower();
                    if (basesource.IndexOf(currenterror) < 0 && source.IndexOf(currenterror) >= 0)
                    {
                        res = true;
                        goto exit;
                    }
                }
            }
            exit:
            return res;
        }

        public void saver(ref List<string> sourcefiles, bool finished = false, bool itsbad = false)
        {
            try
            {
                if (finished)
                {
                    if (sourcefiles.Count > 0)
                    {
                        string filepath = helper.logpath + "\\" + $"scanner [{name}] - vulnerable.txt";
                        if (itsbad)
                        {
                            filepath = helper.logpath + "\\" + $"scanner [{name}] - unvulnerable.txt";
                        }
                        using (StreamWriter st = File.AppendText(filepath))
                        {
                            foreach (var item in sourcefiles)
                            {
                                st.WriteLine(item);
                            }
                        }
                    }
                    sourcefiles = new List<string>();
                }
                else
                {
                    lock (scannerlock)
                    {
                        if (sourcefiles.Count > 0)
                        {
                            string filepath = helper.logpath + "\\" + $"scanner [{name}] - vulnerable.txt";
                            if (itsbad)
                            {
                                filepath = helper.logpath + "\\" + $"scanner [{name}] - unvulnerable.txt";
                            }
                            using (StreamWriter st = File.AppendText(filepath))
                            {
                                foreach (var item in sourcefiles)
                                {
                                    st.WriteLine(item);
                                }
                            }
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