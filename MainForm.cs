using Microsoft.VisualBasic;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace APSoft_Web_Scanner_v2
{
    public partial class MainForm : Form
    {
        #region property

        private core helper { get; set; }
        private List<Control> settingtabcontrolslist { get; set; }

        #endregion property

        public MainForm()
        {
            InitializeComponent();
            tabControl1.SelectedIndexChanged += TabControl1_SelectedIndexChanged;
            CheckForIllegalCrossThreadCalls = false;
            settingtabcontrolslist = settingtabcontrols(tabPage2);
            if (File.Exists("setting.json"))
            {
                try
                {
                    helper = JsonConvert.DeserializeObject<core>(File.ReadAllText("setting.json"));
                    helper.main = this;
                    loadsetting();
                }
                catch
                {
                    helper = new core();
                    helper.main = this;
                    loadsetting();
                }
            }
            else
            {
                helper = new core();
                helper.main = this;
                loadsetting();
            }
        }

        private void TabControl1_SelectedIndexChanged(object sender, EventArgs e)
        {
            updateguisettingdependmod();
            if (tabControl1.SelectedIndex == 1)
            {
                comboBox1.SelectedIndex = 0;
                if (helper.dorksgeneratedlist.Count > 0)
                {
                    buttonsenable();
                    helper.dorksgeneratedlist.ForEach(func =>
                {
                    checkedListBox5.Items.Add(func, CheckState.Checked);
                });
                    buttonsenable(true);
                }
                helper.paylodasinstance.sql
                    .ForEach(func => listView1.Items.Add(new ListViewItem(new string[] { "SQL", func })));
                helper.paylodasinstance.xss
                    .ForEach(func => listView1.Items.Add(new ListViewItem(new string[] { "XSS", func })));
                helper.paylodasinstance.lfi
                    .ForEach(func => listView1.Items.Add(new ListViewItem(new string[] { "LFI", func })));
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            for (int i = 0; i < checkedListBox5.Items.Count; i++)
            {
                if (checkedListBox5.GetItemCheckState(i) == CheckState.Unchecked)
                {
                    helper.dorksgeneratedlist.Remove(checkedListBox5.Items[i].ToString());
                }
            }
            File.WriteAllText("setting.json", JsonConvert.SerializeObject(helper, Formatting.Indented));
            File.WriteAllText("payloads.json", JsonConvert.SerializeObject(helper.paylodasinstance, Formatting.Indented));
        }

        #region tabpage1 - dorks setting

        private async void button6_Click(object sender, EventArgs e)
        {
            tabPage1.Controls
                .OfType<Button>()
                .ToList()
                .ForEach(func => func.Enabled = false);
            helper.loadlist(ref helper.dorksconfigurationlist, "dorks configurations");
            await Task.Factory.StartNew(() =>
            {
                dorkssettingupdateconfigurations();
            });
            tabPage1.Controls
                .OfType<Button>()
                .ToList()
                .ForEach(func => func.Enabled = true);
        }

        private void dorkssettingupdateconfigurations()
        {
            checkedListBox1.Items.Clear();
            helper.filterdorksconfigurations();
            progressBar1.Maximum = helper.dorksconfigurationlist.Count;
            helper.dorksconfigurationlist.ForEach(func =>
            {
                checkedListBox1.Items.Add(func, true);
                progressBar1.Value = checkedListBox1.Items.Count;
            });
        }

        private async void button5_Click(object sender, EventArgs e)
        {
            tabPage1.Controls
                .OfType<Button>()
                .ToList()
                .ForEach(func => func.Enabled = false);
            helper.loadlist(ref helper.dorkskeywordlist, "dorks keywords");
            await Task.Factory.StartNew(() =>
            {
                dorkssettingupdatekeywords();
            });
            tabPage1.Controls
                .OfType<Button>()
                .ToList()
                .ForEach(func => func.Enabled = true);
        }

        private void dorkssettingupdatekeywords()
        {
            checkedListBox2.Items.Clear();
            helper.filterdorkskeywords();
            progressBar1.Maximum = helper.dorkskeywordlist.Count;
            helper.dorkskeywordlist.ForEach(func =>
            {
                checkedListBox2.Items.Add(func, true);
                progressBar1.Value = checkedListBox2.Items.Count;
            });
        }

        private void button3_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox1.Items.Count; i++)
            {
                checkedListBox1.SetItemCheckState(i, CheckState.Unchecked);
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox1.Items.Count; i++)
            {
                checkedListBox1.SetItemCheckState(i, CheckState.Checked);
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox2.Items.Count; i++)
            {
                checkedListBox2.SetItemCheckState(i, CheckState.Checked);
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox2.Items.Count; i++)
            {
                checkedListBox2.SetItemCheckState(i, CheckState.Unchecked);
            }
        }

        private void button7_Click(object sender, EventArgs e)
        {
            helper.dorksconfigurationlist.Add(textBox1.Text);
            dorkssettingupdateconfigurations();
        }

        private void button8_Click(object sender, EventArgs e)
        {
            helper.dorkskeywordlist.Add(textBox2.Text);
            dorkssettingupdatekeywords();
        }

        private async void button9_Click(object sender, EventArgs e)
        {
            tabPage1.Controls
                .OfType<Button>()
                .ToList()
                .ForEach(func => func.Enabled = false);
            helper.dorksconfigurationlist.Clear();
            for (int i = 0; i < checkedListBox1.Items.Count; i++)
            {
                if (checkedListBox1.GetItemCheckState(i) == CheckState.Checked)
                    helper.dorksconfigurationlist.Add(checkedListBox1.Items[i].ToString());
            }
            label4.Text = helper.dorksconfigurationlist.Count.ToString();
            helper.dorkskeywordlist.Clear();
            for (int i = 0; i < checkedListBox2.Items.Count; i++)
            {
                if (checkedListBox2.GetItemCheckState(i) == CheckState.Checked)
                    helper.dorkskeywordlist.Add(checkedListBox2.Items[i].ToString());
            }
            label5.Text = helper.dorkskeywordlist.Count.ToString();
            int totaldorkspredict = helper.dorkskeywordlist.Count * helper.dorksconfigurationlist.Count;
            if (totaldorkspredict > 0)
            {
                progressBar1.Maximum = totaldorkspredict;
                progressBar1.Value = 0;
                helper.dorksgeneratedlist.Clear();
                await Task.Factory.StartNew(() =>
                {
                    helper.dorkskeywordlist.ForEach(func =>
                    {
                        helper.dorksconfigurationlist.ForEach(func2 =>
                        {
                            helper.dorksgeneratedlist.Add(func2.Replace("{DORK}", func));
                            progressBar1.Value = helper.dorksgeneratedlist.Count;
                        });
                    });
                    if (this.checkBox3.Checked)
                    {
                        helper.dorksgeneratedlist = helper.dorksgeneratedlist
                        .OrderByDescending(func => func.Length)
                        .ToList();
                    }
                    File.WriteAllLines(helper.logpath + "\\" + "dorksgenerated.txt", helper.dorksgeneratedlist);
                    if (!checkBox1.Checked)
                    {
                        helper.dorksgeneratedlist = new System.Collections.Generic.List<string>();
                    }
                    helper.Dispose();
                });
                MessageBox.Show("finished");
            }
            else
            {
                MessageBox.Show(
                    "load configurations and keywords to generate dorks",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            tabPage1.Controls
                .OfType<Button>()
                .ToList()
                .ForEach(func => func.Enabled = true);
        }

        #endregion tabpage1 - dorks setting

        #region tabpage2 - setting

        private void loadsetting()
        {
            #region general setting

            textBox5.Text = helper.urlregex;
            numericUpDown1.Value = helper.connectiontimeout;
            numericUpDown2.Value = helper.threadscount;
            checkBox4.Checked = helper.randomuseragent;
            textBox4.Text = helper.customuseragent;
            numericUpDown3.Value = helper.scannermaxpayloadchecking;
            numericUpDown4.Value = helper.grabbermaxsearchdepth;
            checkBox5.Checked = helper.continueifwafdetected;

            #region proxy setting

            checkBox8.Checked = helper.proxyautoupdate;

            checkBox7.Checked = helper.useproxy;
            if (helper.useproxy)
            {
                settingtabcontrolslist
                    .Where(func => func.Tag != null && func.Tag.ToString().Contains("proxy"))
                    .ToList()
                    .ForEach(func => func.Enabled = true);
                if (helper.proxyautoupdate)
                {
                    settingtabcontrolslist
                        .Where(func => func.Tag != null && func.Tag.ToString() == "proxyautoupdate")
                        .ToList()
                        .ForEach(func => func.Enabled = true);
                }
                else
                {
                    settingtabcontrolslist
                        .Where(func => func.Tag != null && func.Tag.ToString() == "proxyautoupdate")
                        .ToList()
                        .ForEach(func => func.Enabled = false);
                }
            }
            else
            {
                settingtabcontrolslist
                  .Where(func => func.Tag != null && func.Tag.ToString().Contains("proxy"))
                  .ToList()
                  .ForEach(func => func.Enabled = false);
            }
            comboBox2.SelectedItem = helper.proxytype;
            numericUpDown5.Value = helper.proxyautoupdateinterval;

            #endregion proxy setting

            #endregion general setting
        }

        private void buttonsenable(bool enable = false)
        {
            settingtabcontrolslist.OfType<Button>().ToList().ForEach(func =>
            {
                func.Enabled = enable;
            });
        }

        private List<Control> settingtabcontrols(Control basectr)
        {
            List<Control> res = new List<Control>();
            foreach (Control item in basectr.Controls)
            {
                if (item.GetType() == typeof(Panel))
                {
                    res.AddRange(settingtabcontrols(item));
                }
                else
                {
                    res.Add(item);
                }
            }
            return res;
        }

        private void updateguisettingdependmod()
        {
            List<Control> scanner_controls = new List<Control>();
            List<Control> urlgrabber_controls = new List<Control>();
            foreach (Control item in settingtabcontrolslist)
            {
                if (item.Tag != null)
                {
                    if (item.GetType() == typeof(RadioButton)) continue;
                    if (item.Tag.ToString() == "scanner")
                    {
                        scanner_controls.Add(item);
                    }
                    else if (item.Tag.ToString() == "grabber")
                    {
                        urlgrabber_controls.Add(item);
                    }
                }
            }
            if (radioButton1.Checked)
            {
                helper.scannersrealltimeupdate = false;
                scanner_controls.ForEach(func => func.Enabled = true);
                urlgrabber_controls.ForEach(func => func.Enabled = false);
            }
            else if (radioButton2.Checked)
            {
                scanner_controls.ForEach(func => func.Enabled = false);
                urlgrabber_controls.ForEach(func => func.Enabled = true);
            }
            else
            {
                helper.scannersrealltimeupdate = true;
                scanner_controls.ForEach(func => func.Enabled = true);
                urlgrabber_controls.ForEach(func => func.Enabled = true);
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            updateguisettingdependmod();
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            updateguisettingdependmod();
        }

        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            updateguisettingdependmod();
        }

        private void button14_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox5.Items.Count; i++)
            {
                checkedListBox5.SetItemCheckState(i, CheckState.Unchecked);
            }
        }

        private void button15_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox5.Items.Count; i++)
            {
                checkedListBox5.SetItemCheckState(i, CheckState.Checked);
            }
        }

        private void button13_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox3.Items.Count; i++)
            {
                checkedListBox3.SetItemCheckState(i, CheckState.Checked);
            }
        }

        private void button12_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox3.Items.Count; i++)
            {
                checkedListBox3.SetItemCheckState(i, CheckState.Unchecked);
            }
        }

        private void button11_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox4.Items.Count; i++)
            {
                checkedListBox4.SetItemCheckState(i, CheckState.Checked);
            }
        }

        private void button10_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBox4.Items.Count; i++)
            {
                checkedListBox4.SetItemCheckState(i, CheckState.Unchecked);
            }
        }

        private async void button16_Click(object sender, EventArgs e)
        {
            buttonsenable();
            helper.loadlist(ref helper.dorksgeneratedlist, "dorks list");
            await Task.Factory.StartNew(() =>
            {
                helper.dorksgeneratedlist.ForEach(func =>
                {
                    checkedListBox5.Items.Add(func, CheckState.Checked);
                });
            });
            buttonsenable(true);
        }

        private void button18_Click(object sender, EventArgs e)
        {
            string dork = textBox6.Text;
            if (!helper.dorksgeneratedlist.Contains(dork))
            {
                helper.dorksgeneratedlist.Add(dork);
                checkedListBox5.Items.Add(dork, CheckState.Checked);
            }
        }

        private void textBox5_TextChanged(object sender, EventArgs e)
        {
            helper.urlregex = textBox5.Text;
        }

        private void button17_Click(object sender, EventArgs e)
        {
            string payload = textBox3.Text;
            if (comboBox1.SelectedIndex == 0)
            {
                if (!helper.paylodasinstance.sql.Contains(payload))
                {
                    listView1.Items.Add(new ListViewItem(new string[] { "SQL", payload }));
                    helper.paylodasinstance.sql.Add(payload);
                }
            }
            else if (comboBox1.SelectedIndex == 1)
            {
                if (!helper.paylodasinstance.xss.Contains(payload))
                {
                    listView1.Items.Add(new ListViewItem(new string[] { "XSS", payload }));
                    helper.paylodasinstance.xss.Add(payload);
                }
            }
            else
            {
                if (!helper.paylodasinstance.lfi.Contains(payload))
                {
                    listView1.Items.Add(new ListViewItem(new string[] { "LFI", payload }));
                    helper.paylodasinstance.lfi.Add(payload);
                }
            }
        }

        private void numericUpDown1_ValueChanged(object sender, EventArgs e)
        {
            int value = (int)numericUpDown1.Value;
            helper.connectiontimeout = value;
        }

        private void numericUpDown2_ValueChanged(object sender, EventArgs e)
        {
            int value = (int)numericUpDown2.Value;
            helper.threadscount = value;
        }

        private void checkBox4_CheckedChanged(object sender, EventArgs e)
        {
            helper.randomuseragent = checkBox4.Checked;
        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {
            helper.customuseragent = textBox4.Text;
        }

        private void numericUpDown3_ValueChanged(object sender, EventArgs e)
        {
            int value = (int)numericUpDown3.Value;
            helper.scannermaxpayloadchecking = value;
        }

        private void numericUpDown4_ValueChanged(object sender, EventArgs e)
        {
            int value = (int)numericUpDown4.Value;
            helper.grabbermaxsearchdepth = value;
        }

        private void checkBox5_CheckedChanged(object sender, EventArgs e)
        {
            helper.continueifwafdetected = checkBox5.Checked;
        }

        private void checkBox7_CheckedChanged(object sender, EventArgs e)
        {
            helper.useproxy = checkBox7.Checked;
            if (helper.useproxy)
            {
                settingtabcontrolslist
                    .Where(func => func.Tag != null && func.Tag.ToString().Contains("proxy"))
                    .ToList()
                    .ForEach(func => func.Enabled = true);
                if (helper.proxyautoupdate)
                {
                    settingtabcontrolslist
                        .Where(func => func.Tag != null && func.Tag.ToString() == "proxyautoupdate")
                        .ToList()
                        .ForEach(func => func.Enabled = true);
                }
                else
                {
                    settingtabcontrolslist
                        .Where(func => func.Tag != null && func.Tag.ToString() == "proxyautoupdate")
                        .ToList()
                        .ForEach(func => func.Enabled = false);
                }
            }
            else
            {
                settingtabcontrolslist
                  .Where(func => func.Tag != null && func.Tag.ToString().Contains("proxy"))
                  .ToList()
                  .ForEach(func => func.Enabled = false);
            }
        }

        private void checkBox8_CheckedChanged(object sender, EventArgs e)
        {
            helper.proxyautoupdate = checkBox8.Checked;
            if (helper.proxyautoupdate)
            {
                settingtabcontrolslist
                    .Where(func => func.Tag != null && func.Tag.ToString() == "proxyautoupdate")
                    .ToList()
                    .ForEach(func => func.Enabled = true);
            }
            else
            {
                settingtabcontrolslist
                    .Where(func => func.Tag != null && func.Tag.ToString() == "proxyautoupdate")
                    .ToList()
                    .ForEach(func => func.Enabled = false);
            }
        }

        private void comboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {
            helper.proxytype = comboBox2.SelectedItem.ToString();
        }

        private void numericUpDown5_ValueChanged(object sender, EventArgs e)
        {
            int value = (int)numericUpDown5.Value;
            helper.proxyautoupdateinterval = value;
        }

        private async void button19_Click(object sender, EventArgs e)
        {
            helper.proxyloadurl = Interaction.InputBox("Enter proxy url", "Url", helper.proxyloadurl, -1, -1);
            if (Uri.IsWellFormedUriString(helper.proxyloadurl, UriKind.Absolute))
            {
                buttonsenable();
                await Task.Factory.StartNew(() =>
                {
                    helper.loadproxyfromurl();
                });
                MessageBox.Show("Loaded proxies : " + helper.proxylist.Count,
                    "Result",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                buttonsenable(true);
            }
        }

        private void button20_Click(object sender, EventArgs e)
        {
            buttonsenable();
            helper.loadlist(ref helper.proxylist, "proxy list");
            MessageBox.Show("Loaded proxies : " + helper.proxylist.Count,
                "Result",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            buttonsenable(true);
        }

        #endregion tabpage2 - setting

        #region tabpage3 - statistics

        private async void button22_Click(object sender, EventArgs e)
        {
            if (this.button22.Text == "Start")
            {
                if (radioButton1.Checked)
                {
                    helper.scannersrealltimeupdate = false;
                    helper.stopsource = new CancellationTokenSource();
                    if (checkedListBox3.CheckedItems.Count > 0)
                    {
                        for (int i = 0; i < checkedListBox3.Items.Count; i++)
                        {
                            if (checkedListBox3.GetItemCheckState(i) != CheckState.Checked)
                            {
                                helper.scannerslist.RemoveAll(func => func.name == checkedListBox3.Items[i].ToString());
                            }
                        }

                        if (helper.scannerslist.Count > 0)
                        {
                            if (helper.urlslist.Count > 0)
                            {
                                label35.Text = helper.urlslist.Count.ToString();
                                button22.Text = "Stop";
                                await helper.scannerstart();
                            }
                            else
                            {
                                MessageBox.Show("load urls first to use scanner",
                                    "error",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Error);
                            }
                        }
                        else
                        {
                            MessageBox.Show("set a vulnerability scanner first to use scanner",
                                "error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                        }
                    }
                    else
                    {
                        MessageBox.Show("set a vulnerability scanner first to use scanner",
                             "error",
                             MessageBoxButtons.OK,
                             MessageBoxIcon.Error);
                    }
                }
                else if (radioButton2.Checked)
                {
                    helper.stopsource = new CancellationTokenSource();
                    if (checkedListBox4.CheckedItems.Count > 0)
                    {
                        for (int i = 0; i < checkedListBox4.Items.Count; i++)
                        {
                            if (checkedListBox4.GetItemCheckState(i) != CheckState.Checked)
                            {
                                helper.searcherslist.RemoveAll(func => func.name == checkedListBox4.Items[i].ToString());
                            }
                        }
                        if (helper.searcherslist.Count > 0)
                        {
                            if (helper.dorksgeneratedlist.Count > 0)
                            {
                                button22.Text = "Stop";
                                await helper.searchersstart();
                                button22.Text = "Start";
                            }
                            else
                            {
                                MessageBox.Show("load dorkslsit first to use url grabber",
                              "error",
                              MessageBoxButtons.OK,
                              MessageBoxIcon.Error);
                            }
                        }
                        else
                        {
                            MessageBox.Show("set a searcher first to use url grabber",
 "error",
 MessageBoxButtons.OK,
 MessageBoxIcon.Error);
                        }
                    }
                    else
                    {
                        MessageBox.Show("set a searcher first to use url grabber",
                      "error",
                      MessageBoxButtons.OK,
                      MessageBoxIcon.Error);
                    }
                }
                else
                {
                    helper.stopsource = new CancellationTokenSource();
                    helper.scannersrealltimeupdate = true;
                    if (checkedListBox4.CheckedItems.Count > 0)
                    {
                        for (int i = 0; i < checkedListBox4.Items.Count; i++)
                        {
                            if (checkedListBox4.GetItemCheckState(i) != CheckState.Checked)
                            {
                                helper.searcherslist.RemoveAll(func => func.name == checkedListBox4.Items[i].ToString());
                            }
                        }
                        if (helper.searcherslist.Count > 0)
                        {
                            if (checkedListBox3.CheckedItems.Count > 0)
                            {
                                for (int i = 0; i < checkedListBox3.Items.Count; i++)
                                {
                                    if (checkedListBox3.GetItemCheckState(i) != CheckState.Checked)
                                    {
                                        helper.scannerslist.RemoveAll(func => func.name == checkedListBox3.Items[i].ToString());
                                    }
                                }
                                if (helper.scannerslist.Count > 0)
                                {
                                    button22.Text = "Stop";
                                    List<Task> tklist = new List<Task>();
                                    tklist.Add(helper.searchersstart());
                                    tklist.Add(helper.scannerstart());
                                    helper.scannerbothisactive = true;
                                    await Task.WhenAll(tklist);
                                    helper.stopsource.Cancel();
                                    MessageBox.Show("Finished both");
                                }
                                else
                                {
                                    MessageBox.Show("set a vulnerability scanner first to use scanner", "error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                }
                            }
                            else
                            {
                                MessageBox.Show("set a vulnerability scanner first to use scanner", "error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                        }
                        else
                        {
                            MessageBox.Show("set a searcher first to use url grabber", "error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    else
                    {
                        MessageBox.Show("set a searcher first to use url grabber", "error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            else
            {
                helper.stopsource.Cancel();
                button22.Text = "Start";
                helper.scannerbothisactive = false;
            }
        }

        private void button21_Click(object sender, EventArgs e)
        {
            helper.loadlist(ref helper.urlslist, "urls list");
        }

        #endregion tabpage3 - statistics
    }
}