using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace Client
{
    class AES256
    {
        private string key;
        private string iv;
        private int bytelen = 32;
        private int bitlen = 256;

        public AES256()
        {
            key = "abcdefgh12345678abcdefgh12345678";
            iv = "abcdefgh12345678";
        }
        public AES256(string _key)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _key;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }
        public AES256(string _key, string _iv)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _iv;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }

        public string getKey() { return key; }
        public string getIV() { return iv; }

        public string Encrypt(string textToEncrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            byte[] plainText = Encoding.UTF8.GetBytes(textToEncrypt);
            return Convert.ToBase64String(transform.TransformFinalBlock(plainText, 0, plainText.Length));
        }
        public string Decrypt(string textToDecrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] encryptedData = Convert.FromBase64String(textToDecrypt);
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            byte[] plainText = rijndaelCipher.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return Encoding.UTF8.GetString(plainText);
        }
    }
    public class AsyncObject
    {
        public byte[] Buffer;
        public Socket WorkingSocket;
        public readonly int BufferSize;
        public AsyncObject(int bufferSize)
        {
            BufferSize = bufferSize;
            Buffer = new byte[BufferSize];
        }

        public void ClearBuffer()
        {
            Array.Clear(Buffer, 0, BufferSize);
        }
    }
    public partial class MainWindow : Window
    {
        AES256 aes256;
        String args = "";
        bool isAddNeeded = false;
        bool isEncryption = true;
        delegate void AppendTextDelegate(Control ctrl, string s);
        AppendTextDelegate _textAppender;
        Socket mainSock;
        DispatcherTimer timer = new DispatcherTimer();
        public MainWindow()
        {
            InitializeComponent();
            timer.IsEnabled = true;
            timer.Interval = TimeSpan.FromMilliseconds(500);
            timer.Tick += new EventHandler(Timer_Tick);
            timer.Start();
            mainSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
            _textAppender = new AppendTextDelegate(AppendText);
            IPHostEntry he = Dns.GetHostEntry(Dns.GetHostName());
            aes256 = new AES256("developerswithaes256byjuyeongjin");

            // 처음으로 발견되는 ipv4 주소를 사용한다.
            IPAddress defaultHostAddress = null;
            foreach (IPAddress addr in he.AddressList)
            {
                if (addr.AddressFamily == AddressFamily.InterNetwork)
                {
                    defaultHostAddress = addr;
                    break;
                }
            }

            if (defaultHostAddress == null)
                defaultHostAddress = IPAddress.Loopback;

            txtAddress.Text = defaultHostAddress.ToString();
        }

        public void Timer_Tick(object sender, EventArgs e)
        {
            if (isAddNeeded)
            {
                addLogs(args);
                args = "";
                isAddNeeded = false;
            }
        }

        void AppendText(Control ctrl, string s)
        {
            if (!ctrl.Dispatcher.CheckAccess())
            {
                ctrl.Dispatcher.Invoke(_textAppender, ctrl, s);
            }
            else
            {
                ctrl.SetValue(TextBlock.TextProperty, ctrl.GetValue(TextBlock.TextProperty) + Environment.NewLine + s);
                ctrl.SetValue(ContentControl.ContentProperty, ctrl.GetValue(ContentControl.ContentProperty) + Environment.NewLine + s);
            }
            args = s;
            isAddNeeded = true;
        }
        public void addLogs(String str)
        {
            log.AppendText(str + Environment.NewLine);
            log.Select(log.Text.Length, 0);
            log.ScrollToEnd();
        }

        void Connect_Click(object sender, RoutedEventArgs e)
        {
            if (mainSock.Connected)
            {
                MessageBox.Show("이미 연결되어 있습니다!");
                return;
            }

            int port;
            if (!int.TryParse(txtPort.Text, out port))
            {
                MessageBox.Show("포트 번호가 잘못 입력되었거나 입력되지 않았습니다.");
                txtPort.Focus();
                txtPort.SelectAll();
                return;
            }
            try { mainSock.Connect(new IPEndPoint(IPAddress.Parse(txtAddress.Text), port)); }
            catch (Exception ex)
            {
                MessageBox.Show("연결에 실패했습니다!\n오류 내용: " +  ex.Message, "", MessageBoxButton.OK);
                return;
            }

            AppendText(log, "서버와 연결되었습니다.");

            AsyncObject obj = new AsyncObject(4096);
            obj.WorkingSocket = mainSock;
            mainSock.BeginReceive(obj.Buffer, 0, obj.BufferSize, 0, DataReceived, obj);
        }
        void DataReceived(IAsyncResult ar)
        {
            AsyncObject obj = (AsyncObject)ar.AsyncState;
            int received;
            try
            {
                received = obj.WorkingSocket.EndReceive(ar);
            }
            catch (Exception ex)
            {
                MessageBox.Show("서버와의 연결이 끊어졌습니다! 서버 상태를 확인해주세요.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                mainSock.Close();
                mainSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
                return;
            }

            if (received <= 0)
            {
                obj.WorkingSocket.Close();
                return;
            }

            string text = Encoding.UTF8.GetString(obj.Buffer);

            // 0x01 기준으로 짜른다.
            // tokens[0] - 보낸 사람 IP
            // tokens[1] - 보낸 메세지
            string[] tokens = text.Split('\x01');
            string ip = tokens[0];
            string msg = tokens[1];
            msg = msg.Trim('\0');
            string resulttxt;
            if(isEncryption)
            {
                resulttxt = aes256.Decrypt(msg);
            }
            else resulttxt = msg;
            AppendText(log, string.Format("[받음]{0}: {1}", ip, resulttxt));

            obj.ClearBuffer();

            obj.WorkingSocket.BeginReceive(obj.Buffer, 0, 4096, 0, DataReceived, obj);
        }

        void Send_Click(object sender, RoutedEventArgs e)
        {
            if (!mainSock.IsBound)
            {
                MessageBox.Show("서버가 실행되고 있지 않습니다!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string tts = txtTTS.Text.Trim();
            string ttse;
            if (isEncryption)
            {
                ttse = aes256.Encrypt(tts);
            }
            else ttse = tts;
            if (string.IsNullOrEmpty(tts))
            {
                MessageBox.Show("텍스트가 입력되지 않았습니다!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                txtTTS.Focus();
                return;
            }

            // 서버 ip 주소와 메세지를 담도록 만든다.
            IPEndPoint ip = (IPEndPoint)mainSock.LocalEndPoint;
            string addr = ip.Address.ToString() + ":" + (ip.Port.ToString());
            byte[] bDts = Encoding.UTF8.GetBytes(addr + '\x01' + ttse);

            mainSock.Send(bDts);

            AppendText(log, string.Format("[보냄]{0}: {1}", addr, tts));
            txtTTS.Clear();
        }

        private void Grid_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key.Equals(Key.Enter))
            {
                if (mainSock.Connected)
                {
                    Send_Click(sender, e);
                    txtTTS.Focus();
                }
                else
                {
                    Connect_Click(sender, e);
                    txtTTS.Focus();
                }
            }
        }

        private void isEncrypt_Checked(object sender, RoutedEventArgs e)
        {
            isEncryption = true;
        }

        private void isEncrypt_Unchecked(object sender, RoutedEventArgs e)
        {
            isEncryption = false;
        }
    }
}
