using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.ServiceModel;
using Client.ChatService;
using System.IO;
using System.Security.Cryptography;
using RSAEncryptionLib;
using System.Security.Cryptography.X509Certificates;

namespace Client
{
    public partial class frmClient : Form
    {
        ReceiveClient rc = null;
        string myName;

        RSAEncryption myRsa = new RSAEncryption();
        AesCryptoServiceProvider myAes = new AesCryptoServiceProvider();
        byte[] sessionKey;
        
        public frmClient()
        {
            InitializeComponent();
            this.FormClosing+=new FormClosingEventHandler(frmClient_FormClosing);
            this.txtSend.KeyPress += new KeyPressEventHandler(txtSend_KeyPress);
            
        }

        void txtSend_KeyPress(object sender, KeyPressEventArgs e)
        {
            int keyValue = (int)e.KeyChar;

            if (keyValue == 13)
                SendMessage();
            
        }

        private void frmClient_FormClosing(object sender, EventArgs e)
        {
            rc.Stop(myName);
        }

        private void frmClient_Load(object sender, EventArgs e)
        {
            txtMsgs.Enabled = false;
            txtSend.Enabled = false;
            btnSend.Enabled = false;
        }

        void rc_ReceiveMsg(string sender, byte[] msg)
        {
            string sMsg="";
            //the first 4 bytes represresent a flag (0=>public chat (AES), 1=>private chat (RSA))
            int f = BitConverter.ToInt32(msg, 0);

            string path = Application.StartupPath + "\\" + myName + "PrivateKey.xml";
            myRsa.LoadPrivateFromXml(path);  // Loading the private key to the custom RSA instance
            if ((msg.Length > 0) && (f == 0)) //public chat
            {
                Data msgReceived = new Data(msg);
                this.sessionKey = null;
                this.sessionKey = myRsa.PrivateDecryption(msgReceived.encrKey); //decrypt session Key with the assymetric key (public Key)
                msgReceived.strMessage = Encoding.UTF8.GetBytes(AES.DecryptStringFromBytes_Aes(msgReceived.strMessage, this.sessionKey, Encoding.UTF8.GetBytes("1234567812345678"))); //decrypt the msg with the session key
                sMsg = Encoding.UTF8.GetString(msgReceived.strMessage);
            }
            else if ((msg.Length > 0) && (f == 1)) //private chat
            {
                // this section is related to 1st step in homework
                /*
                byte[] msgToDecrypt = msg.Skip(8).ToArray();
                byte[] message = null;
                message = myRsa.PrivateDecryption(msgToDecrypt);
                sMsg = Encoding.UTF8.GetString(message);
                */

                string CN = "CN=" + myName;
                X509Store store = new X509Store("My");
                store.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    string CerName = cert.GetName();
                    if (CerName.CompareTo(CN) == 0)
                    {
                        RSACryptoServiceProvider provider = (RSACryptoServiceProvider)cert.PrivateKey;
                       
                        Data msgReceived = new Data(msg);
                        this.sessionKey = provider.Decrypt(msgReceived.encrKey, false);//decrypt the session key with reciever public key
                        msgReceived.strMessage = Encoding.UTF8.GetBytes(AES.DecryptStringFromBytes_Aes(msgReceived.strMessage, this.sessionKey, Encoding.UTF8.GetBytes("1234567812345678"))); //decrypt the msg with the session key

                        //load the public key of the sender for decription the hash value and verfying the msg (digital signature)
                        RSACryptoServiceProvider senderRSA=new RSACryptoServiceProvider();
                        senderRSA.FromXmlString(msgReceived.publicParams);
                        RSAParameters senderPuKey = senderRSA.ExportParameters(false);
                       
                        if (VerifySignedHash(msgReceived.strMessage, msgReceived.msgHash, senderPuKey))// decrypt hash and verify data
                        {
                            sMsg = Encoding.UTF8.GetString(msgReceived.strMessage);
                        }
                    }
                }
            }
            txtMsgs.AppendText(Environment.NewLine + sender + ">" + sMsg);
        }

  
        void rc_NewNames(object sender, List<string> names)
        {
            lstClients.Items.Clear();
            foreach (string name in names)
            {
                if (name!=myName)
                    lstClients.Items.Add(name);
            }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            SendMessage();
        }

        public void initAES()
        {
            this.sessionKey = myAes.Key;
            myAes.IV = Encoding.UTF8.GetBytes("1234567812345678");
        }

        public byte[] encryptAES(string des)
        {
            this.sessionKey = myAes.Key;
            Data msgToSend = new Data();
            string path = Application.StartupPath + "\\" + des + "PublicKey.xml";
            myRsa.LoadPublicFromXml(path);// load the public key of the reciever
            msgToSend.strMessage = AES.EncryptStringToBytes_Aes(txtSend.Text, myAes.Key, myAes.IV);//encrypt msg with session key
            byte[] sssa = myRsa.PublicEncryption(this.sessionKey);//encrypt session key with reciever public key
            msgToSend.encrKey = sssa;
            byte[] byteData = msgToSend.ToByte();
            Data sssdsd = new Data(byteData);
            return byteData;
        }

        private void SendMessage()
        {
            if (lstClients.Items.Count != 0)
            {
                txtMsgs.AppendText( Environment.NewLine + myName + ">" + txtSend.Text);
                if (lstClients.SelectedItems.Count == 0)//public chat
                {
                    
                    for (int i = 0; i < lstClients.Items.Count; i++)
                    {
                        byte[] toSend = encryptAES(lstClients.Items[i].ToString());
                        rc.SendMessage(toSend, myName, lstClients.Items[i].ToString()); 
                    }
                }
                else
                    if (!string.IsNullOrEmpty(lstClients.SelectedItem.ToString()))//private chat
                    {
                        for (int i = 0; i < lstClients.SelectedItems.Count; i++)
                        {
                           //this section is related to the 1st step in the homework
                            /*
                            string path = Application.StartupPath + "\\" + lstClients.SelectedItems[i].ToString() + "PublicKey.xml";
                            myRsa.LoadPublicFromXml(path);  // Loading the public key to the custom RSA instance
                            byte[] message = Encoding.UTF8.GetBytes(txtSend.Text);
                            byte[] encMessage = null;
                            encMessage = myRsa.PublicEncryption(message);
                            Data msgToSend = new Data();
                            msgToSend.strMessage = encMessage;
                            msgToSend.flag = 1;
                            byte[] byteData = msgToSend.ToByte();

                            rc.SendMessage(byteData, myName, lstClients.SelectedItems[i].ToString());
                            //rc.SendMessage(txtSend.Text, myName, lstClients.SelectedItems[i].ToString());
                            * */

                            string myNameWithMethod = myName + "_RSA";
                            string CN = "CN=" + lstClients.SelectedItems[i].ToString();
                            X509Store store = new X509Store("My");

                            store.Open(OpenFlags.ReadOnly);

                            foreach (X509Certificate2 cert in store.Certificates)
                            {
                                string CerName = cert.GetName();
                                if (CerName.CompareTo(CN) == 0)
                                {
                                    
                                    RSACryptoServiceProvider desProvider = (RSACryptoServiceProvider)cert.PublicKey.Key;//public key of the reciever from the certificate

                                    //load the private key of sender for digital signature
                                    string path = Application.StartupPath + "\\" + myName+ "PrivateKey.xml";
                                    myRsa.LoadPrivateFromXml(path);
                                    RSAParameters prKey = myRsa.rsa.ExportParameters(true);

                                    //store data to send
                                    Data msgToSend = new Data();
                                    msgToSend.flag = 1;
                                    msgToSend.publicParams = myRsa.rsa.ToXmlString(false);//public key of the sender (for digital signature use)
                                    msgToSend.strMessage = Encoding.UTF8.GetBytes(txtSend.Text);
                                    
                                    msgToSend.msgHash = HashAndSignBytes(msgToSend.strMessage, prKey);//calculate hash of the msg and sign the hash value with sender private key
                                    this.sessionKey = myAes.Key;
                                    msgToSend.strMessage = AES.EncryptStringToBytes_Aes(Encoding.UTF8.GetString(msgToSend.strMessage), myAes.Key, myAes.IV);//encrypt the msg with session key
                                    msgToSend.encrKey = desProvider.Encrypt(this.sessionKey, false);//encrypt session key with destination public key
                                    byte[] byteData = msgToSend.ToByte();
                                    rc.SendMessage(byteData, myNameWithMethod, lstClients.SelectedItems[i].ToString());
                                }
                            }
                        }
                    }
                txtSend.Clear();
            }
        }


        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the  
                // key from RSAParameters.  
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider 
                // to specify the use of SHA1 for hashing. 
                return RSAalg.SignData(DataToSign, new SHA1CryptoServiceProvider());
            }
            catch (CryptographicException e)
            {
                MessageBox.Show(e.Message);
                return null;
            }
        }


        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the  
                // key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA1CryptoServiceProvider 
                // to specify the use of SHA1 for hashing. 
                return RSAalg.VerifyData(DataToVerify, new SHA1CryptoServiceProvider(), SignedData);

            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            if (txtUserName.Text.Length > 0)
            {
                txtMsgs.Enabled = true;
                txtSend.Enabled = true;
                btnSend.Enabled = true;

                myName = txtUserName.Text.Trim();

                initAES();
              //this section is related to the 1st step in the homework
                /*
                rc = new ReceiveClient();
                rc.Start(rc, myName);
                 //MessageBox.Show("The Key pair created successfully at:\n" + Application.StartupPath);
               */

                rc = new ReceiveClient();
                rc.Start(rc, myName);
                rc.NewNames += new GotNames(rc_NewNames);
                rc.ReceiveMsg += new ReceviedMessage(rc_ReceiveMsg);

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                string privateKey = rsa.ToXmlString(true);
                File.WriteAllText(Application.StartupPath + "\\" + myName + "PrivateKey.xml", privateKey);
                string publicKey = rsa.ToXmlString(false);
                File.WriteAllText(Application.StartupPath + "\\" + myName + "PublicKey.xml", publicKey);
               



                System.Diagnostics.Process process = new System.Diagnostics.Process();
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                startInfo.FileName = "cmd.exe";
                startInfo.Arguments = "makecert -r -pe -n CN=" + myName + " -sky exchange -ss my";
                process.StartInfo = startInfo;
                process.Start();

            }
            else
            {
                txtMsgs.Enabled = false;
                txtSend.Enabled = false;
                btnSend.Enabled = false;
            }
        }

    }
   
}
