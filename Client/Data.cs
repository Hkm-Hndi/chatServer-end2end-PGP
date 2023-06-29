using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Client
{
    class Data
    {
        public int flag;// 0=>AES, 1=>RSA
        public byte[] encrKey;
        public byte[] strMessage;
        public string publicParams;
        public byte[] msgHash;


        public Data()
        {
            this.strMessage = null;
            this.encrKey = null;
            this.publicParams = null;
            this.msgHash = null;
            this.flag = 0;
        }

        public Data(byte[] data)
        {

            //length of the encryption key (symmetric Key)
            int encrLen = BitConverter.ToInt32(data, 4);

            //length of the public params
            int pubLen = BitConverter.ToInt32(data, 8);

            //length of the hash
            int hashLen = BitConverter.ToInt32(data, 12);

            //length of the message
            int msgLen = BitConverter.ToInt32(data, 16);

            //check if the encryption passed to the bytes array
            if (encrLen > 0)
            {
                this.encrKey = new byte[encrLen];
                System.Array.Copy(data, 20, this.encrKey, 0, encrLen);
            }
            else
                this.encrKey = null;


            //check if the encryption passed to the bytes array
            if (pubLen > 0)
                this.publicParams = Encoding.UTF8.GetString(data, 20 + encrLen, pubLen);
            else
                this.publicParams = null;

            //check if the hash value passed to the bytes array
            if (hashLen > 0)
            {
                this.msgHash = new byte[hashLen];
                System.Array.Copy(data, 20 + encrLen + pubLen, this.msgHash, 0, hashLen);
            }
            else
                this.msgHash = null;

            //check for a null message field
            if (msgLen > 0)
            {
                this.strMessage = new byte[msgLen];
                System.Array.Copy(data, 20 + encrLen + pubLen + hashLen, this.strMessage, 0, msgLen);
            }
            else
                this.strMessage = null;
        }

        
        public byte[] ToByte()
        {
            List<byte> result = new List<byte>();
            //Add flag to the begining (0=>AES, 1=>RSA)
            result.AddRange(BitConverter.GetBytes(this.flag));
           
            //Add the length of the encryption key
            if (encrKey != null)
                result.AddRange(BitConverter.GetBytes(encrKey.Length));
            else if ((encrKey==null) && (flag!=1))
                result.AddRange(BitConverter.GetBytes(0));

            //Add the length of the public key
            if (publicParams != null)
                result.AddRange(BitConverter.GetBytes(publicParams.Length));
            else
                result.AddRange(BitConverter.GetBytes(0));

            //Add the length of the hash
            if (msgHash != null)
                result.AddRange(BitConverter.GetBytes(msgHash.Length));
            else
                result.AddRange(BitConverter.GetBytes(0));

            //Add the Length of the message
            if (strMessage != null)
                result.AddRange(BitConverter.GetBytes(strMessage.Length));
            else
                result.AddRange(BitConverter.GetBytes(0));

            //Add the values to the bytes array
            if (encrKey != null)
                result.AddRange(encrKey);

            if (publicParams != null)
                result.AddRange(Encoding.UTF8.GetBytes(publicParams));

            if (msgHash != null)
                result.AddRange(msgHash);

            if (strMessage != null)
                result.AddRange(strMessage);

            return result.ToArray();
        }


    }
}
