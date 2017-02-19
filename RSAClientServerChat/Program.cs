using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace RSAClientServerChat
{
    class Program
    {
        private static RSACryptoServiceProvider keys { get; set; }
        private static RSACryptoServiceProvider enc;
        private static RSACryptoServiceProvider decr;
        private static string acquiredPublicKey;
        private static int KEYS_BITS = 3072;
        private static string IP_ADDRESS = "127.0.0.1";
        private static int PORT = 8888;
        private static NetworkStream stream;
        private static bool isServer = false;

        static void Main(string[] args)
        {
            int choise;
            Console.WriteLine("1. Start server");
            Console.WriteLine("2. Start client");
            choise = Int32.Parse(Console.ReadLine());
            switch (choise)
            {
                case 1:
                    isServer = true;
                    IPAddress localAddr = IPAddress.Parse(IP_ADDRESS);
                    TcpListener server = new TcpListener(localAddr, PORT);
                    server.Start();
                    Console.WriteLine("Waiting for client...");
                    while (true)
                    {
                        if (server.Pending())
                        {
                            Console.WriteLine("Client connected...");
                            stream = server.AcceptTcpClient().GetStream();
                            exchangeKeys();
                            Console.WriteLine("Client public key " + acquiredPublicKey);
                            break;
                        }
                    }
                    while (true)
                    {
                        receiveMessage();
                    }
                    break;
                case 2:
                    TcpClient client = new TcpClient();
                    client.Connect(IP_ADDRESS, PORT);
                    if (client.Connected)
                    {
                        Console.WriteLine("Connection to server has been established...");
                        stream = client.GetStream();
                        exchangeKeys();
                        Console.WriteLine("Server public key " + acquiredPublicKey);
                    }
                    else
                    {
                        Console.WriteLine("Connection error, while trying to connect to {0} on {1}", IP_ADDRESS, PORT);
                        Console.ReadKey();
                        return;
                    }
                    while (client.Connected)
                    {
                        sendMessage();
                        //receiveMessage();
                    }
                    break;
            }
        }
        public static void receiveMessage()
        {
            while (true)
            {
                try
                {
                    byte[] data = new byte[384];
                    StringBuilder builder = new StringBuilder();
                    int bytes = 0;
                    string message;
                    do
                    {
                        bytes = stream.Read(data, 0, data.Length);
                        builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                        message = builder.ToString();
                    }
                    while (stream.DataAvailable);
                    if (message.Contains("--encr--"))
                    {
                        decr = new RSACryptoServiceProvider();
                        decr.FromXmlString(keys.ToXmlString(true)); // load our private key
                        //enc.FromXmlString(acquiredPublicKey); // load acquired public key
                        //byte[] decrData = enc.Decrypt(Encoding.Unicode.GetBytes(message), false);
                        byte[] decrData = decr.Decrypt(data, true);
                        message = Encoding.Unicode.GetString(decrData);
                        Console.WriteLine("Received message:");
                        Console.WriteLine(message);//вывод сообщения
                        sendMessage();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine(keys.ToXmlString(false));
                    Console.ReadLine();
                }
            }
        }
        public static void sendMessage()
        {
            while (true)
            {
                Console.WriteLine("Enter message:");
                string message = Console.ReadLine();
                byte[] data = new byte[384];
                enc = new RSACryptoServiceProvider();
                enc.FromXmlString(acquiredPublicKey); // load acquired public key
                data = enc.Encrypt(Encoding.Unicode.GetBytes(message), true);
                //enc.FromXmlString(keys.ToXmlString(true)); // load our private key
                //data = enc.Encrypt(data, false);
                byte[] mark = Encoding.Unicode.GetBytes("--encr--");
                stream.Write(mark, 0, mark.Length);
                stream.Write(data, 0, data.Length);
                receiveMessage();
            }
        }
        public static void exchangeKeys()
        {
            StringBuilder builder = new StringBuilder();
            int bytes = 0;
            byte[] data = new byte[1024];
            if (!isServer)
            {
                do
                {
                    bytes = stream.Read(data, 0, data.Length);
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                } while (stream.DataAvailable);
                Console.WriteLine("Receiving server public key...");
                acquiredPublicKey = builder.ToString();
            }
            Console.WriteLine("Generating RSA public and private keys...");
            keys = new RSACryptoServiceProvider(KEYS_BITS);
            string publicKey = keys.ToXmlString(false);
            Console.WriteLine("Sending public key...");
            stream.Write(Encoding.Unicode.GetBytes(publicKey), 0, Encoding.Unicode.GetBytes(publicKey).Length);
            if (isServer)
            {
                do
                {
                    bytes = stream.Read(data, 0, data.Length);
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                } while (stream.DataAvailable);
                Console.WriteLine("Receiving client public key...");
                acquiredPublicKey = builder.ToString();
            }
        }
    }
}
