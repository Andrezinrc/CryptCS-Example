using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FileCryptor
{
    public class CryptCS
    {
        private List<byte> key;
        private const int KeySize = 32;
        public const string KeyHeader = "CRYPT::KEY"; //header da chave
        public const string TextHeader = "CRYPT::TEXT"; //header arquivo de texto
        public const string BinaryHeader = "CRYPT::BIN"; //header arquivos binario

        public CryptCS()
        {
            key = new List<byte>();
        }

        // gera uma nova chave e salva no caminho informado
        public void GenerateKey(string path)
        {
            string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            key.Clear();

            for (int i = 0; i < KeySize; i++)
            {
                char c = characters[random.Next(characters.Length)];
                key.Add((byte)c);
            }

            //cria uma cópia da chave com a assinatura no início
            //a assinatura NAO deve ser adicionada a lista key
            List<byte> keyWithHeader = new List<byte>();
            keyWithHeader.AddRange(Encoding.UTF8.GetBytes(KeyHeader)); //so na hora de salvar
            keyWithHeader.AddRange(key);
            File.WriteAllBytes(path, keyWithHeader.ToArray());
        }

        // carrega chave de um arquivo
        public void LoadKey(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Arquivo de chave não encontrado.");
            }

            byte[] rawKey = File.ReadAllBytes(path);

            if (rawKey.Length < KeyHeader.Length)
            {
                throw new Exception("Chave inválida: tamanho insuficiente");
            }

            // verifica a assinatura
            string header = Encoding.UTF8.GetString(rawKey.Take(KeyHeader.Length).ToArray());
            if (header != KeyHeader)
                throw new Exception("Chave inválida ou corrompida!");

            // agora so a parte da chave é usada nos calculos
            key = new List<byte>(rawKey.Skip(KeyHeader.Length));

            //verificacao tamanho da chave
            if (key.Count < 32)
            {
                throw new Exception("Chave inválida: tamanho da chave criptográfica insuficiente");
            }
        }

        //verifica se um arquivo é binário com base na sua extensao
        public bool IsBinaryFile(string filePath)
        {
            // extensoes comuns de arquivos de texto
            string[] textExtensions = { ".txt", ".csv", ".json", ".xml", ".html", ".md" };

            string ext = Path.GetExtension(filePath).ToLower();
            return !textExtensions.Contains(ext);
        }

        // criptografa o texto com a chave carregada
        public string Encrypt(string text)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            byte[] result = new byte[textBytes.Length];

            //verifica se a chave esta carregada
            if (key.Count == 0)
                throw new Exception("Chave vazia: carregamento falhou?");

            for (int i = 0; i < textBytes.Length; i++)
            {
                byte original = textBytes[i];
                byte keyByte = key[i % key.Count];

                // soma o byte do conteudo com o byte da chave e aplica % 256 para manter no intervalo de 0–255
                byte encrypted = (byte)((original + keyByte) % 256);
                result[i] = encrypted;
            }

            //armazena como texto
            return TextHeader + Convert.ToBase64String(result);
        }

        // para arquivos binarios img, pdf etc
        public byte[] Encrypt(byte[] data)
        {
            byte[] result = new byte[data.Length];

            //verifica se a chave esta carregada
            if (key.Count == 0)
                throw new Exception("Chave vazia: carregamento falhou?");

            for (int i = 0; i < data.Length; i++)
            {
                byte original = data[i];
                byte keyByte = key[i % key.Count];
                byte encrypted = (byte)((original + keyByte) % 256);

                result[i] = encrypted;
            }

            byte[] header = Encoding.UTF8.GetBytes(BinaryHeader);
            byte[] dataWithHeader = new byte[header.Length + result.Length];

            Buffer.BlockCopy(header, 0, dataWithHeader, 0, header.Length);
            Buffer.BlockCopy(result, 0, dataWithHeader, header.Length, result.Length);

            return dataWithHeader; //mantem como bytes
        }

        // descriptografa o texto com a chave carregada
        public string Decrypt(string encryptedText)
        {
            // remove o selo antes de converter de base64
            string base64Part = encryptedText.Substring(TextHeader.Length);
            byte[] encryptedBytes = Convert.FromBase64String(base64Part);

            byte[] result = new byte[encryptedBytes.Length];

            //verifica se a chave esta carregada
            if (key.Count == 0)
                throw new Exception("Chave vazia: carregamento falhou?");

            for (int i = 0; i < encryptedBytes.Length; i++)
            {
                byte encrypted = encryptedBytes[i];
                byte keyByte = key[i % key.Count];

                // subtrai o byte da chave do byte criptografado, ajusta com +256 e aplica % 256 para recuperar o original
                byte original = (byte)((256 + encrypted - keyByte) % 256);
                result[i] = original;
            }

            return Encoding.UTF8.GetString(result);
        }

        // para arquivos binarios pdf, img etc
        public byte[] Decrypt(byte[] encryptedData)
        {
            byte[] header = Encoding.UTF8.GetBytes(BinaryHeader);

            //verifica se a chave esta carregada
            if (key.Count == 0)
                throw new Exception("Chave vazia: carregamento falhou?");

            if (encryptedData.Length < header.Length)
                throw new Exception("Arquivo muito pequeno para conter dados criptografados.");

            // modificacao crítica - mantem verificacao
            bool isHeaderValid = true;
            for (int i = 0; i < header.Length; i++)
            {
                if (i >= encryptedData.Length || encryptedData[i] != header[i])
                {
                    isHeaderValid = false;
                    break;
                }
            }

            byte[] dataWithoutHeader;

            if (isHeaderValid)
            {
                // remove a assinatura do início do arquivo, preservando apenas os dados
                dataWithoutHeader = encryptedData.Skip(header.Length).ToArray();
            }
            else
            {
                // se nao tiver assinatura, assume que os dados já estão sem assinatura
                dataWithoutHeader = encryptedData;
            }

            byte[] result = new byte[dataWithoutHeader.Length];

            for (int i = 0; i < dataWithoutHeader.Length; i++)
            {
                byte encrypted = dataWithoutHeader[i];
                byte keyByte = key[i % key.Count];

                // reversao mantendo os valores entre 0-255
                byte original = (byte)((256 + encrypted - keyByte) % 256);

                result[i] = original;
            }

            return result; // retorna os bytes originais
        }
    }
}
