using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class CryptCS
{
    private List<byte> key;
    private const int KeySize = 32;

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

        File.WriteAllBytes(path, key.ToArray());
    }

    // carrega chave de um arquivo
    public void LoadKey(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Arquivo de chave não encontrado.");
        }

        key = new List<byte>(File.ReadAllBytes(path));
    }

    // criptografa o texto com a chave carregada
    public string Encrypt(string text)
    {
        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        byte[] result = new byte[textBytes.Length];

        for (int i = 0; i < textBytes.Length; i++)
        {
            byte original = textBytes[i];
            byte keyByte = key[i % key.Count];

            // soma o byte do conteudo com o byte da chave e aplica % 256 para manter no intervalo de 0–255
            byte encrypted = (byte)((original + keyByte) % 256);
            result[i] = encrypted;
        }
        
        //armazena como texto
        return Convert.ToBase64String(result);
    }

    // para arquivos binarios img, pdf etc
    public byte[] Encrypt(byte[] data)
    {
        byte[] result = new byte[data.Length];

        for (int i = 0; i < data.Length; i++)
        {
            byte original = data[i];
            byte keyByte = key[i % key.Count];
            byte encrypted = (byte)((original + keyByte) % 256);
            result[i] = encrypted;
        }

        return result; //mantem como bytes
    }

    // descriptografa o texto com a chave carregada
    public string Decrypt(string encryptedText)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
        byte[] result = new byte[encryptedBytes.Length];

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
        byte[] result = new byte[encryptedData.Length];

        for (int i = 0; i < encryptedData.Length; i++)
        {
            byte encrypted = encryptedData[i];
            byte keyByte = key[i % key.Count];
            byte original = (byte)((256 + encrypted - keyByte) % 256);
            result[i] = original;
        }

        return result; // retorna os bytes originais
    }

    public static void Main()
    {
        CryptCS crypt = new CryptCS();

        Console.WriteLine("=== CriptoSimples ===");
        Console.WriteLine("Diretório atual: " + Directory.GetCurrentDirectory());
        Console.WriteLine("1 - Criptografar arquivo");
        Console.WriteLine("2 - Descriptografar arquivo");
        Console.Write("Escolha uma opção: ");
        string option = Console.ReadLine();

        Console.Write("Digite o caminho do arquivo (ex: arquivo.txt, imagem.jpeg): ");
        string filePath = Console.ReadLine();

        Console.Write("Digite o caminho do arquivo de chave (.key): ");
        string keyPath = Console.ReadLine();

        try
        {
            if (option == "1")
            {
                // criptografar
                string originalContent = File.ReadAllText(filePath);
                crypt.GenerateKey(keyPath);
                string encrypted = crypt.Encrypt(originalContent);
                File.WriteAllText(filePath, encrypted); // sobrescreve o original
                Console.WriteLine("Arquivo criptografado com sucesso!");
            }
            else if (option == "2")
            {
                // descriptografar
                crypt.LoadKey(keyPath);
                string encryptedContent = File.ReadAllText(filePath);
                string originalText = crypt.Decrypt(encryptedContent);
                File.WriteAllText(filePath, originalText);
                Console.WriteLine("Arquivo descriptografado com sucesso!");
            }
            else
            {
                Console.WriteLine("Opção inválida. Digite 1 ou 2.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro: " + ex.Message);
        }
    }
}