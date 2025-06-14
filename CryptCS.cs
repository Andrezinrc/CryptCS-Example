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

        //cria uma cópia da chave com a assinatura no início
        List<byte> chaveComAssinatura = new List<byte>();
        chaveComAssinatura.AddRange(Encoding.UTF8.GetBytes("CRIPTO1"));
        chaveComAssinatura.AddRange(key);
        File.WriteAllBytes(path, chaveComAssinatura.ToArray());
    }

    // carrega chave de um arquivo
    public void LoadKey(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Arquivo de chave não encontrado.");
        }

        byte[] rawKey = File.ReadAllBytes(path);

        if (rawKey.Length < 7)
        {
            throw new Exception("Chave inválida: tamanho insuficiente");
        }

        // verifica a assinatura
        string assinatura = Encoding.UTF8.GetString(rawKey.Take(7).ToArray());
        if (assinatura != "CRIPTO1")
            throw new Exception("Chave inválida ou corrompida!");

        key = new List<byte>(rawKey.Skip(7));

        //verificacao tamanho da chave
        if (key.Count < 32)
        {
            throw new Exception("Chave inválida: tamanho da chave criptográfica insuficiente");
        }
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
        return "CRYPTED::" + Convert.ToBase64String(result);
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
        // remove o selo antes de converter de base64
        string base64Part = encryptedText.Substring("CRYPTED::".Length);
        byte[] encryptedBytes = Convert.FromBase64String(base64Part);

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

        Console.WriteLine("=== CryptCS ===");
        Console.WriteLine($"Diretório atual: {Directory.GetCurrentDirectory()}");
        Console.WriteLine("1 - Criptografar arquivo");
        Console.WriteLine("2 - Descriptografar arquivo");
        Console.Write("Escolha uma opção (1 ou 2): ");

        string option = Console.ReadLine();

        Console.Write("Digite o caminho do arquivo (ex: arquivo.txt, imagem.jpeg): ");
        string filePath = Console.ReadLine();

        Console.Write("Digite o caminho do arquivo de chave (.key): ");
        string keyPath = Console.ReadLine();

        // verificação simples contra nulo ou vazio
        if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(keyPath))
        {
            Console.WriteLine("Caminho do arquivo ou da chave inválido.");
            return;
        }

        try
        {
            if (option == "1")
            {
                // criptografar
                // verifica se é pasta ou arquivo
                if (Directory.Exists(filePath))
                {
                    if (File.Exists(keyPath))
                    {
                        try
                        {
                            crypt.LoadKey(keyPath); // tenta carregar e validar a chave existente
                            Console.WriteLine("Chave já existe. Usando a chave existente.");
                        }
                        catch
                        {
                            Console.WriteLine("Chave existente inválida ou corrompida");
                            return;
                        }
                    }
                    else
                    {
                        Console.Write("Arquivo de chave não encontrado. Deseja criar uma nova? (S/N): ");
                        string resposta = Console.ReadLine()?.Trim().ToUpper();

                        if (resposta == "S")
                        {
                            crypt.GenerateKey(keyPath); // cria nova chave se não existir
                            Console.WriteLine("Nova chave gerada.");
                        }
                        else
                        {
                            Console.WriteLine("Operação cancelada");
                            return;
                        }
                    }

                    string[] files = Directory.GetFiles(filePath, "*", SearchOption.AllDirectories);
                    foreach (string file in files)
                    {
                        string content = File.ReadAllText(file);

                        if (content.StartsWith("CRYPTED::"))
                        {
                            Console.WriteLine($"[IGNORADO] {file} já está criptografado.");
                            continue;
                        }

                        string encrypted = crypt.Encrypt(content);
                        File.WriteAllText(file, encrypted);
                        Console.WriteLine($"[OK] {file} criptografado.");
                    }

                    Console.WriteLine("Todos os arquivos da pasta foram criptografados.");
                }
                else if (File.Exists(filePath))
                {
                    string originalContent = File.ReadAllText(filePath);

                    if (originalContent.StartsWith("CRYPTED::"))
                    {
                        Console.WriteLine("O arquivo já está criptografado.");
                        return;
                    }

                    if (File.Exists(keyPath))
                    {
                        try
                        {
                            crypt.LoadKey(keyPath);
                        }
                        catch
                        {
                            Console.WriteLine("Chave existente inválida ou corrompida.");
                            return;
                        }
                    }
                    else
                    {
                        Console.Write("Arquivo de chave não encontrado. Deseja criar uma nova? (S/N): ");
                        string resposta = Console.ReadLine()?.Trim().ToUpper();

                        if (resposta == "S")
                        {
                            crypt.GenerateKey(keyPath);
                            Console.WriteLine("Nova chave gerada.");
                        }
                        else
                        {
                            Console.WriteLine("Operação cancelada pelo usuário.");
                            return;
                        }
                    }

                    string encrypted = crypt.Encrypt(originalContent);
                    File.WriteAllText(filePath, encrypted);
                    Console.WriteLine("Arquivo criptografado com sucesso!");
                }
                else
                {
                    Console.WriteLine("Arquivo ou pasta não encontrados.");
                }
            }
            else if (option == "2")
            {
                // descriptografar
                if (Directory.Exists(filePath))
                {
                    if (File.Exists(keyPath))
                    {
                        try
                        {
                            crypt.LoadKey(keyPath);
                        }
                        catch
                        {
                            Console.WriteLine("Chave existente inválida ou corrompida. Cancelando operação.");
                            return;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Arquivo de chave não encontrado. Cancelando operação.");
                        return;
                    }
                    string[] files = Directory.GetFiles(filePath, "*", SearchOption.AllDirectories);
                    foreach (string file in files)
                    {
                        string content = File.ReadAllText(file);

                        if (!content.StartsWith("CRYPTED::"))
                        {
                            Console.WriteLine($"[IGNORADO] {file} não parece estar criptografado.");
                            continue;
                        }

                        string decrypted = crypt.Decrypt(content);
                        File.WriteAllText(file, decrypted);
                        Console.WriteLine($"[OK] {file} descriptografado.");
                    }

                    Console.WriteLine("Todos os arquivos da pasta foram descriptografados.");
                }
                else if (File.Exists(filePath))
                {
                    string encryptedContent = File.ReadAllText(filePath);

                    if (!encryptedContent.StartsWith("CRYPTED::"))
                    {
                        Console.WriteLine("O arquivo não parece estar criptografado.");
                        return;
                    }

                    if (!File.Exists(keyPath))
                    {
                        Console.WriteLine("Arquivo de chave não encontrado. Não é possível descriptografar.");
                        return;
                    }

                    crypt.LoadKey(keyPath);
                    string originalText = crypt.Decrypt(encryptedContent);
                    File.WriteAllText(filePath, originalText); // sobrescreve o original
                    Console.WriteLine("Arquivo descriptografado com sucesso!");
                }
                else
                {
                    Console.WriteLine("Arquivo ou pasta não encontrados.");
                }
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
