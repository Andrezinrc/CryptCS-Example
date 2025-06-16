using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class CryptCS
{
    private List<byte> key;
    private const int KeySize = 32;
    private const string KeyHeader = "CRYPT::KEY"; //header da chave
    private const string TextHeader = "CRYPT::TEXT"; //header arquivo de texto
    private const string BinaryHeader = "CRYPT::BIN"; //header arquivos binario

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
            throw new Exception("Invalid or corrupted key!");

        // agora so a parte da chave é usada nos calculos
        key = new List<byte>(rawKey.Skip(KeyHeader.Length));

        //verificacao tamanho da chave
        if (key.Count < 32)
        {
            throw new Exception("Chave inválida: tamanho da chave criptográfica insuficiente");
        }
    }

    //verifica se um arquivo é binário com base na sua extensao
    public static bool IsBinaryFile(string filePath)
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
                        string response = Console.ReadLine()?.Trim().ToUpper();

                        if (response == "S")
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
                        bool isBinary = IsBinaryFile(file);

                        if (isBinary)
                        {
                            byte[] fileBytes = File.ReadAllBytes(file);

                            //verifica se já está criptografado
                            byte[] header = Encoding.UTF8.GetBytes(BinaryHeader);
                            bool alreadyEncrypted = fileBytes.Length >= header.Length &&
                                fileBytes.Take(header.Length).SequenceEqual(header);

                            if (alreadyEncrypted)
                            {
                                Console.WriteLine($"[IGNORADO] {file} já está criptografado (binário).");
                                continue;
                            }

                            byte[] encryptedBytes = crypt.Encrypt(fileBytes);
                            File.WriteAllBytes(file, encryptedBytes);
                            Console.WriteLine($"[OK] {file} criptografado (binário).");
                        }
                        else
                        {
                            string content = File.ReadAllText(file);

                            if (content.StartsWith(TextHeader))
                            {
                                Console.WriteLine($"[IGNORADO] {file} já está criptografado (texto).");
                                continue;
                            }

                            string encrypted = crypt.Encrypt(content);
                            File.WriteAllText(file, encrypted);
                            Console.WriteLine($"[OK] {file} criptografado (texto).");
                        }
                    }

                    Console.WriteLine("Todos os arquivos da pasta foram criptografados.");
                }
                else if (File.Exists(filePath))
                {
                    bool isBinary = IsBinaryFile(filePath);

                    if (isBinary)
                    {
                        byte[] fileBytes = File.ReadAllBytes(filePath);
                        byte[] encryptedBytes = crypt.Encrypt(fileBytes);
                        File.WriteAllBytes(filePath, encryptedBytes);
                        Console.WriteLine("Arquivo binário criptografado com sucesso!");
                    }
                    else
                    {
                        string originalContent = File.ReadAllText(filePath);

                        if (originalContent.StartsWith(TextHeader))
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
                            string response = Console.ReadLine()?.Trim().ToUpper();

                            if (response == "S")
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
                        Console.WriteLine("Arquivo de texto criptografado com sucesso!");
                    }
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
                        bool isBinary = IsBinaryFile(file);

                        if (isBinary)
                        {
                            byte[] fileBytes = File.ReadAllBytes(file);
                            byte[] header = Encoding.UTF8.GetBytes(BinaryHeader);

                            // verifica se o arquivo binário tem a header
                            bool hasHeader = fileBytes.Length >= header.Length &&
                                fileBytes.Take(header.Length).SequenceEqual(header);

                            if (!hasHeader)
                            {
                                Console.WriteLine($"[IGNORADO] {file} não parece estar criptografado (binário).");
                                continue;
                            }

                            // remove a header antes de descriptografar
                            byte[] realContent = fileBytes.Skip(header.Length).ToArray();

                            byte[] decryptedBytes = crypt.Decrypt(realContent);
                            File.WriteAllBytes(file, decryptedBytes);
                            Console.WriteLine($"[OK] {file} descriptografado (binário).");
                        }
                        else
                        {
                            string content = File.ReadAllText(file);

                            if (!content.StartsWith(TextHeader))
                            {
                                Console.WriteLine($"[IGNORADO] {file} não parece estar criptografado.");
                                continue;
                            }

                            string decrypted = crypt.Decrypt(content);
                            File.WriteAllText(file, decrypted);
                            Console.WriteLine($"[OK] {file} descriptografado (texto).");
                        }
                    }

                    Console.WriteLine("Todos os arquivos da pasta foram descriptografados.");
                }
                else if (File.Exists(filePath))
                {
                    bool isBinary = IsBinaryFile(filePath);

                    if (isBinary)
                    {
                        byte[] encryptedBytes = File.ReadAllBytes(filePath);
                        byte[] header = Encoding.UTF8.GetBytes(BinaryHeader);

                        // verifica se tem a header
                        if (encryptedBytes.Length >= header.Length && 
                            encryptedBytes.Take(header.Length).SequenceEqual(header))
                        {
                            try
                            {
                                // remove a header antes de descriptografar
                                byte[] contentWithoutHeader = encryptedBytes.Skip(header.Length).ToArray();
                                byte[] decryptedBytes = crypt.Decrypt(contentWithoutHeader);
                                File.WriteAllBytes(filePath, decryptedBytes);
                                Console.WriteLine("Arquivo binário descriptografado com sucesso!");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Erro ao descriptografar: {ex.Message}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Header inválida: o arquivo não está criptografado ou foi corrompido.");
                        }
                    }
                    else
                    {
                        string encryptedContent = File.ReadAllText(filePath);

                        if (!encryptedContent.StartsWith(TextHeader))
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
                        File.WriteAllText(filePath, originalText);
                        Console.WriteLine("Arquivo de texto descriptografado com sucesso!");
                    }
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