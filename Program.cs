using System;
using System.IO;
using System.Text;
using FileCryptor;

namespace FileCryptor
{
    class Program
    {
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
                            bool isBinary = crypt.IsBinaryFile(file);

                            if (isBinary)
                            {
                                byte[] fileBytes = File.ReadAllBytes(file);

                                //verifica se já está criptografado
                                byte[] header = Encoding.UTF8.GetBytes(CryptCS.BinaryHeader);
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

                                if (content.StartsWith(CryptCS.TextHeader))
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
                        bool isBinary = crypt.IsBinaryFile(filePath);

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

                            if (originalContent.StartsWith(CryptCS.TextHeader))
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
                            bool isBinary = crypt.IsBinaryFile(file);

                            if (isBinary)
                            {
                                byte[] fileBytes = File.ReadAllBytes(file);
                                byte[] header = Encoding.UTF8.GetBytes(CryptCS.BinaryHeader);

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

                                if (!content.StartsWith(CryptCS.TextHeader))
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
                        bool isBinary = crypt.IsBinaryFile(filePath);

                        if (isBinary)
                        {
                            byte[] encryptedBytes = File.ReadAllBytes(filePath);
                            byte[] header = Encoding.UTF8.GetBytes(CryptCS.BinaryHeader);

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

                            if (!encryptedContent.StartsWith(CryptCS.TextHeader))
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
}
