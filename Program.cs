using System;
using System.IO;
using System.Text;
using FileCryptor;

namespace FileCryptor
{
    class Program
    {
        private static readonly string logFilePath = "crypt_log.txt";
        private const string Info = "INFO";
        private const string Error = "ERROR";

        //loga mensagens no arquivo, com as mais novas no topo
        private static void Log(string type, string message)
        {
            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{type}] {message}";

            // escreve no arquivo, colocando o novo log no topo
            try
            {
                string existingContent = string.Empty;

                // se o arquivo existe, le todo o conteudo atual
                if (File.Exists(logFilePath))
                {
                    existingContent = File.ReadAllText(logFilePath);
                }

                //escreve o novo log seguido do conteúdo existente
                File.WriteAllText(logFilePath, logMessage + Environment.NewLine + existingContent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOG ERROR] Failed to write log: {ex.Message}");
            }
        }

        public static void Main()
        {
            CryptCS crypt = new CryptCS();

            string title = "=== CryptCS ===";
            string currentDir = $"Diretório atual: {Directory.GetCurrentDirectory()}";
            string option1 = "1 - Criptografar arquivo";
            string option2 = "2 - Descriptografar arquivo";
            string chooseOption = "Escolha uma opção (1 ou 2): ";

            Console.WriteLine(title);
            Console.WriteLine(currentDir);
            Console.WriteLine(option1);
            Console.WriteLine(option2);
            Console.Write(chooseOption);

            string option = Console.ReadLine();

            string filePathPrompt = "Digite o caminho do arquivo (ex: arquivo.txt, imagem.jpeg): ";
            Console.Write(filePathPrompt);
            string filePath = Console.ReadLine();

            string keyPathPrompt = "Digite o caminho do arquivo de chave (.key): ";
            Console.Write(keyPathPrompt);
            string keyPath = Console.ReadLine();

            // verificação simples contra nulo ou vazio
            if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(keyPath))
            {
                string invalidPathMsg = "Caminho do arquivo ou da chave inválido.";
                Console.WriteLine(invalidPathMsg);
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
                                crypt.LoadKey(keyPath);
                                string msg = "Chave já existe. Usando a chave existente.";
                                Console.WriteLine(msg);
                                Log(Info, msg);
                            }
                            catch (Exception ex)
                            {
                                string errMsg = "Erro ao carregar a chave: " + ex.Message;
                                Console.WriteLine(errMsg);
                                Log(Error, errMsg);
                            }
                        }
                        else
                        {
                            string keyNotFoundMsg = "Arquivo de chave não encontrado. Deseja criar uma nova? (S/N): ";
                            Console.Write(keyNotFoundMsg);
                            string response = Console.ReadLine()?.Trim().ToUpper();

                            if (response == "S")
                            {
                                crypt.GenerateKey(keyPath); // cria nova chave se não existir
                                string newKeyMsg = "Nova chave gerada.";
                                Console.WriteLine(newKeyMsg);
                                Log(Info, newKeyMsg);
                            }
                            else
                            {
                                string operationCancelled = "Operação cancelada";
                                Console.WriteLine(operationCancelled);
                                Log(Info, operationCancelled);
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
                                    string ignoredBinaryMsg = $"[IGNORADO] {file} já está criptografado (binário).";
                                    Console.WriteLine(ignoredBinaryMsg);
                                    Log(Info, ignoredBinaryMsg);
                                    continue;
                                }

                                byte[] encryptedBytes = crypt.Encrypt(fileBytes);
                                File.WriteAllBytes(file, encryptedBytes);
                                string okBinaryMsg = $"[OK] {file} criptografado (binário).";
                                Console.WriteLine(okBinaryMsg);
                                Log(Info, okBinaryMsg);
                            }
                            else
                            {
                                string content = File.ReadAllText(file);

                                if (content.StartsWith(CryptCS.TextHeader))
                                {
                                    string ignoredTextMsg = $"[IGNORADO] {file} já está criptografado (texto).";
                                    Console.WriteLine(ignoredTextMsg);
                                    Log(Info, ignoredTextMsg);
                                    continue;
                                }

                                string encrypted = crypt.Encrypt(content);
                                File.WriteAllText(file, encrypted);
                                string okTextMsg = $"[OK] {file} criptografado (texto).";
                                Console.WriteLine(okTextMsg);
                                Log(Info, okTextMsg);
                            }
                        }

                        string allFilesEncrypted = "Todos os arquivos da pasta foram criptografados.";
                        Console.WriteLine(allFilesEncrypted);
                        Log(Info, allFilesEncrypted);
                    }
                    else if (File.Exists(filePath))
                    {
                        bool isBinary = crypt.IsBinaryFile(filePath);

                        if (isBinary)
                        {
                            byte[] fileBytes = File.ReadAllBytes(filePath);
                            byte[] encryptedBytes = crypt.Encrypt(fileBytes);
                            File.WriteAllBytes(filePath, encryptedBytes);
                            string binarySuccess = "Arquivo binário criptografado com sucesso!";
                            Console.WriteLine(binarySuccess);
                            Log(Info, binarySuccess);
                        }
                        else
                        {
                            string originalContent = File.ReadAllText(filePath);

                            if (originalContent.StartsWith(CryptCS.TextHeader))
                            {
                                string alreadyEncrypted = "O arquivo já está criptografado.";
                                Console.WriteLine(alreadyEncrypted);
                                Log(Info, alreadyEncrypted);
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
                                    string invalidKey = "Chave existente inválida ou corrompida.";
                                    Console.WriteLine(invalidKey);
                                    Log(Error, invalidKey);
                                    return;
                                }
                            }
                            else
                            {
                                string keyNotFound = "Arquivo de chave não encontrado. Deseja criar uma nova? (S/N): ";
                                Console.Write(keyNotFound);
                                string response = Console.ReadLine()?.Trim().ToUpper();

                                if (response == "S")
                                {
                                    crypt.GenerateKey(keyPath);
                                    string newKeyCreated = "Nova chave gerada.";
                                    Console.WriteLine(newKeyCreated);
                                    Log(Info, newKeyCreated);
                                }
                                else
                                {
                                    string userCancelled = "Operação cancelada pelo usuário.";
                                    Console.WriteLine(userCancelled);
                                    Log(Info, userCancelled);
                                    return;
                                }
                            }

                            string encrypted = crypt.Encrypt(originalContent);
                            File.WriteAllText(filePath, encrypted);
                            string textSuccess = "Arquivo de texto criptografado com sucesso!";
                            Console.WriteLine(textSuccess);
                            Log(Info, textSuccess);
                        }
                    }
                    else
                    {
                        string notFound = "Arquivo ou pasta não encontrados.";
                        Console.WriteLine(notFound);
                        Log(Error, notFound);
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
                                string invalidKey = "Chave existente inválida ou corrompida. Cancelando operação.";
                                Console.WriteLine(invalidKey);
                                Log(Error, invalidKey);
                                return;
                            }
                        }
                        else
                        {
                            string keyNotFound = "Arquivo de chave não encontrado. Cancelando operação.";
                            Console.WriteLine(keyNotFound);
                            Log(Error, keyNotFound);
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
                                    string ignoredBinary = $"[IGNORADO] {file} não parece estar criptografado (binário).";
                                    Console.WriteLine(ignoredBinary);
                                    Log(Info, ignoredBinary);
                                    continue;
                                }

                                // remove a header antes de descriptografar
                                byte[] realContent = fileBytes.Skip(header.Length).ToArray();

                                byte[] decryptedBytes = crypt.Decrypt(realContent);
                                File.WriteAllBytes(file, decryptedBytes);
                                string okBinary = $"[OK] {file} descriptografado (binário).";
                                Console.WriteLine(okBinary);
                                Log(Info, okBinary);
                            }
                            else
                            {
                                string content = File.ReadAllText(file);

                                if (!content.StartsWith(CryptCS.TextHeader))
                                {
                                    string ignoredText = $"[IGNORADO] {file} não parece estar criptografado.";
                                    Console.WriteLine(ignoredText);
                                    Log(Info, ignoredText);
                                    continue;
                                }

                                string decrypted = crypt.Decrypt(content);
                                File.WriteAllText(file, decrypted);
                                string okText = $"[OK] {file} descriptografado (texto).";
                                Console.WriteLine(okText);
                                Log(Info, okText);
                            }
                        }

                        string allFilesDecrypted = "Todos os arquivos da pasta foram descriptografados.";
                        Console.WriteLine(allFilesDecrypted);
                        Log(Info, allFilesDecrypted);
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
                                    string binarySuccess = "Arquivo binário descriptografado com sucesso!";
                                    Console.WriteLine(binarySuccess);
                                    Log(Info, binarySuccess);
                                }
                                catch (Exception ex)
                                {
                                    string decryptError = $"Erro ao descriptografar: {ex.Message}";
                                    Console.WriteLine(decryptError);
                                    Log(Error, decryptError);
                                }
                            }
                            else
                            {
                                string invalidHeader = "Header inválida: o arquivo não está criptografado ou foi corrompido.";
                                Console.WriteLine(invalidHeader);
                                Log(Error, invalidHeader);
                            }
                        }
                        else
                        {
                            string encryptedContent = File.ReadAllText(filePath);

                            if (!encryptedContent.StartsWith(CryptCS.TextHeader))
                            {
                                string notEncrypted = "O arquivo não parece estar criptografado.";
                                Console.WriteLine(notEncrypted);
                                Log(Info, notEncrypted);
                                return;
                            }

                            if (!File.Exists(keyPath))
                            {
                                string keyMissing = "Arquivo de chave não encontrado. Não é possível descriptografar.";
                                Console.WriteLine(keyMissing);
                                Log(Error, keyMissing);
                                return;
                            }

                            crypt.LoadKey(keyPath);
                            string originalText = crypt.Decrypt(encryptedContent);
                            File.WriteAllText(filePath, originalText);
                            string textSuccess = "Arquivo de texto descriptografado com sucesso!";
                            Console.WriteLine(textSuccess);
                            Log(Info, textSuccess);
                        }
                    }
                    else
                    {
                        string notFound = "Arquivo ou pasta não encontrados.";
                        Console.WriteLine(notFound);
                        Log(Error, notFound);
                    }
                }
                else
                {
                    string invalidOption = "Opção inválida. Digite 1 ou 2.";
                    Console.WriteLine(invalidOption);
                    Log(Error, invalidOption);
                }
            }
            catch (Exception ex)
            {
                string errorMsg = "Erro: " + ex.Message;
                Console.WriteLine(errorMsg);
                Log(Error, errorMsg);
            }
        }
    }
}