# CryptCS-Example

Exemplo simples de criptografia simétrica usando C# puro.  
Ideal para fins educacionais e aprendizado de manipulação de arquivos e bytes.

## Como a chave é gerada

- A chave é formada por caracteres aleatórios (ex: letras e números).
- O tamanho da chave é de 32 bytes.
- Ao ser salva em disco, ela inclui uma assinatura especial no início: `CRYPT::KEY`.
- Essa assinatura é usada para validar se o arquivo realmente é uma chave gerada pelo sistema.
- Ela é salva em um arquivo `.key`, que deve ser usado tanto na criptografia quanto na descriptografia.

---

## Como a criptografia funciona

- Cada byte do arquivo é criptografado com um byte da chave.
- A chave é repetida automaticamente caso o arquivo seja maior que ela.

- Para **criptografar**:
  - `150 + 200 = 350`
  - `350 % 256 = 94`
  - Resultado: byte criptografado é `94`

- Para **descriptografar**:
  - `94 - 200 = -106`
  - `-106 + 256 = 150`
  - Resultado: byte original recuperado é `150`

---

## Aviso

> Este projeto é apenas para fins **educacionais**.  
> **Não utilize em arquivos importantes ou sensíveis.**  
> O método aqui apresentado **não é seguro para uso real em produção**.
