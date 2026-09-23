# Serviço de hash

## `include/crypto/HashService.hpp`

Declara uma classe de métodos estáticos, sem estado. `file(caminho, algoritmo)` retorna a representação hexadecimal do digest solicitado; `sha256File(caminho)` é o atalho compatível que fixa `SHA256`.

## `src/crypto/HashService.cpp`

`DigestContext` é um `unique_ptr` para `EVP_MD_CTX`, com `EVP_MD_CTX_free` como desalocador. O contexto OpenSSL é liberado inclusive em qualquer retorno de erro.

`HashService::file` executa a sequência abaixo:

1. Abre o arquivo em modo binário. Se falhar, consulta a existência do caminho para diferenciar `FileNotFound` de `FileNotReadable`.
2. Resolve o nome do algoritmo por `EVP_get_digestbyname`. A [[cli]] e a GUI oferecem `SHA256`, `SHA512`, `SHA3-256` e `BLAKE2b512`; OpenSSL decide quais nomes estão disponíveis. Um nome desconhecido resulta em `InvalidArgument`.
3. Cria e inicializa o contexto EVP. Falha nessa etapa é `CryptoError`.
4. Lê blocos de 64 KiB e passa exatamente `gcount()` bytes de cada bloco para `EVP_DigestUpdate`. Isso torna o consumo de memória constante mesmo para arquivos grandes.
5. Se a leitura terminou por erro, e não por EOF, retorna `FileNotReadable`.
6. Finaliza o digest em um buffer do tamanho máximo permitido por EVP e converte cada byte para duas casas hexadecimais, com zero à esquerda.

`sha256File` apenas delega para `file(file, "SHA256")`; ela existe para uma API simples e para o teste do vetor conhecido `abc`.
