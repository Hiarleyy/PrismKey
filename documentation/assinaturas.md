# Serviço de assinatura digital

## `include/crypto/SignatureService.hpp`

`SignatureDetails` acrescenta metadados à verificação: algoritmo efetivo, timestamp UTC e indicador `legacy`. `signFile` cria uma assinatura; `verifyFileDetails` verifica e entrega os metadados; `verifyFile` é uma fachada que descarta esses detalhes.

## `src/crypto/SignatureService.cpp`

Os aliases RAII `Key`, `Bio` e `Ctx` administram objetos OpenSSL. `rsa` e `ed` aceitam somente os dois algoritmos suportados. `bytes` lê integralmente um arquivo em binário e distingue ausência de problema de leitura.

Para RSA, `pss` configura padding RSA-PSS. Ao assinar, o salt tem tamanho igual ao digest SHA-256; ao verificar, OpenSSL aceita o salt presente na assinatura (`RSA_PSS_SALTLEN_AUTO`). Para Ed25519, a API EVP recebe digest nulo, como exige esse algoritmo.

### Envelope atual de `.sig`

O arquivo salvo não é apenas a assinatura crua:

```text
PKSIG001 (8 bytes) | algoritmo (1) | tamanho UTC, big-endian (2) | UTC | assinatura
```

`algoritmo` vale `1` para RSA-PSS/SHA-256 e `2` para Ed25519. O dado efetivamente assinado é outro envelope: `"PrismKey-v1\0"`, algoritmo, tamanho do timestamp, timestamp e bytes originais do arquivo. Desse modo, alterar data, algoritmo ou conteúdo invalida a verificação. O timestamp é ISO-8601 em UTC, por exemplo `2026-09-23T12:34:56Z`.

`signFile` carrega a chave privada PEM com a senha, rejeita chave inválida como `IncorrectPassword`, lê o arquivo, monta o envelope, assina e grava no diretório `signatures`, usando apenas o nome de `outputSignature`.

`verifyFileDetails` carrega a chave pública, lê arquivo e `.sig`, e então escolhe o formato. Se o magic não existir, trata o conteúdo como assinatura legada crua RSA-PSS/SHA-256; ela não contém data e só aceita chave RSA. No formato atual, valida tamanho mínimo, algoritmo, comprimento do timestamp e compatibilidade entre algoritmo e chave antes de reconstruir o dado e chamar `EVP_DigestVerify`. Só uma verificação bem-sucedida devolve detalhes confiáveis.

`verifyFile` preserva código e mensagem de qualquer falha de `verifyFileDetails`, mas omite os metadados para chamadas que só precisam do resultado booleano.
