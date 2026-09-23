# `tests/CryptoServicesTests.cpp` — testes automatizados

O arquivo usa GoogleTest e OpenSSL para validar o contrato externo dos serviços. `CryptoServicesTest` é uma fixture: em `SetUp`, cria uma pasta temporária única, muda o diretório atual para ela, gera um par RSA protegido por `senha-de-teste` e atualiza os caminhos para os destinos reais de `ProjectStorage`. Em `TearDown`, restaura o diretório anterior e apaga recursivamente a pasta temporária. `writeFile` grava conteúdo binário de apoio.

Casos cobertos:

- `CalculatesKnownSha256`: usa o vetor conhecido de SHA-256 para `abc` e confere o hexato de 64 caracteres.
- `GeneratesLoadableEncryptedPemKeys`: relê privada e pública com a API PEM do OpenSSL, usando a senha, e confirma RSA de 3072 bits.
- `SignsAndVerifiesFile`: estabelece o caminho feliz de uma assinatura RSA.
- `RejectsModifiedFile`: muda o conteúdo depois da assinatura e espera `InvalidSignature`.
- `RejectsDifferentPublicKey`: gera outro par e confirma que a pública errada não valida.
- `SignsAndVerifiesEd25519WithTimestamp`: gera Ed25519, verifica o formato novo, algoritmo, ausência de legado e final `Z` no timestamp.
- `RejectsModifiedTimestampEnvelope`: sobrescreve um byte do timestamp no offset 11 (depois de magic, algoritmo e tamanho) e espera falha, comprovando que o timestamp faz parte dos dados assinados.

Os testes verificam os principais fluxos criptográficos, mas não cobrem HashService com algoritmos alternativos, colisões de armazenamento, interface Qt ou operações em lote.
