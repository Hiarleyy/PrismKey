# Serviço de chaves

## `include/crypto/KeyService.hpp`

`KeyAlgorithm` seleciona `Rsa` ou `Ed25519`. `PublicKeyDetails` é a resposta da inspeção: nome do algoritmo, tamanho retornado pelo OpenSSL e fingerprint SHA-256 do arquivo PEM público.

`generateRsaKeyPair` é uma fachada para compatibilidade; `generateKeyPair` é a operação geral. `inspectPublicKey` lê e classifica uma chave pública PEM.

## `src/crypto/KeyService.cpp`

Os aliases internos `KeyContext`, `Key` e `Bio` aplicam RAII aos objetos OpenSSL. `isRsa` e `isEd25519` verificam o identificador base da chave, evitando aceitar outros tipos PEM por acidente.

`inspectPublicKey` abre o PEM por BIO e usa `PEM_read_bio_PUBKEY`. Recusa uma leitura malformada e algoritmos diferentes de RSA/Ed25519 com `InvalidKey`. Em seguida, lê os bytes do PEM e calcula SHA-256 diretamente sobre sua serialização para formar a fingerprint hexadecimal. Logo, uma reserialização equivalente da mesma chave pode mudar a fingerprint. Retorna também `EVP_PKEY_bits`; para Ed25519 esse campo depende da semântica fornecida pelo OpenSSL.

`generateRsaKeyPair` somente chama `generateKeyPair` com `KeyAlgorithm::Rsa`.

`generateKeyPair` valida primeiro senha não vazia e caminhos distintos. Depois calcula os destinos com `ProjectStorage`, cria as pastas `keys/public` e `keys/private`, cria um contexto EVP do algoritmo pedido e inicializa a geração. Para RSA fixa 3072 bits; Ed25519 não aceita essa configuração e usa a geração nativa. Após conferir que o objeto produzido é do tipo solicitado, grava:

- a chave pública em PEM com `PEM_write_bio_PUBKEY`;
- a chave privada em PEM cifrada por AES-256-CBC via `PEM_write_bio_PrivateKey` e a senha recebida.

Cada abertura, geração ou gravação malsucedida se converte em `Result<void>` com a classificação apropriada. Uma falha depois de gravar a chave pública pode deixar esse arquivo no disco sem a correspondente privada; o método não implementa rollback.
