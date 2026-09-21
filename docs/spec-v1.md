# PrismKey V1 — Especificação funcional e técnica

## Escopo

O PrismKey V1 é uma aplicação desktop distribuída como CLI C++20. Ela calcula SHA-256 de arquivos, gera chaves RSA, assina arquivos e verifica assinaturas.

Comandos suportados:

- `prismkey hash <arquivo>`
- `prismkey keygen --public <arquivo.pem> --private <arquivo.pem>`
- `prismkey sign <arquivo> --key <privada.pem> --out <assinatura.sig>`
- `prismkey verify <arquivo> --signature <assinatura.sig> --key <publica.pem>`

## Requisitos técnicos

- SHA-256 é calculado em blocos, sem carregar todo o arquivo na memória.
- Chaves são RSA de 3072 bits em PEM. A chave privada é protegida por senha e a pública é exportada separadamente.
- Assinaturas usam RSA-PSS + SHA-256, são binárias e vinculam o conteúdo completo do arquivo.
- OpenSSL 3.x realiza todas as operações criptográficas; recursos são tratados por RAII e smart pointers.
- A CLI usa mensagens em português, retorna 0 em sucesso e valor diferente de 0 em falha.
- Senhas não são argumentos de linha de comando, não têm eco no terminal e não aparecem em mensagens ou logs.

## Decisões de segurança

Não há algoritmos criptográficos implementados manualmente. MD5, SHA-1, RSA PKCS#1 v1.5 e AES-ECB são proibidos. A V1 não implementa AES, pois não criptografa arquivos.

## Limitações da V1

Não inclui interface gráfica, criptografia AES de arquivos, banco de dados, armazenamento/gerenciamento de chaves, rede, envio de arquivos, telemetria ou formatos externos de assinatura. A assinatura binária é destinada ao fluxo PrismKey V1.

## Critérios de aceite

1. O hash de `abc` é `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
2. `keygen` cria PEM público e PEM privado RSA de 3072 bits protegido por senha.
3. Um arquivo assinado com a chave privada é validado pela chave pública correspondente.
4. Alterar o arquivo, alterar a assinatura ou usar chave pública diferente torna a validação inválida.
5. Arquivos inexistentes/ilegíveis, chaves inválidas, senha incorreta e argumentos ausentes resultam em erro claro e código diferente de 0.
6. A suíte GoogleTest cobre hash conhecido, geração de chaves, assinatura válida, adulteração e chave pública incorreta.
