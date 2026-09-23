# Construção e interface gráfica

Na raiz do projeto, instale as dependências de manifesto e configure o CMake com o toolchain do vcpkg:

```powershell
.\vcpkg\vcpkg.exe install --triplet x64-windows
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=.\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Debug --target prismkey prismkey_gui
```

Para abrir a aplicação Qt:

```powershell
.\build\Debug\prismkey_gui.exe
```

Ela oferece as abas Hash, Gerar chaves, Assinar, Verificar e Download. Senhas são inseridas somente em campos mascarados e não são exibidas nas mensagens de resultado.

# Uso da CLI PrismKey

Todos os comandos retornam `0` quando concluídos com sucesso e valor diferente de `0` quando ocorre erro.

## Hash de arquivo

```powershell
prismkey hash .\contrato.pdf
prismkey hash .\contrato.pdf --algorithm SHA3-256
```

Os algoritmos aceitos são `SHA256`, `SHA512`, `SHA3-256` e `BLAKE2b512`.

## Gerar chaves RSA ou Ed25519

```powershell
prismkey keygen --public .\chave-publica.pem --private .\chave-privada.pem
prismkey keygen --algorithm ED25519 --public .\chave-publica.pem --private .\chave-privada.pem
```

RSA é o padrão quando `--algorithm` é omitido. O programa solicita e confirma a senha da chave privada sem exibi-la. Nunca passe a senha na linha de comando.

## Assinar um arquivo

```powershell
prismkey sign .\contrato.pdf --key .\chave-privada.pem --out .\contrato.sig
```

O programa solicita a senha da chave privada e cria uma assinatura binária em `contrato.sig`.

## Verificar uma assinatura

```powershell
prismkey verify .\contrato.pdf --signature .\contrato.sig --key .\chave-publica.pem
```

Saída esperada: `Assinatura válida. Algoritmo: ... | Timestamp UTC: ...`. Se o arquivo for alterado, a assinatura for corrompida ou a chave pública não corresponder, o comando informa que a assinatura é inválida e retorna erro. Assinaturas RSA antigas continuam válidas, mas são identificadas como legadas e sem timestamp.

O timestamp é um registro local em UTC protegido pela assinatura. Ele não é uma certificação de tempo por uma TSA (Time Stamping Authority) nem prova que terceiros atestaram aquele horário.

## Baixar e validar por hash

```powershell
prismkey download https://exemplo.com/arquivo.zip --out .\arquivo.zip --hash <hash-em-hexadecimal> --algorithm SHA-256
```

São aceitos `SHA-256`, `SHA-512`, `SHA3-256` e `BLAKE2b-512`. A URL deve usar HTTPS e o hash é comparado sem diferenciar maiúsculas de minúsculas. O arquivo de destino só é disponibilizado quando a transferência, o certificado TLS e o hash forem válidos; falhas removem o temporário.

## Erros comuns

- Caminho inexistente ou sem leitura: confira o caminho e as permissões.
- Senha incorreta ou chave privada inválida: use a chave e a senha corretas; a senha nunca será mostrada.
- Argumentos ausentes: execute o programa sem argumentos para ver a sintaxe aceita.
- URL HTTP, certificado TLS inválido ou hash divergente: confirme a URL HTTPS e o hash publicado pela fonte confiável; nenhum arquivo validado será disponibilizado.
