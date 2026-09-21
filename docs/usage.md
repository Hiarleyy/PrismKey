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

Ela oferece as abas Hash, Gerar chaves, Assinar e Verificar. Senhas são inseridas somente em campos mascarados e não são exibidas nas mensagens de resultado.

# Uso da CLI PrismKey

Todos os comandos retornam `0` quando concluídos com sucesso e valor diferente de `0` quando ocorre erro.

## Hash SHA-256

```powershell
prismkey hash .\contrato.pdf
```

Saída esperada: `SHA-256: <hash-em-hexadecimal>`.

## Gerar chaves RSA

```powershell
prismkey keygen --public .\chave-publica.pem --private .\chave-privada.pem
```

O programa solicita e confirma a senha da chave privada sem exibi-la. Nunca passe a senha na linha de comando.

## Assinar um arquivo

```powershell
prismkey sign .\contrato.pdf --key .\chave-privada.pem --out .\contrato.sig
```

O programa solicita a senha da chave privada e cria uma assinatura binária em `contrato.sig`.

## Verificar uma assinatura

```powershell
prismkey verify .\contrato.pdf --signature .\contrato.sig --key .\chave-publica.pem
```

Saída esperada: `Assinatura válida.` Se o arquivo for alterado, a assinatura for corrompida ou a chave pública não corresponder, o comando informa que a assinatura é inválida e retorna erro.

## Erros comuns

- Caminho inexistente ou sem leitura: confira o caminho e as permissões.
- Senha incorreta ou chave privada inválida: use a chave e a senha corretas; a senha nunca será mostrada.
- Argumentos ausentes: execute o programa sem argumentos para ver a sintaxe aceita.
