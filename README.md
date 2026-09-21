
<p align="center">
  <img width="200" height="200" alt="Prismkey-removebg-preview" src="https://github.com/user-attachments/assets/a8ffbc89-a2ea-448d-8a40-f4b2b57b4cb1" />

</p>

<h1 align="center">PrismKey</h1>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-2f80ed?style=flat-square" alt="Versão 0.1.0">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4caf50?style=flat-square" alt="Licença MIT"></a>
  <img src="https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square" alt="Plataforma Windows">
  <img src="https://img.shields.io/badge/C%2B%2B-20-00599c?style=flat-square" alt="C++20">
  <img src="https://img.shields.io/badge/Qt-6-41cd52?style=flat-square" alt="Qt 6">
</p>

<p align="center">
Aplicação desktop e linha de comando para calcular hashes SHA-256, gerar chaves RSA, assinar arquivos e verificar assinaturas digitais.
  Aplicação local para calcular hashes SHA-256, gerar chaves RSA, assinar arquivos e verificar assinaturas digitais.
</p>

## Recursos

- Hash SHA-256 de arquivos
- Geração de chaves RSA protegidas por senha
- Assinatura digital RSA-PSS/SHA-256 e verificação de assinaturas
- Interface gráfica Qt: **Hash**, **Gerar chaves**, **Assinar** e **Verificar**
- CLI `prismkey` independente da interface gráfica

## Pré-requisitos

- CMake 3.21 ou superior
- Compilador C++20
- Qt 6 Widgets
- vcpkg

O projeto foi configurado com o kit **Qt 6 MinGW 64-bit**. O Qt e as dependências do vcpkg devem usar o mesmo compilador.

## Configuração

### 1. Dependências

Na raiz do projeto, instale as dependências para o kit Qt MinGW:

```powershell
.\vcpkg\vcpkg.exe install --triplet x64-mingw-dynamic
```

### 2. Caminho do Qt

No Qt Creator, abra **Edit > Preferences > Kits**, selecione o kit Desktop MinGW 64-bit e copie o caminho do Qt. Exemplo:

```text
C:\Qt\6.11.2\mingw_64
```

### 3. Configurar o CMake

Substitua o caminho de `CMAKE_PREFIX_PATH` pelo diretório do Qt instalado:

```powershell
cmake -S . -B build-mingw -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug `
  -DCMAKE_TOOLCHAIN_FILE=E:\PrismKey\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-mingw-dynamic `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.11.2\mingw_64"
```

## Compilar

Compile a CLI e a interface gráfica:

```powershell
cmake --build build-mingw --target prismkey prismkey_gui
```

Para compilar e executar os testes:

```powershell
cmake --build build-mingw
ctest --test-dir build-mingw --output-on-failure
```

## Executar

### Interface gráfica

```powershell
.\build-mingw\prismkey_gui.exe
```

Se houver erro de DLL na primeira execução fora do Qt Creator, distribua as dependências do Qt e do MinGW:

```powershell
& "C:\Qt\6.11.2\mingw_64\bin\windeployqt.exe" --compiler-runtime --no-translations .\build-mingw\prismkey_gui.exe
```

### Linha de comando

```powershell
.\build-mingw\prismkey.exe
```

## Guia da interface gráfica

1. **Hash**: selecione um arquivo e clique em **Calcular SHA-256**.
2. **Gerar chaves**: escolha destinos diferentes para as chaves pública e privada, informe e confirme a senha, depois clique em **Gerar chaves RSA**.
3. **Assinar**: escolha o arquivo, a chave privada e o destino da assinatura (por exemplo, `documento.sig`), informe a senha e clique em **Assinar arquivo**. O `.sig` é criado no destino escolhido.
4. **Verificar**: informe o arquivo original, a assinatura `.sig` e a chave pública; clique em **Verificar assinatura**.

Senhas usam campos mascarados e são limpas após gerar chaves ou assinar.

## Guia da CLI

### Calcular hash

```powershell
.\build-mingw\prismkey.exe hash .\documento.pdf
```

### Gerar chaves

```powershell
.\build-mingw\prismkey.exe keygen --public .\chave-publica.pem --private .\chave-privada.pem
```

### Assinar

```powershell
.\build-mingw\prismkey.exe sign .\documento.pdf --key .\chave-privada.pem --out .\documento.sig
```

### Verificar

```powershell
.\build-mingw\prismkey.exe verify .\documento.pdf --signature .\documento.sig --key .\chave-publica.pem
```
