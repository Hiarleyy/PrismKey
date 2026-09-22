<p align="center">
  <img src="assets/icons/prismkey.png" alt="Logo do PrismKey" width="170">
</p>

<h1 align="center">PrismKey</h1>

<p align="center">
  Aplicacao Windows para calcular hashes SHA-256, gerar chaves RSA, assinar arquivos e verificar assinaturas digitais.
</p>

## Download

Baixe a versao mais recente para Windows em [GitHub Releases](https://github.com/Hiarleyy/PrismKey/releases/latest). O arquivo `PrismKey-0.1.1-windows-x64.zip` e portatil: extraia-o e abra `PrismKey.exe`.

O pacote inclui a interface grafica (`PrismKey.exe`), a CLI (`PrismKey-cli.exe`) e `HELLO_WORLD.txt`. Mantenha todos os arquivos extraidos juntos. O Windows pode exibir um aviso para executaveis sem assinatura de codigo; baixe somente da pagina oficial de Releases.

## Recursos

- Hash SHA-256 de arquivos
- Geracao de chaves RSA protegidas por senha
- Assinatura digital RSA-PSS/SHA-256 e verificacao de assinaturas
- Interface grafica Qt: **Hash**, **Gerar chaves**, **Assinar** e **Verificar**
- CLI `prismkey` independente da interface grafica

## Linha de comando

```powershell
.\PrismKey-cli.exe hash .\documento.pdf
.\PrismKey-cli.exe keygen --public .\chave-publica.pem --private .\chave-privada.pem
.\PrismKey-cli.exe sign .\documento.pdf --key .\chave-privada.pem --out .\documento.sig
.\PrismKey-cli.exe verify .\documento.pdf --signature .\documento.sig --key .\chave-publica.pem
```

## Compilar a partir do codigo-fonte

Requisitos: CMake 3.21+, compilador C++20, Qt 6 Widgets e vcpkg. Qt e vcpkg devem usar o mesmo compilador.

```powershell
.\vcpkg\vcpkg.exe install --triplet x64-mingw-dynamic
cmake -S . -B build-mingw -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE=E:\PrismKey\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-mingw-dynamic `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.11.2\mingw_64"
cmake --build build-mingw
ctest --test-dir build-mingw --output-on-failure
```

Para gerar o ZIP distribuivel localmente:

```powershell
.\scripts\package-windows.ps1
```

## Licenca

[MIT](LICENSE)
