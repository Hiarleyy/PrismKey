<p align="center">
  <img src="assets/icons/prismkey.png" alt="Logo do PrismKey" width="170">
</p>

<h1 align="center">PrismKey</h1>

<p align="center">
  Aplicacao Windows para calcular hashes, gerar chaves RSA ou Ed25519, assinar arquivos e validar downloads HTTPS.
</p>

## Download

Baixe a versao mais recente para Windows em [GitHub Releases](https://github.com/Hiarleyy/PrismKey/releases/latest). O arquivo `PrismKey-0.1.1-windows-x64.zip` e portatil: extraia-o e abra `PrismKey.exe`.

O pacote inclui a interface grafica (`PrismKey.exe`), a CLI (`PrismKey-cli.exe`) e `HELLO_WORLD.txt`. Mantenha todos os arquivos extraidos juntos. O Windows pode exibir um aviso para executaveis sem assinatura de codigo; baixe somente da pagina oficial de Releases.

## Recursos

- Hashes SHA-256, SHA-512, SHA3-256 e BLAKE2b-512
- Geracao de chaves RSA ou Ed25519 protegidas por senha
- Assinatura digital RSA-PSS/SHA-256 ou Ed25519, com registro local em UTC
- Download HTTPS validado por hash, sem publicar arquivos que falhem na validacao
- Interface grafica Qt: **Hash**, **Gerar chaves**, **Assinar**, **Verificar** e **Download**
- CLI `prismkey` independente da interface grafica

## Linha de comando

```powershell
.\PrismKey-cli.exe hash .\documento.pdf
.\PrismKey-cli.exe keygen --algorithm ED25519 --public .\chave-publica.pem --private .\chave-privada.pem
.\PrismKey-cli.exe sign .\documento.pdf --key .\chave-privada.pem --out .\documento.sig
.\PrismKey-cli.exe verify .\documento.pdf --signature .\documento.sig --key .\chave-publica.pem
.\PrismKey-cli.exe download https://exemplo.com/arquivo.zip --out .\arquivo.zip --hash <hash-em-hexadecimal> --algorithm SHA-256
```

O timestamp apresentado em `verify` e um registro local em UTC autenticado pela assinatura. Ele nao e uma certificacao de tempo por terceiros (TSA).

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
