<p align="center">
  <img src="assets/icons/prismkey.png" alt="Logo do PrismKey" width="170">
</p>

<h1 align="center">PrismKey</h1>

<p align="center">
  Aplicacao Windows para calcular hashes SHA-256, gerar chaves RSA, assinar arquivos e verificar assinaturas digitais.
</p>

## Download

Baixe a versao mais recente para Windows em [GitHub Releases](https://github.com/Hiarleyy/PrismKey/releases/latest). O arquivo `PrismKey-0.1.0-windows-x64.zip` e portatil: extraia-o e abra `PrismKey.exe`. Nao e necessaria instalacao.

O pacote tambem inclui `prismkey.exe`, a versao de linha de comando, e `HELLO_WORLD.txt`. O Windows pode exibir um aviso de seguranca para executaveis que ainda nao possuem assinatura de codigo; use apenas o arquivo baixado da pagina oficial de Releases.

## Recursos

- Hash SHA-256 de arquivos
- Geracao de chaves RSA protegidas por senha
- Assinatura digital RSA-PSS/SHA-256 e verificacao de assinaturas
- Interface grafica Qt: **Hash**, **Gerar chaves**, **Assinar** e **Verificar**
- CLI `prismkey` independente da interface grafica

## Executar

Depois de extrair o ZIP, execute `PrismKey.exe`. Mantenha todos os arquivos e pastas extraidos juntos, pois eles contem as dependencias da aplicacao.

### Linha de comando

```powershell
.\prismkey.exe hash .\documento.pdf
.\prismkey.exe keygen --public .\chave-publica.pem --private .\chave-privada.pem
.\prismkey.exe sign .\documento.pdf --key .\chave-privada.pem --out .\documento.sig
.\prismkey.exe verify .\documento.pdf --signature .\documento.sig --key .\chave-publica.pem
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

Para gerar o mesmo ZIP distribuivel localmente:

```powershell
.\scripts\package-windows.ps1
```

## Licenca

[MIT](LICENSE)
