# Recursos e pacote Windows

## `assets/prismkey.qrc`

É o manifesto de recursos Qt. Declara o prefixo `/icons` e incorpora `assets/icons/prismkey.png` com o alias `prismkey.png`. Após o `AUTORCC`, a GUI pode usá-lo pelo caminho virtual `:/icons/prismkey.png`, sem depender de um PNG ao lado do executável.

## `assets/prismkey.rc`

É um recurso nativo Windows. Associa o identificador `IDI_PRISMKEY_ICON` ao arquivo ICO. O CMake só o adiciona a `prismkey_gui` quando `WIN32` está ativo, fazendo o Explorer exibir o ícone no `.exe`.

## `scripts/package-windows.ps1`

Script PowerShell parametrizado para criar `dist/PrismKey-<Version>-windows-x64.zip`. Os parâmetros permitem escolher diretório de build, instalação Qt e versão, com valores padrão voltados a MinGW e Qt 6.11.2. `ErrorActionPreference = Stop` transforma falhas em interrupções do script.

Ele calcula caminhos a partir de `PSScriptRoot`, exige a GUI, [[cli]] e `windeployqt`, remove uma pasta/ZIP do mesmo nome existentes, recria a pasta de pacote e copia `LICENSE` e `HELLO_WORLD.txt`. Em seguida executa `windeployqt` para trazer DLLs e plugins Qt, renomeia/copía os executáveis para `PrismKey.exe` e `PrismKey-[[cli]].exe`, exige `libcrypto-3-x64.dll`, e por fim compacta o conteúdo.

As remoções são deliberadas: reempacotar a mesma versão substitui a distribuição anterior. O script verifica os alvos antes de apagá-los, mas não cria nem compila o build; isso deve ocorrer antes de sua execução.
