# Documentação técnica do PrismKey

Esta pasta descreve o código que compõe o PrismKey no estado atual do repositório. A documentação cobre os fontes C++, cabeçalhos, configuração de compilação, recursos da interface, script de empacotamento e [[testes]]. Arquivos gerados (`build/`, `dist/`, `vcpkg_installed/`) não são documentados porque não fazem parte do código-fonte mantido.

## Visão geral

O PrismKey oferece duas interfaces para as mesmas operações criptográficas:

```text
CLI (src/main.cpp) ─┐
                    ├─> serviços crypto/ ─> OpenSSL
GUI (src/gui/*) ────┘          │
                               └─> core/ProjectStorage e core/Result
```

As [[chaves]] e [[assinaturas]] sempre são guardadas, a partir do diretório de execução, em `keys/public`, `keys/private` e `signatures`. O caminho digitado pelo usuário define apenas o nome final do arquivo nessas pastas.

## Índice por arquivo

| Área | Arquivo | Documento |
| --- | --- | --- |
| Compilação | `CMakeLists.txt` | [compilacao.md](compilacao.md) |
| Aplicação [[cli]] | `src/main.cpp` | [cli.md](cli.md) |
| Aplicação Qt | `src/gui/main.cpp`, `src/gui/MainWindow.hpp`, `src/gui/MainWindow.cpp` | [interface-grafica.md](interface-grafica.md) |
| Núcleo | `include/core/Result.hpp`, `include/core/ProjectStorage.hpp`, `src/core/ProjectStorage.cpp` | [nucleo.md](nucleo.md) |
| [[hash]] | `include/crypto/HashService.hpp`, `src/crypto/HashService.cpp` | [hash.md](hash.md) |
| [[chaves]] | `include/crypto/KeyService.hpp`, `src/crypto/KeyService.cpp` | [chaves.md](chaves.md) |
| [[assinaturas]] | `include/crypto/SignatureService.hpp`, `src/crypto/SignatureService.cpp` | [assinaturas.md](assinaturas.md) |
| [[lotes]] | `include/crypto/BatchService.hpp`, `src/crypto/BatchService.cpp` | [lotes.md](lotes.md) |
| [[testes]] | `tests/CryptoServicesTests.cpp` | [testes.md](testes.md) |
| Distribuição | `assets/prismkey.qrc`, `assets/prismkey.rc`, `scripts/package-windows.ps1` | [distribuicao.md](distribuicao.md) |

## Convenções transversais

- `prismkey::core::Result<T>` é o contrato de retorno dos serviços: em sucesso contém um valor; em falha contém código e mensagem. Isso evita exceções como mecanismo normal de comunicação entre camadas.
- `std::filesystem::path` é usado para caminhos, e leitura de conteúdo é binária. Assim, hashes e [[assinaturas]] não sofrem transformação de fim de linha ou codificação.
- OpenSSL é encapsulado com `std::unique_ptr` e o desalocador correto. Recursos alocados pela biblioteca são liberados automaticamente em retornos antecipados.
- A GUI chama os mesmos serviços da [[cli]]; ela não reimplementa a criptografia.
