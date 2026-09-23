# Núcleo: resultados e armazenamento

## `include/core/Result.hpp`

Este cabeçalho centraliza o tratamento explícito de falhas.

`ErrorCode` classifica as causas que as camadas superiores podem distinguir: arquivo ausente, ilegível ou não gravável; chave inválida; senha incorreta; assinatura inválida; falha do OpenSSL; e argumento inválido.

`Result<T>` armazena quatro campos: `ok_`, o eventual `value_`, `errorCode_` e `message_`. Seus construtores são privados, portanto quem chama só pode produzir resultados por `success(valor)` e `failure(codigo, mensagem)`. Os acessores são marcados `[[nodiscard]]` onde interessa não ignorar a consulta, e `noexcept` quando apenas leem estado. `value()` só deve ser chamado após `ok()`; o tipo não lança nem faz validação adicional nessa chamada.

A especialização `Result<void>` remove o valor para operações que só precisam indicar êxito ou erro, como gravar uma chave. `success()` conserva um código interno sem significado para sucesso; consumidores devem usar `ok()` antes de consultar qualquer dado de erro.

## `include/core/ProjectStorage.hpp`

Define `StorageKind`, que representa os três destinos administrados: chave pública, chave privada e assinatura. A classe sem estado `ProjectStorage` expõe:

- `destination`: calcula o destino padronizado sem gravar nada;
- `copy`: cria o diretório se necessário e copia um arquivo para esse destino, opcionalmente substituindo um existente.

## `src/core/ProjectStorage.cpp`

`folderFor` é uma função interna que converte o enum em `keys/public`, `keys/private` ou `signatures`. Ela não pode ser chamada fora deste arquivo.

`destination` concatena `current_path()`, a pasta do tipo e somente `source.filename()`. Essa última escolha evita que subdiretórios fornecidos pelo usuário sejam reproduzidos no armazenamento do projeto, mas também significa que dois arquivos com o mesmo nome colidem.

`copy` usa `std::error_code` em vez de exceções: tenta criar o pai, recusa um alvo existente quando `overwrite` é falso, escolhe a opção de cópia apropriada e devolve `false` em qualquer erro. Nenhum serviço atual precisa copiar [[chaves]] para esse local: geração e assinatura gravam diretamente no destino calculado.
