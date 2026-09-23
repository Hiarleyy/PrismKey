# Operações em lote

## `include/crypto/BatchService.hpp`

Define três estruturas de transporte: `FilePair` associa um arquivo à sua assinatura; `BatchItemResult` associa cada arquivo ao resultado individual; e `FolderPairs` separa pares encontrados de arquivos ignorados. `BatchService` reúne operações de seleção, descoberta, assinatura e verificação em lote.

## `src/crypto/BatchService.cpp`

`regularFiles` filtra a lista recebida com `is_regular_file`; é usada principalmente no arrastar-e-soltar para ignorar URLs não locais, diretórios e itens especiais.

`signaturePath` não usa `replace_extension`: concatena `.sig` ao caminho completo. Portanto `relatorio.pdf` vira `relatorio.pdf.sig`, preservando a extensão original no nome.

`discoverPairs` percorre somente o primeiro nível de uma pasta. Para cada arquivo que não termina em `.sig`, procura seu caminho derivado por `signaturePath`; se ambos existem, adiciona um `FilePair`, caso contrário deixa o arquivo em `ignored`. Para uma assinatura isolada, remove `.sig` com `stem()` e procura o arquivo correspondente. O método não lança uma falha para diretório inexistente: retorna duas listas vazias.

`signFiles` chama `SignatureService::signFile` uma vez por arquivo, escolhendo como saída o caminho `<arquivo>.sig`. Retorna todos os resultados, sem parar no primeiro erro. `verifyPairs` tem a mesma política, chamando `verifyFile` em cada par. Essa estratégia permite à GUI exibir um resumo parcial, como “7/8 assinados”.
