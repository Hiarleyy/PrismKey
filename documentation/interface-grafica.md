# Interface gráfica Qt

## `src/gui/main.cpp`

É o ponto de entrada da aplicação `prismkey_gui`. Cria `QApplication`, aplica o ícone de recurso `:/icons/prismkey.png`, instancia `prismkey::gui::MainWindow`, mostra a janela e transfere o controle para o laço de eventos `application.exec()`.

## `src/gui/MainWindow.hpp`

Declara a janela principal final, derivada de `QMainWindow`. Ela sobrescreve eventos de arrastar e soltar e declara quatro construtores de abas: [[hash]], [[chaves]], assinatura e verificação. Os ponteiros para widgets são inicializados com `nullptr` e pertencem à árvore de objetos Qt, logo serão destruídos automaticamente pelo pai. `signFiles_` é a fila de caminhos adicionados por arrastar-e-soltar; `tabs_` ajuda a decidir em que contexto um drop ocorreu.

## `src/gui/MainWindow.cpp`

No espaço interno, `toPath` converte texto Qt em caminho usando uma string larga, importante para nomes Windows com Unicode. `pathField` constrói uma linha reutilizável de campo e botão “Procurar...”; conforme `save`, abre seletor de abertura ou de destino. `setError` e `setSuccess` aplicam cor e texto de feedback.

O construtor define título, tamanho inicial 720×420, habilita drops e cria as quatro abas. `processHashFiles` processa todos os caminhos com o algoritmo selecionado e os acrescenta à lista; `refreshSignQueue` espelha `signFiles_` visualmente. `dragEnterEvent` só aceita dados com URLs. `dropEvent` converte URLs locais, filtra arquivos regulares e: na terceira aba (índice 2, Assinar) os enfileira; em qualquer outra aba calcula hashes. A decisão por índice acopla esse comportamento à ordem das abas.

### Aba Hash

Oferece seletor de arquivo, lista de quatro algoritmos, botão e rótulo/lista de resultados. O clique valida presença de arquivo e chama `HashService::file`. Drops permitem processar vários itens e aparecem em `hashResults_`.

### Aba Gerar chaves

Solicita destinos PEM e senha com confirmação, mascarada por `QLineEdit::Password`. O botão gera somente RSA, por `generateRsaKeyPair`, mesmo que o serviço também suporte Ed25519. Após tentativa, limpa os dois campos de senha. A mesma aba também inspeciona uma chave pública e mostra algoritmo, tamanho e fingerprint. O texto sempre rotula o tamanho como “RSA”, inclusive se no futuro a GUI passar a inspecionar Ed25519.

### Aba Assinar

Permite fluxo unitário ou lote. Sem fila, exige arquivo, privada, destino e senha e chama `SignatureService`. Com fila, o destino unitário deixa de ser necessário: cada assinatura recebe `<arquivo>.sig`. Antes do lote, se detectar qualquer caminho de assinatura existente, pede confirmação de substituição; o serviço de lote então assina todos os arquivos. A senha é limpa ao final, incluindo erros.

### Aba Verificar

Apresenta campos de arquivo, assinatura, pasta para lote e chave pública, mas o callback atual exige os três campos unitários e chama somente `SignatureService::verifyFile`. O campo de pasta e o membro `verifyResults_` não são usados nessa implementação; ainda não há verificação gráfica por pasta apesar de `BatchService::discoverPairs` existir.
