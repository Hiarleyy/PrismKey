# `src/main.cpp` — interface de linha de comando

O executável `prismkey` converte argumentos em chamadas aos serviços. Não persiste estado próprio e retorna `0` em sucesso ou `1` para uso inválido/falha.

`printUsage` imprime os quatro comandos aceitos. `optionValue` faz uma varredura linear dos argumentos: localiza uma opção, exige que o próximo token exista e não comece com `--`, e então devolve o valor opcional. Ela não remove argumentos consumidos nem rejeita opções desconhecidas.

`readPassword` evita eco da senha. Em Windows usa `_getch`; backspace remove um caractere e Ctrl+C devolve ausência de valor. Em Unix ajustaria `termios` para desativar `ECHO`. Ao terminar, sempre escreve apenas uma quebra de linha. `report` é um adaptador comum para `Result<void>` que imprime a mensagem de erro ou a confirmação e transforma o estado em código de processo.

## Fluxo de `main`

- `hash <arquivo> [--algorithm ...]`: aceita exatamente dois ou quatro argumentos após o executável, usa SHA256 por padrão e imprime `algoritmo: digest`.
- `keygen [--algorithm RSA|ED25519] --public ... --private ...`: valida destinos e algoritmo, pede a senha duas vezes e exige igualdade não vazia. Então mapeia a string para `KeyAlgorithm` e gera o par.
- `sign <arquivo> --key ... --out ...`: pede a senha da privada e delega a assinatura ao serviço.
- `verify <arquivo> --signature ... --key ...`: chama a variante detalhada da verificação e mostra algoritmo e data UTC; [[assinaturas]] legadas são identificadas explicitamente.

Qualquer outro comando mostra um erro e o resumo de uso. Há um `return report(...)` inatingível depois do `return 0` do ramo `verify`; ele não afeta a execução, mas é código morto que poderia ser removido numa alteração futura.
