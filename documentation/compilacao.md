# `CMakeLists.txt` — compilação e alvos

O único arquivo de build exige CMake 3.21, declara o projeto `PrismKey` na versão 0.1.1 e fixa C++20 sem extensões específicas do compilador. `CMAKE_AUTORCC` instrui o CMake a transformar o arquivo `.qrc` da Qt em código C++ de recurso.

`find_package` localiza três dependências: OpenSSL para primitivas criptográficas, GTest para [[testes]] e Qt6 Widgets para a janela. `include(CTest)` habilita a opção padrão `BUILD_TESTING`.

## Alvos criados

- `prismkey_crypto` é a biblioteca interna com `ProjectStorage` e os quatro serviços. Expõe `include/` publicamente e vincula `OpenSSL::Crypto`; por isso qualquer executável que a use também recebe os cabeçalhos e a dependência necessários.
- `prismkey` é o executável de terminal, construído de `src/main.cpp` e ligado à biblioteca interna.
- `prismkey_gui` é o executável Windows sem console (`WIN32`). Inclui inicialização Qt, a janela e o recurso Qt. Em Windows também incorpora o `.rc`, que define o ícone do executável.
- `prismkey_tests`, criado somente com `BUILD_TESTING`, é ligado à biblioteca e a `GTest::gtest_main`. `gtest_discover_tests` registra cada caso de teste no CTest depois de o binário ser compilado.

Quando o compilador é MSVC, `/utf-8` garante interpretação consistente dos literais em português e `/W4` aumenta o nível de avisos nos três alvos de produção.
