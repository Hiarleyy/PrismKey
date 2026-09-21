#pragma once

#include <QMainWindow>

class QLabel;
class QLineEdit;

namespace prismkey::gui {

class MainWindow final : public QMainWindow {
public:
    MainWindow();

private:
    void createHashTab();
    void createKeyGenerationTab();
    void createSignTab();
    void createVerifyTab();

    QLineEdit* hashFile_ = nullptr;
    QLabel* hashResult_ = nullptr;

    QLineEdit* publicKeyOutput_ = nullptr;
    QLineEdit* privateKeyOutput_ = nullptr;
    QLineEdit* keyPassword_ = nullptr;
    QLineEdit* keyPasswordConfirmation_ = nullptr;
    QLabel* keyGenerationResult_ = nullptr;

    QLineEdit* signFile_ = nullptr;
    QLineEdit* signPrivateKey_ = nullptr;
    QLineEdit* signOutput_ = nullptr;
    QLineEdit* signPassword_ = nullptr;
    QLabel* signResult_ = nullptr;

    QLineEdit* verifyFile_ = nullptr;
    QLineEdit* verifySignature_ = nullptr;
    QLineEdit* verifyPublicKey_ = nullptr;
    QLabel* verifyResult_ = nullptr;
};

}  // namespace prismkey::gui
