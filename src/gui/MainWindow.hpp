#pragma once

#include <QMainWindow>
#include <filesystem>
#include <vector>

class QLabel;
class QLineEdit;
class QListWidget;
class QTabWidget;
class QDragEnterEvent;
class QDropEvent;
class QComboBox;

namespace prismkey::gui {

class MainWindow final : public QMainWindow {
   public:
    MainWindow();

   protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;

   private:
    void createHashTab();
    void createKeyGenerationTab();
    void createSignTab();
    void createVerifyTab();
    void processHashFiles(const std::vector<std::filesystem::path>& files);
    void refreshSignQueue();

    QLineEdit* hashFile_ = nullptr;
    QLabel* hashResult_ = nullptr;
    QListWidget* hashResults_ = nullptr;
    QComboBox* hashAlgorithm_ = nullptr;

    QLineEdit* publicKeyOutput_ = nullptr;
    QLineEdit* privateKeyOutput_ = nullptr;
    QLineEdit* keyPassword_ = nullptr;
    QLineEdit* keyPasswordConfirmation_ = nullptr;
    QLabel* keyGenerationResult_ = nullptr;
    QLineEdit* inspectPublicKey_ = nullptr;
    QLabel* keyInspectionResult_ = nullptr;

    QLineEdit* signFile_ = nullptr;
    QLineEdit* signPrivateKey_ = nullptr;
    QLineEdit* signOutput_ = nullptr;
    QLineEdit* signPassword_ = nullptr;
    QLabel* signResult_ = nullptr;
    QListWidget* signQueue_ = nullptr;
    std::vector<std::filesystem::path> signFiles_;

    QLineEdit* verifyFile_ = nullptr;
    QLineEdit* verifySignature_ = nullptr;
    QLineEdit* verifyPublicKey_ = nullptr;
    QLabel* verifyResult_ = nullptr;
    QLineEdit* verifyFolder_ = nullptr;
    QListWidget* verifyResults_ = nullptr;
    QTabWidget* tabs_ = nullptr;
};

}  // namespace prismkey::gui
