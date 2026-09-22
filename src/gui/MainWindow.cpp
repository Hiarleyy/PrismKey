#include "MainWindow.hpp"

#include "crypto/HashService.hpp"
#include "crypto/BatchService.hpp"
#include "crypto/KeyService.hpp"
#include "crypto/SignatureService.hpp"

#include <QFileDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QListWidget>
#include <QMessageBox>
#include <QMimeData>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <filesystem>

namespace prismkey::gui {
namespace {

std::filesystem::path toPath(const QLineEdit* field) {
    return std::filesystem::path(field->text().toStdWString());
}

QLineEdit* pathField(QFormLayout* layout, const QString& label, QWidget* parent, bool save, const QString& filter = {}) {
    auto* field = new QLineEdit(parent);
    auto* browse = new QPushButton("Procurar...", parent);
    auto* row = new QWidget(parent);
    auto* rowLayout = new QHBoxLayout(row);
    rowLayout->setContentsMargins(0, 0, 0, 0);
    rowLayout->addWidget(field);
    rowLayout->addWidget(browse);
    layout->addRow(label, row);
    QObject::connect(browse, &QPushButton::clicked, parent, [parent, field, save, filter] {
        const QString selected = save
            ? QFileDialog::getSaveFileName(parent, "Selecionar destino", field->text(), filter)
            : QFileDialog::getOpenFileName(parent, "Selecionar arquivo", field->text(), filter);
        if (!selected.isEmpty()) field->setText(selected);
    });
    return field;
}

void setError(QLabel* label, const QString& message) {
    label->setStyleSheet("color: #b00020;");
    label->setText("Erro: " + message);
}

void setSuccess(QLabel* label, const QString& message) {
    label->setStyleSheet("color: #137333;");
    label->setText(message);
}

}  // namespace

MainWindow::MainWindow() {
    setWindowTitle("PrismKey");
    resize(720, 420);
    setAcceptDrops(true);

    auto* tabs = new QTabWidget(this);
    tabs_ = tabs;
    setCentralWidget(tabs);
    createHashTab();
    createKeyGenerationTab();
    createSignTab();
    createVerifyTab();
}

void MainWindow::processHashFiles(const std::vector<std::filesystem::path>& files) {
    hashResult_->clear();
    for (const auto& file : files) {
        const auto result = crypto::HashService::sha256File(file);
        const QString message = QString::fromStdWString(file.wstring()) + ": " +
            (result.ok() ? QString::fromStdString(result.value()) : "Erro - " + QString::fromStdString(result.message()));
        if (hashResults_) hashResults_->addItem(message); else hashResult_->setText(message);
    }
}

void MainWindow::refreshSignQueue() {
    if (!signQueue_) return;
    signQueue_->clear();
    for (const auto& file : signFiles_) signQueue_->addItem(QString::fromStdWString(file.wstring()));
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* event) {
    std::vector<std::filesystem::path> paths;
    for (const auto& url : event->mimeData()->urls()) if (url.isLocalFile()) paths.emplace_back(url.toLocalFile().toStdWString());
    const auto files = crypto::BatchService::regularFiles(paths);
    if (files.empty()) { setError(tabs_ && tabs_->currentIndex() == 2 ? signResult_ : hashResult_, "Solte arquivos locais regulares."); return; }
    if (tabs_ && tabs_->currentIndex() == 2) { signFiles_.insert(signFiles_.end(), files.begin(), files.end()); refreshSignQueue(); setSuccess(signResult_, "Arquivos adicionados a fila."); }
    else processHashFiles(files);
    event->acceptProposedAction();
}

void MainWindow::createHashTab() {
    auto* tab = new QWidget(this);
    auto* layout = new QVBoxLayout(tab);
    auto* form = new QFormLayout;
    hashFile_ = pathField(form, "Arquivo:", tab, false);
    layout->addLayout(form);
    auto* calculate = new QPushButton("Calcular SHA-256", tab);
    layout->addWidget(calculate);
    hashResult_ = new QLabel(tab);
    hashResult_->setWordWrap(true);
    layout->addWidget(hashResult_);
    hashResults_ = new QListWidget(tab);
    layout->addWidget(hashResults_);
    layout->addStretch();
    static_cast<QTabWidget*>(centralWidget())->addTab(tab, "Hash");

    connect(calculate, &QPushButton::clicked, this, [this] {
        hashResult_->clear();
        if (hashFile_->text().isEmpty()) { setError(hashResult_, "Selecione um arquivo."); return; }
        const auto result = crypto::HashService::sha256File(toPath(hashFile_));
        if (!result.ok()) { setError(hashResult_, QString::fromStdString(result.message())); return; }
        setSuccess(hashResult_, "SHA-256: " + QString::fromStdString(result.value()));
    });
}

void MainWindow::createKeyGenerationTab() {
    auto* tab = new QWidget(this);
    auto* layout = new QVBoxLayout(tab);
    auto* form = new QFormLayout;
    publicKeyOutput_ = pathField(form, "Chave pública:", tab, true, "Chaves PEM (*.pem)");
    privateKeyOutput_ = pathField(form, "Chave privada:", tab, true, "Chaves PEM (*.pem)");
    keyPassword_ = new QLineEdit(tab);
    keyPassword_->setEchoMode(QLineEdit::Password);
    form->addRow("Senha:", keyPassword_);
    keyPasswordConfirmation_ = new QLineEdit(tab);
    keyPasswordConfirmation_->setEchoMode(QLineEdit::Password);
    form->addRow("Confirmar senha:", keyPasswordConfirmation_);
    layout->addLayout(form);
    auto* generate = new QPushButton("Gerar chaves RSA", tab);
    layout->addWidget(generate);
    keyGenerationResult_ = new QLabel(tab);
    keyGenerationResult_->setWordWrap(true);
    layout->addWidget(keyGenerationResult_);
    layout->addStretch();
    static_cast<QTabWidget*>(centralWidget())->addTab(tab, "Gerar chaves");

    connect(generate, &QPushButton::clicked, this, [this] {
        keyGenerationResult_->clear();
        const QString password = keyPassword_->text();
        const QString confirmation = keyPasswordConfirmation_->text();
        if (publicKeyOutput_->text().isEmpty() || privateKeyOutput_->text().isEmpty() || password.isEmpty() || password != confirmation) {
            setError(keyGenerationResult_, "Informe destinos diferentes e senhas iguais, não vazias.");
        } else {
            const auto result = crypto::KeyService::generateRsaKeyPair(toPath(publicKeyOutput_), toPath(privateKeyOutput_), password.toStdString());
            if (result.ok()) setSuccess(keyGenerationResult_, "Par de chaves RSA gerado com sucesso.");
            else setError(keyGenerationResult_, QString::fromStdString(result.message()));
        }
        keyPassword_->clear();
        keyPasswordConfirmation_->clear();
    });
}

void MainWindow::createSignTab() {
    auto* tab = new QWidget(this);
    auto* layout = new QVBoxLayout(tab);
    auto* form = new QFormLayout;
    signFile_ = pathField(form, "Arquivo:", tab, false);
    signPrivateKey_ = pathField(form, "Chave privada:", tab, false, "Chaves PEM (*.pem)");
    signOutput_ = pathField(form, "Assinatura:", tab, true, "Assinaturas (*.sig)");
    signPassword_ = new QLineEdit(tab);
    signPassword_->setEchoMode(QLineEdit::Password);
    form->addRow("Senha:", signPassword_);
    layout->addLayout(form);
    signQueue_ = new QListWidget(tab);
    layout->addWidget(signQueue_);
    auto* sign = new QPushButton("Assinar arquivo", tab);
    layout->addWidget(sign);
    signResult_ = new QLabel(tab);
    signResult_->setWordWrap(true);
    layout->addWidget(signResult_);
    layout->addStretch();
    static_cast<QTabWidget*>(centralWidget())->addTab(tab, "Assinar");

    connect(sign, &QPushButton::clicked, this, [this] {
        signResult_->clear();
        const QString password = signPassword_->text();
        if (signPrivateKey_->text().isEmpty() || password.isEmpty() || (signFiles_.empty() && (signFile_->text().isEmpty() || signOutput_->text().isEmpty()))) {
            setError(signResult_, "Informe o arquivo, a chave privada, o destino e a senha.");
        } else {
            if (signFiles_.empty()) {
                const auto result = crypto::SignatureService::signFile(toPath(signFile_), toPath(signPrivateKey_), toPath(signOutput_), password.toStdString());
                if (result.ok()) setSuccess(signResult_, "Arquivo assinado com sucesso."); else setError(signResult_, QString::fromStdString(result.message()));
            } else {
                bool conflict = false; for (const auto& file : signFiles_) conflict = conflict || std::filesystem::exists(crypto::BatchService::signaturePath(file));
                if (conflict && QMessageBox::question(this, "Substituir assinaturas", "Ha assinaturas existentes. Substitui-las?") != QMessageBox::Yes) { setError(signResult_, "Lote cancelado."); }
                else { const auto results = crypto::BatchService::signFiles(signFiles_, toPath(signPrivateKey_), password.toStdString()); int ok = 0; for (const auto& item : results) ok += item.ok; setSuccess(signResult_, QString("Lote concluido: %1/%2 assinados.").arg(ok).arg(results.size())); }
            }
        }
        signPassword_->clear();
    });
}

void MainWindow::createVerifyTab() {
    auto* tab = new QWidget(this);
    auto* layout = new QVBoxLayout(tab);
    auto* form = new QFormLayout;
    verifyFile_ = pathField(form, "Arquivo:", tab, false);
    verifySignature_ = pathField(form, "Assinatura:", tab, false, "Assinaturas (*.sig)");
    verifyFolder_ = new QLineEdit(tab);
    form->addRow("Pasta para lote:", verifyFolder_);
    verifyPublicKey_ = pathField(form, "Chave pública:", tab, false, "Chaves PEM (*.pem)");
    layout->addLayout(form);
    auto* verify = new QPushButton("Verificar assinatura", tab);
    layout->addWidget(verify);
    verifyResult_ = new QLabel(tab);
    verifyResult_->setWordWrap(true);
    layout->addWidget(verifyResult_);
    layout->addStretch();
    static_cast<QTabWidget*>(centralWidget())->addTab(tab, "Verificar");

    connect(verify, &QPushButton::clicked, this, [this] {
        verifyResult_->clear();
        if (verifyFile_->text().isEmpty() || verifySignature_->text().isEmpty() || verifyPublicKey_->text().isEmpty()) {
            setError(verifyResult_, "Informe o arquivo, a assinatura e a chave pública.");
            return;
        }
        const auto result = crypto::SignatureService::verifyFile(toPath(verifyFile_), toPath(verifySignature_), toPath(verifyPublicKey_));
        if (result.ok()) setSuccess(verifyResult_, "Assinatura válida.");
        else setError(verifyResult_, "Assinatura inválida ou não foi possível verificar os arquivos.");
    });
}

}  // namespace prismkey::gui
