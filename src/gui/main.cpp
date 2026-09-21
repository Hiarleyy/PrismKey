#include "MainWindow.hpp"

#include <QApplication>
#include <QIcon>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    application.setWindowIcon(QIcon(":/icons/prismkey.png"));
    prismkey::gui::MainWindow window;
    window.show();
    return application.exec();
}
