#include <QApplication>
#include <QIcon>

#include "MainWindow.hpp"

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    application.setWindowIcon(QIcon(":/icons/prismkey.png"));
    prismkey::gui::MainWindow window;
    window.show();
    return application.exec();
}
