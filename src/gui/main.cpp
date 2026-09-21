#include "MainWindow.hpp"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    prismkey::gui::MainWindow window;
    window.show();
    return application.exec();
}
