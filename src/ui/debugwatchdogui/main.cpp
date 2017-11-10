#include <signal.h>

#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    sigset_t stopped_process_actions_set;
    if (sigemptyset(&stopped_process_actions_set) != 0) {
        return -1;
    }
    if (sigaddset(&stopped_process_actions_set, SIGUSR1) == -1) {
        return -1;
    }
    if (pthread_sigmask(SIG_BLOCK, &stopped_process_actions_set, NULL) != 0) {
        return -1;
    }

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
