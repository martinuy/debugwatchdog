#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QItemSelectionModel>
#include <QMainWindow>
#include <QMutex>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    static MainWindow* globalInstance;
    static void fatalErrorHandler(int status);
    static void stoppedProcessCallback(pid_t pid);
    static QString getProcessExecutableBinary(pid_t p);
    Ui::MainWindow *ui;
    bool debugWatchdogLibraryInitialized;
    bool fatalErrorOccurred;
    QMutex globalMutex;
    pid_t getSelectedStoppedProcessPid(void);
    void removeCurrentSelectedStoppedProcess(void);
    QString getSelectedWatchedBinary(void);
    void setSuccessStatusMessage(const QString& m);
    void setFailureStatusMessage(const QString& m);

protected:
    void mousePressEvent(QMouseEvent* event);

public slots:
    void onOffCheckBoxStateChanged(int state);
    void watchButtonClicked(void);
    void unwatchButtonClicked(void);
    void killButtonClicked(void);
    void continueButtonClicked(void);
    void debugButtonClicked(void);
    void binaryToWatchTextEnterPressed(int);
    void watchedBinariesItemSelectionChanged(const QModelIndex&, const QModelIndex&);
    void stoppedProcessesItemSelectionChanged(const QModelIndex&, const QModelIndex&);
};

#endif // MAINWINDOW_H
